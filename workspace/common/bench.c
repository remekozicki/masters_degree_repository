#include "crypto_aead.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "api.h"   /* z katalogu wybranej implementacji (IMPL_DIR) */

/* ------------------------ narzędzia ------------------------ */

static int hex2bin(const char *hex, unsigned char **out, size_t *outlen) {
    // hex może być pusty po " ="
    while (*hex && isspace((unsigned char)*hex)) hex++;
    if (*hex == '\0') { // pusty string
        *out = NULL; *outlen = 0; return 0;
    }
    size_t n = strlen(hex);
    // obetnij trailing spacje/newline
    while (n && isspace((unsigned char)hex[n-1])) n--;
    if (n % 2 != 0) return -1;
    *out = (unsigned char*)malloc(n/2);
    if (!*out) return -2;
    *outlen = n/2;
    for (size_t i=0;i<n;i+=2) {
        char buf[3] = {hex[i], hex[i+1], 0};
        char *end = NULL;
        unsigned long v = strtoul(buf, &end, 16);
        if (end != buf+2) { free(*out); *out=NULL; return -3; }
        (*out)[i/2] = (unsigned char)v;
    }
    return 0;
}

static void* xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, "OOM\n"); exit(1); }
    return p;
}

/* prosty xorshift32 do deterministycznych testów funkcjonalnych */
static uint32_t rng_state = 0x12345678u;
static uint32_t xorshift32(void) {
    uint32_t x = rng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    rng_state = x; return x;
}
static void rand_bytes(unsigned char *buf, size_t n) {
    for (size_t i=0;i<n;i++) buf[i] = (unsigned char)(xorshift32() & 0xFF);
}

/* ------------------------ KAT runner ------------------------ */

static int run_kat(const char *kat_path) {
    FILE *f = fopen(kat_path, "r");
    if (!f) {
        fprintf(stderr, "Nie mogę otworzyć KAT: %s\n", kat_path);
        return 1;
    }
    char *line = NULL; size_t cap = 0;
    unsigned char *key=NULL,*npub=NULL,*pt=NULL,*ad=NULL,*ct=NULL;
    size_t keylen=0,npublen=0,ptlen=0,adlen=0,ctlen=0;
    int tests = 0, ok = 0;

    while (getline(&line, &cap, f) != -1) {
        if (strncmp(line, "Key = ", 6) == 0) {
            free(key); key=NULL; keylen=0;
            if (hex2bin(line+6, &key, &keylen) != 0) goto parse_error;
        } else if (strncmp(line, "Nonce = ", 8) == 0) {
            free(npub); npub=NULL; npublen=0;
            if (hex2bin(line+8, &npub, &npublen) != 0) goto parse_error;
        } else if (strncmp(line, "PT = ", 5) == 0) {
            free(pt); pt=NULL; ptlen=0;
            if (hex2bin(line+5, &pt, &ptlen) != 0) goto parse_error;
        } else if (strncmp(line, "AD = ", 5) == 0) {
            free(ad); ad=NULL; adlen=0;
            if (hex2bin(line+5, &ad, &adlen) != 0) goto parse_error;
        } else if (strncmp(line, "CT = ", 5) == 0) {
            free(ct); ct=NULL; ctlen=0;
            if (hex2bin(line+5, &ct, &ctlen) != 0) goto parse_error;

            // Mamy komplet rekordu => weryfikacja
            tests++;

            unsigned long long clen = (unsigned long long)(ptlen + CRYPTO_ABYTES);
            unsigned char *c = (unsigned char*)xmalloc(clen);
            int r = crypto_aead_encrypt(
                    c, &clen,
                    pt, (unsigned long long)ptlen,
                    ad, (unsigned long long)adlen,
                    NULL, npub, key
            );
            if (r != 0) { fprintf(stderr, "[KAT] encrypt zwrócił %d\n", r); goto mismatch; }
            if (clen != ctlen || memcmp(c, ct, ctlen) != 0) goto mismatch;

            // decrypt
            unsigned long long mlen = (unsigned long long)ptlen;
            unsigned char *m = (unsigned char*)xmalloc(mlen ? mlen : 1);
            r = crypto_aead_decrypt(
                    m, &mlen, NULL,
                    c, clen,
                    ad, (unsigned long long)adlen,
                    npub, key
            );
            if (r != 0 || mlen != ptlen || (ptlen && memcmp(m, pt, ptlen)!=0)) {
                free(m); free(c); goto mismatch;
            }

            ok++;
            free(m); free(c);
            continue;

            mismatch:
            fprintf(stderr, "[KAT] NIEZGODNOŚĆ w teście #%d\n", tests);
            free(c);
            // nie przerywamy — pozwalamy dokończyć i zliczyć
        }
    }
    fclose(f); free(line);
    free(key); free(npub); free(pt); free(ad); free(ct);

    printf("KAT: %d/%d poprawnych\n", ok, tests);
    return (ok==tests) ? 0 : 2;

    parse_error:
    fprintf(stderr, "Błąd parsowania KAT w linii: %s\n", line?line:"<null>");
    fclose(f); free(line);
    free(key); free(npub); free(pt); free(ad); free(ct);
    return 3;
}

/* ------------------------ testy funkcjonalne ------------------------ */

static int expect_fail_decrypt(const unsigned char *c, unsigned long long clen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *npub, const unsigned char *k) {
    unsigned long long mlen = clen; // górny bound
    unsigned char *m = (unsigned char*)xmalloc(mlen ? mlen : 1);
    int r = crypto_aead_decrypt(m, &mlen, NULL, c, clen, ad, adlen, npub, k);
    free(m);
    return (r != 0); // oczekujemy niezerowego kodu błędu
}

static int run_functional(void) {
    const size_t msg_sizes[] = {0,1,2,15,16,17,31,32,33,64,256,1024,4096,16384};
    const size_t ad_sizes[]  = {0,1,7,8,15,16,17,32,33,64};
    const int ROUNDS = 3; // powtórzenia dla losowości
    int fails = 0, tests = 0;

    for (int r=0; r<ROUNDS; r++) {
        for (size_t i=0;i<sizeof(msg_sizes)/sizeof(msg_sizes[0]);i++) {
            for (size_t j=0;j<sizeof(ad_sizes)/sizeof(ad_sizes[0]);j++) {
                size_t mlen = msg_sizes[i], adlen = ad_sizes[j];
                unsigned char key[CRYPTO_KEYBYTES], npub[CRYPTO_NPUBBYTES];
                unsigned char *m = (unsigned char*)xmalloc(mlen?mlen:1);
                unsigned char *ad = (unsigned char*)xmalloc(adlen?adlen:1);
                rand_bytes(key, sizeof key);
                rand_bytes(npub, sizeof npub);
                rand_bytes(m, mlen);
                rand_bytes(ad, adlen);

                unsigned long long clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
                unsigned char *c = (unsigned char*)xmalloc(clen);

                int r1 = crypto_aead_encrypt(c, &clen, m, (unsigned long long)mlen,
                                             ad, (unsigned long long)adlen,
                                             NULL, npub, key);
                tests++;
                if (r1 != 0 || clen != mlen + CRYPTO_ABYTES) { fails++; goto next_case; }

                // decrypt OK
                unsigned long long mlen2 = (unsigned long long)mlen;
                unsigned char *m2 = (unsigned char*)xmalloc(mlen2?mlen2:1);
                int r2 = crypto_aead_decrypt(m2, &mlen2, NULL, c, clen,
                                             ad, (unsigned long long)adlen,
                                             npub, key);
                tests++;
                if (r2 != 0 || mlen2 != mlen || (mlen && memcmp(m,m2,mlen)!=0)) { fails++; free(m2); goto next_case; }
                free(m2);

                /* testy negatywne: modyfikacje jednego bajtu */
                // 1) flip w ciphertext
                if (clen > 0) {
                    unsigned char *c1 = (unsigned char*)xmalloc(clen);
                    memcpy(c1, c, clen);
                    c1[0] ^= 0x01;
                    tests++;
                    if (!expect_fail_decrypt(c1, clen, ad, adlen, npub, key)) fails++;
                    free(c1);
                }
                // 2) flip w TAG (ostatni bajt)
                {
                    unsigned char *c2 = (unsigned char*)xmalloc(clen);
                    memcpy(c2, c, clen);
                    c2[clen-1] ^= 0x80;
                    tests++;
                    if (!expect_fail_decrypt(c2, clen, ad, adlen, npub, key)) fails++;
                    free(c2);
                }
                // 3) flip w AD (jeśli niepuste)
                if (adlen > 0) {
                    unsigned char *ad2 = (unsigned char*)xmalloc(adlen);
                    memcpy(ad2, ad, adlen);
                    ad2[0] ^= 0x40;
                    tests++;
                    if (!expect_fail_decrypt(c, clen, ad2, adlen, npub, key)) fails++;
                    free(ad2);
                }
                // 4) flip w NPUB
                {
                    unsigned char npub2[CRYPTO_NPUBBYTES];
                    memcpy(npub2, npub, sizeof npub2);
                    npub2[0] ^= 0x01;
                    tests++;
                    if (!expect_fail_decrypt(c, clen, ad, adlen, npub2, key)) fails++;
                }

                next_case:
                free(c); free(m); free(ad);
            }
        }
    }
    printf("Functional: %d/%d testów zaliczonych\n", (tests - fails), tests);
    return fails ? 1 : 0;
}

/* ------------------------ main / CLI ------------------------ */

static void usage(const char *prog){
    fprintf(stderr,
            "Użycie: %s [--kat PATH] [--functional]\n"
            "  --kat PATH      : uruchom Known Answer Tests z pliku KAT\n"
            "  --functional    : losowe testy funkcjonalne + negatywne\n", prog);
}

int main(int argc, char **argv) {
    int rc = 0; int ran = 0;
    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i], "--kat") == 0 && i+1 < argc) {
            rc |= run_kat(argv[++i]); ran = 1;
        } else if (strcmp(argv[i], "--functional") == 0) {
            rc |= run_functional(); ran = 1;
        } else {
            usage(argv[0]); return 1;
        }
    }
    if (!ran) { usage(argv[0]); return 1; }
    return rc;
}
