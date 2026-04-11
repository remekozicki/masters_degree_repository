#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../common/tests_common.h"

/* ------------------------ helper ------------------------ */

static int expect_fail_decrypt(const unsigned char *c, unsigned long long clen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *npub, const unsigned char *k)
{
    unsigned long long mlen = clen;
    unsigned char *m = (unsigned char*)xmalloc(mlen ? mlen : 1);
    int r = crypto_aead_decrypt(m, &mlen, NULL, c, clen, ad, adlen, npub, k);
    free(m);
    return (r != 0);
}

/* ------------------------ testy funkcjonalne ------------------------ */

static int run_functional(FILE *csv) {
    const size_t msg_sizes[] = {0,1,2,15,16,17,31,32,33,64,256,1024,4096,16384};
    const size_t ad_sizes[]  = {0,1,7,8,15,16,17,32,33,64};
    const int ROUNDS = 3;
    int fails = 0, tests = 0;

    if (csv) {
        fprintf(csv, "type,round,mlen,adlen,what,result\n");
    }

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

                int local_fail = 0;

                int r1 = crypto_aead_encrypt(c, &clen, m, (unsigned long long)mlen,
                                             ad, (unsigned long long)adlen,
                                             NULL, npub, key);
                tests++;
                if (r1 != 0 || clen != mlen + CRYPTO_ABYTES) {
                    fails++; local_fail = 1;
                    if (csv) fprintf(csv, "functional,%d,%zu,%zu,encrypt,FAIL\n", r, mlen, adlen);
                    goto next_case;
                } else if (csv) {
                    fprintf(csv, "functional,%d,%zu,%zu,encrypt,OK\n", r, mlen, adlen);
                }

                unsigned long long mlen2 = (unsigned long long)mlen;
                unsigned char *m2 = (unsigned char*)xmalloc(mlen2?mlen2:1);
                int r2 = crypto_aead_decrypt(m2, &mlen2, NULL, c, clen,
                                             ad, (unsigned long long)adlen,
                                             npub, key);
                tests++;
                if (r2 != 0 || mlen2 != mlen || (mlen && memcmp(m,m2,mlen)!=0)) {
                    fails++; local_fail = 1;
                    if (csv) fprintf(csv, "functional,%d,%zu,%zu,decrypt,FAIL\n", r, mlen, adlen);
                    free(m2);
                    goto next_case;
                } else if (csv) {
                    fprintf(csv, "functional,%d,%zu,%zu,decrypt,OK\n", r, mlen, adlen);
                }
                free(m2);

                /* testy negatywne */
                if (clen > 0) {
                    unsigned char *c1 = (unsigned char*)xmalloc(clen);
                    memcpy(c1, c, clen);
                    c1[0] ^= 0x01;
                    tests++;
                    int ok = expect_fail_decrypt(c1, clen, ad, adlen, npub, key);
                    if (!ok) { fails++; local_fail = 1; }
                    if (csv) fprintf(csv, "functional,%d,%zu,%zu,flip_ct, %s\n",
                                     r, mlen, adlen, ok ? "OK" : "FAIL");
                    free(c1);
                }

                {
                    unsigned char *c2 = (unsigned char*)xmalloc(clen);
                    memcpy(c2, c, clen);
                    c2[clen-1] ^= 0x80;
                    tests++;
                    int ok = expect_fail_decrypt(c2, clen, ad, adlen, npub, key);
                    if (!ok) { fails++; local_fail = 1; }
                    if (csv) fprintf(csv, "functional,%d,%zu,%zu,flip_tag,%s\n",
                                     r, mlen, adlen, ok ? "OK" : "FAIL");
                    free(c2);
                }

                if (adlen > 0) {
                    unsigned char *ad2 = (unsigned char*)xmalloc(adlen);
                    memcpy(ad2, ad, adlen);
                    ad2[0] ^= 0x40;
                    tests++;
                    int ok = expect_fail_decrypt(c, clen, ad2, adlen, npub, key);
                    if (!ok) { fails++; local_fail = 1; }
                    if (csv) fprintf(csv, "functional,%d,%zu,%zu,flip_ad,%s\n",
                                     r, mlen, adlen, ok ? "OK" : "FAIL");
                    free(ad2);
                }

                {
                    unsigned char npub2[CRYPTO_NPUBBYTES];
                    memcpy(npub2, npub, sizeof npub2);
                    npub2[0] ^= 0x01;
                    tests++;
                    int ok = expect_fail_decrypt(c, clen, ad, adlen, npub2, key);
                    if (!ok) { fails++; local_fail = 1; }
                    if (csv) fprintf(csv, "functional,%d,%zu,%zu,flip_npub,%s\n",
                                     r, mlen, adlen, ok ? "OK" : "FAIL");
                }

                next_case:
                (void)local_fail; /* na razie nie wykorzystujemy osobno */
                free(c); free(m); free(ad);
            }
        }
    }

    printf("\nPodsumowanie testów funkcjonalnych:\n");
    printf("+--------------------+--------+\n");
    printf("| Liczba asercji     | %6d |\n", tests);
    printf("| Niepowodzenia      | %6d |\n", fails);
    printf("| Sukcesy            | %6d |\n", tests - fails);
    printf("+--------------------+--------+\n\n");

    return fails ? 1 : 0;
}

/* ------------------------ main ------------------------ */

static void usage(const char *prog){
    fprintf(stderr,
            "Użycie: %s [CSV_FILE]\n"
            "  bez argumentów: tylko podsumowanie na stdout\n"
            "  z CSV_FILE     : dodatkowo zapis CSV z wynikami\n", prog);
}

int main(int argc, char **argv) {
    FILE *csv = NULL;
    if (argc > 2) {
        usage(argv[0]);
        return 1;
    }
    if (argc == 2) {
        csv = fopen(argv[1], "w");
        if (!csv) {
            perror("fopen CSV");
            return 1;
        }
    }

    int rc = run_functional(csv);

    if (csv) fclose(csv);
    return rc;
}
