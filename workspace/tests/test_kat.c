#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/tests_common.h"

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

            tests++;

            unsigned long long clen = (unsigned long long)(ptlen + CRYPTO_ABYTES);
            unsigned char *c = (unsigned char*)xmalloc(clen);

            int r = crypto_aead_encrypt(
                    c, &clen,
                    pt, (unsigned long long)ptlen,
                    ad, (unsigned long long)adlen,
                    NULL, npub, key
            );
            if (r != 0) {
                fprintf(stderr, "[KAT] encrypt zwrócił %d w teście #%d\n", r, tests);
                goto mismatch;
            }
            if (clen != ctlen || memcmp(c, ct, ctlen) != 0) goto mismatch;

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
        }
    }

    fclose(f); free(line);
    free(key); free(npub); free(pt); free(ad); free(ct);

    /* ładniejsze podsumowanie */
    printf("\nPodsumowanie KAT:\n");
    printf("+-------------------+--------+\n");
    printf("| Liczba testów     | %6d |\n", tests);
    printf("| Poprawne          | %6d |\n", ok);
    printf("| Błędne            | %6d |\n", tests - ok);
    printf("+-------------------+--------+\n\n");

    return (ok==tests) ? 0 : 2;

    parse_error:
    fprintf(stderr, "Błąd parsowania KAT w linii: %s\n", line?line:"<null>");
    fclose(f); free(line);
    free(key); free(npub); free(pt); free(ad); free(ct);
    return 3;
}

/* ------------------------ main ------------------------ */

static void usage(const char *prog){
    fprintf(stderr, "Użycie: %s KAT_FILE\n", prog);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }
    return run_kat(argv[1]);
}
