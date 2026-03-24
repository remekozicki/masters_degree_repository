#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "../../common/tests_common.h"

static int read_line(FILE *f, char **line, size_t *cap)
{
    if (!f || !line || !cap) {
        return -1;
    }

    if (*line == NULL || *cap < 2u) {
        *cap = 256u;
        *line = (char*)xmalloc(*cap);
        (*line)[0] = '\0';
    }

    size_t len = 0u;

    for (;;) {
        size_t available = *cap - len;
        if (available < 2u) {
            if (*cap > (SIZE_MAX / 2u)) {
                return -1;
            }

            size_t new_cap = (*cap) * 2u;
            char *tmp = (char*)realloc(*line, new_cap);
            if (!tmp) {
                return -1;
            }

            *line = tmp;
            *cap = new_cap;
            available = *cap - len;
        }

        size_t chunk_size = available;
        if (chunk_size > (size_t)INT_MAX) {
            chunk_size = (size_t)INT_MAX;
        }

        if (fgets(*line + len, (int)chunk_size, f) == NULL) {
            return (len == 0u) ? 0 : 1;
        }

        len += strlen(*line + len);
        if (len > 0u && (*line)[len - 1u] == '\n') {
            return 1;
        }
    }
}

/* ------------------------ KAT runner ------------------------ */

static int run_kat(const char *kat_path)
{
    FILE *f = fopen(kat_path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open KAT: %s\n", kat_path);
        return 1;
    }

    char *line = NULL;
    size_t cap = 0u;
    unsigned char *key = NULL, *npub = NULL, *pt = NULL, *ad = NULL, *ct = NULL;
    size_t keylen = 0u, npublen = 0u, ptlen = 0u, adlen = 0u, ctlen = 0u;
    int tests = 0;
    int ok = 0;
    int line_rc = 0;

    while ((line_rc = read_line(f, &line, &cap)) > 0) {
        if (strncmp(line, "Key = ", 6) == 0) {
            free(key);
            key = NULL;
            keylen = 0u;
            if (hex2bin(line + 6, &key, &keylen) != 0) goto parse_error;
        } else if (strncmp(line, "Nonce = ", 8) == 0) {
            free(npub);
            npub = NULL;
            npublen = 0u;
            if (hex2bin(line + 8, &npub, &npublen) != 0) goto parse_error;
        } else if (strncmp(line, "PT = ", 5) == 0) {
            free(pt);
            pt = NULL;
            ptlen = 0u;
            if (hex2bin(line + 5, &pt, &ptlen) != 0) goto parse_error;
        } else if (strncmp(line, "AD = ", 5) == 0) {
            free(ad);
            ad = NULL;
            adlen = 0u;
            if (hex2bin(line + 5, &ad, &adlen) != 0) goto parse_error;
        } else if (strncmp(line, "CT = ", 5) == 0) {
            free(ct);
            ct = NULL;
            ctlen = 0u;
            if (hex2bin(line + 5, &ct, &ctlen) != 0) goto parse_error;

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
                fprintf(stderr, "[KAT] encrypt returned %d in test #%d\n", r, tests);
                goto mismatch;
            }
            if (clen != ctlen || memcmp(c, ct, ctlen) != 0) goto mismatch;

            unsigned long long mlen = (unsigned long long)ptlen;
            unsigned char *m = (unsigned char*)xmalloc(mlen ? mlen : 1u);
            r = crypto_aead_decrypt(
                m, &mlen, NULL,
                c, clen,
                ad, (unsigned long long)adlen,
                npub, key
            );
            if (r != 0 || mlen != ptlen || (ptlen && memcmp(m, pt, ptlen) != 0)) {
                free(m);
                goto mismatch;
            }

            ok++;
            free(m);
            free(c);
            continue;

mismatch:
            fprintf(stderr, "[KAT] MISMATCH in test #%d\n", tests);
            free(c);
        }
    }

    if (line_rc < 0) {
        goto parse_error;
    }

    fclose(f);
    free(line);
    free(key);
    free(npub);
    free(pt);
    free(ad);
    free(ct);

    printf("\nKAT summary:\n");
    printf("+-------------------+--------+\n");
    printf("| Number of tests   | %6d |\n", tests);
    printf("| Passed            | %6d |\n", ok);
    printf("| Failed            | %6d |\n", tests - ok);
    printf("+-------------------+--------+\n\n");

    return (ok == tests) ? 0 : 2;

parse_error:
    fprintf(stderr, "KAT parse/read error near line: %s\n", line ? line : "<null>");
    fclose(f);
    free(line);
    free(key);
    free(npub);
    free(pt);
    free(ad);
    free(ct);
    return 3;
}

/* ------------------------ main ------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s KAT_FILE\n", prog);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }
    return run_kat(argv[1]);
}
