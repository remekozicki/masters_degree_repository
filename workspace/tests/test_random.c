#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "tests_common.h"

static const size_t test_lengths[] = {
        0, 1, 2, 15, 16, 17, 31, 32, 33,
        64, 128, 256, 512, 1024,
        4096, 16384, 65536
};

static const size_t NUM_LENGTHS = sizeof(test_lengths) / sizeof(test_lengths[0]);
static const size_t ROUNDS_PER_LENGTH = 10; // podbijesz jak będziesz chciał

static int run_random_aead_tests(FILE *csv)
{
    printf("=== Random AEAD tests ===\n");

    if (csv) {
        // nagłówek CSV
        fprintf(csv, "mlen,adlen,rounds,encrypt_ok,decrypt_ok,tamper_ok\n");
    }

    // Maksymalne długości z test_lengths
    const size_t MAX_MSG_LEN = test_lengths[NUM_LENGTHS - 1];
    const size_t MAX_AD_LEN  = test_lengths[NUM_LENGTHS - 1];

    unsigned char *msg  = malloc(MAX_MSG_LEN);
    unsigned char *ad   = malloc(MAX_AD_LEN);
    unsigned char *ct   = malloc(MAX_MSG_LEN + CRYPTO_ABYTES);
    unsigned char *dec  = malloc(MAX_MSG_LEN);

    if (!msg || !ad || !ct || !dec) {
        fprintf(stderr, "Allocation failed in random tests\n");
        free(msg); free(ad); free(ct); free(dec);
        return -1;
    }

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];

    unsigned long long clen = 0;
    unsigned long long dec_mlen = 0;

    // init RNG (używany tylko do wyboru pozycji bit-flipa)
    srand((unsigned int)time(NULL));

    size_t total_tests = 0;
    size_t total_tamper_tests = 0;

    for (size_t i = 0; i < NUM_LENGTHS; i++) {
        for (size_t j = 0; j < NUM_LENGTHS; j++) {
            size_t mlen  = test_lengths[i];
            size_t adlen = test_lengths[j];

            size_t encrypt_ok = 0;
            size_t decrypt_ok = 0;
            size_t tamper_ok  = 0;

            for (size_t r = 0; r < ROUNDS_PER_LENGTH; r++) {
                rand_bytes(key,  sizeof key);
                rand_bytes(npub, sizeof npub);
                if (mlen > 0)  rand_bytes(msg, mlen);
                if (adlen > 0) rand_bytes(ad, adlen);

                // encrypt
                int enc_ret = crypto_aead_encrypt(
                        ct, &clen,
                        msg, (unsigned long long)mlen,
                        ad, (unsigned long long)adlen,
                        NULL,
                        npub,
                        key
                );
                if (enc_ret != 0) {
                    fprintf(stderr,
                            "Encrypt failed (mlen=%zu, adlen=%zu, round=%zu)\n",
                            mlen, adlen, r);
                    free(msg); free(ad); free(ct); free(dec);
                    return -1;
                }
                encrypt_ok++;

                // decrypt (prawidłowy)
                int dec_ret = crypto_aead_decrypt(
                        dec, &dec_mlen,
                        NULL,
                        ct, clen,
                        ad, (unsigned long long)adlen,
                        npub,
                        key
                );
                if (dec_ret != 0) {
                    fprintf(stderr,
                            "Decrypt failed (valid) (mlen=%zu, adlen=%zu, round=%zu)\n",
                            mlen, adlen, r);
                    free(msg); free(ad); free(ct); free(dec);
                    return -1;
                }
                if (dec_mlen != mlen) {
                    fprintf(stderr,
                            "Decrypted length mismatch: got %llu, expected %zu\n",
                            dec_mlen, mlen);
                    free(msg); free(ad); free(ct); free(dec);
                    return -1;
                }
                if (memcmp(msg, dec, mlen) != 0) {
                    fprintf(stderr,
                            "Plaintext mismatch (mlen=%zu, adlen=%zu, round=%zu)\n",
                            mlen, adlen, r);
                    free(msg); free(ad); free(ct); free(dec);
                    return -1;
                }
                decrypt_ok++;
                total_tests++;

                // Test fałszerstwa (bit flip w ciphertext/tagu)
                unsigned char *ct_copy = malloc(clen);
                if (!ct_copy) {
                    fprintf(stderr, "Allocation failed ct_copy\n");
                    free(msg); free(ad); free(ct); free(dec);
                    return -1;
                }
                memcpy(ct_copy, ct, (size_t)clen);

                size_t pos = (size_t)(rand()) % (size_t)clen;
                ct_copy[pos] ^= 0x01u;

                dec_ret = crypto_aead_decrypt(
                        dec, &dec_mlen,
                        NULL,
                        ct_copy, clen,
                        ad, (unsigned long long)adlen,
                        npub,
                        key
                );
                if (dec_ret == 0) {
                    fprintf(stderr,
                            "Forgery accepted (mlen=%zu, adlen=%zu, round=%zu, pos=%zu)\n",
                            mlen, adlen, r, pos);
                    free(ct_copy);
                    free(msg); free(ad); free(ct); free(dec);
                    return -1;
                } else {
                    tamper_ok++;
                    total_tamper_tests++;
                }

                free(ct_copy);
            }

            // podsumowanie dla tej pary długości na konsolę
            printf("mlen=%-6zu adlen=%-6zu : encrypt_ok=%zu/%zu, decrypt_ok=%zu/%zu, tamper_ok=%zu/%zu\n",
                   mlen, adlen,
                   encrypt_ok, ROUNDS_PER_LENGTH,
                   decrypt_ok, ROUNDS_PER_LENGTH,
                   tamper_ok,  ROUNDS_PER_LENGTH);

            // i do CSV (jeśli włączone)
            if (csv) {
                fprintf(csv, "%zu,%zu,%zu,%zu,%zu,%zu\n",
                        mlen, adlen,
                        ROUNDS_PER_LENGTH,
                        encrypt_ok,
                        decrypt_ok,
                        tamper_ok);
            }
        }
    }

    printf("Random AEAD tests passed: %zu encryption/decryption, "
           "%zu tamper tests\n",
           total_tests, total_tamper_tests);

    free(msg); free(ad); free(ct); free(dec);
    return 0;
}

int main(int argc, char **argv)
{
    FILE *csv = NULL;

    if (argc >= 2) {
        csv = fopen(argv[1], "w");
        if (!csv) {
            perror("fopen CSV");
            return 1;
        }
        printf("Zapisuję wyniki CSV do: %s\n", argv[1]);
    } else {
        printf("Brak pliku CSV w argumencie – działam tylko na konsoli.\n");
    }

    int ret = run_random_aead_tests(csv);

    if (csv) {
        fclose(csv);
    }

    return (ret != 0);
}
