#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../../common/tests_common.h"

static const size_t test_lengths[] = {
    0, 1, 2, 15, 16, 17, 31, 32, 33,
    64, 128, 256, 512, 1024,
    4096, 16384, 65536
};

static const size_t NUM_LENGTHS = sizeof(test_lengths) / sizeof(test_lengths[0]);
static const size_t ROUNDS_PER_LENGTH = 10;

static size_t random_index(size_t upper_bound)
{
    if (upper_bound == 0u) {
        return 0u;
    }

    uint64_t value = 0u;
    rand_bytes((unsigned char*)&value, sizeof value);
    return (size_t)(value % (uint64_t)upper_bound);
}

static int run_random_aead_tests(FILE *csv)
{
    printf("=== Random AEAD tests ===\n");

    if (csv) {
        fprintf(csv, "mlen,adlen,rounds,encrypt_ok,decrypt_ok,tamper_ok\n");
    }

    const size_t MAX_MSG_LEN = test_lengths[NUM_LENGTHS - 1];
    const size_t MAX_AD_LEN = test_lengths[NUM_LENGTHS - 1];

    unsigned char *msg = (unsigned char*)malloc(MAX_MSG_LEN);
    unsigned char *ad = (unsigned char*)malloc(MAX_AD_LEN);
    unsigned char *ct = (unsigned char*)malloc(MAX_MSG_LEN + CRYPTO_ABYTES);
    unsigned char *dec = (unsigned char*)malloc(MAX_MSG_LEN);

    if (!msg || !ad || !ct || !dec) {
        fprintf(stderr, "Allocation failed in random tests\n");
        free(msg);
        free(ad);
        free(ct);
        free(dec);
        return -1;
    }

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];

    unsigned long long clen = 0;
    unsigned long long dec_mlen = 0;

    size_t total_tests = 0;
    size_t total_tamper_tests = 0;

    for (size_t i = 0; i < NUM_LENGTHS; i++) {
        for (size_t j = 0; j < NUM_LENGTHS; j++) {
            size_t mlen = test_lengths[i];
            size_t adlen = test_lengths[j];

            size_t encrypt_ok = 0;
            size_t decrypt_ok = 0;
            size_t tamper_ok = 0;

            for (size_t r = 0; r < ROUNDS_PER_LENGTH; r++) {
                rand_bytes(key, sizeof key);
                rand_bytes(npub, sizeof npub);
                if (mlen > 0u) rand_bytes(msg, mlen);
                if (adlen > 0u) rand_bytes(ad, adlen);

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
                    free(msg);
                    free(ad);
                    free(ct);
                    free(dec);
                    return -1;
                }
                encrypt_ok++;

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
                    free(msg);
                    free(ad);
                    free(ct);
                    free(dec);
                    return -1;
                }
                if (dec_mlen != mlen) {
                    fprintf(stderr,
                            "Decrypted length mismatch: got %llu, expected %zu\n",
                            dec_mlen, mlen);
                    free(msg);
                    free(ad);
                    free(ct);
                    free(dec);
                    return -1;
                }
                if (memcmp(msg, dec, mlen) != 0) {
                    fprintf(stderr,
                            "Plaintext mismatch (mlen=%zu, adlen=%zu, round=%zu)\n",
                            mlen, adlen, r);
                    free(msg);
                    free(ad);
                    free(ct);
                    free(dec);
                    return -1;
                }
                decrypt_ok++;
                total_tests++;

                unsigned char *ct_copy = (unsigned char*)malloc(clen);
                if (!ct_copy) {
                    fprintf(stderr, "Allocation failed ct_copy\n");
                    free(msg);
                    free(ad);
                    free(ct);
                    free(dec);
                    return -1;
                }
                memcpy(ct_copy, ct, (size_t)clen);

                size_t pos = random_index((size_t)clen);
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
                    free(msg);
                    free(ad);
                    free(ct);
                    free(dec);
                    return -1;
                }

                tamper_ok++;
                total_tamper_tests++;
                free(ct_copy);
            }

            printf("mlen=%-6zu adlen=%-6zu : encrypt_ok=%zu/%zu, decrypt_ok=%zu/%zu, tamper_ok=%zu/%zu\n",
                   mlen, adlen,
                   encrypt_ok, ROUNDS_PER_LENGTH,
                   decrypt_ok, ROUNDS_PER_LENGTH,
                   tamper_ok, ROUNDS_PER_LENGTH);

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

    printf("Random AEAD tests passed: %zu encryption/decryption, %zu tamper tests\n",
           total_tests, total_tamper_tests);

    free(msg);
    free(ad);
    free(ct);
    free(dec);
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
        printf("Saving CSV results to: %s\n", argv[1]);
    } else {
        printf("No CSV file argument; running console-only mode.\n");
    }

    int ret = run_random_aead_tests(csv);

    if (csv) {
        fclose(csv);
    }

    return (ret != 0);
}
