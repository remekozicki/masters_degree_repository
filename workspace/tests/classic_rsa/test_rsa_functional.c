#include "rsa_common.h"

typedef struct {
    size_t total;
    size_t pass;
    size_t fail;
} rsa_stats_t;

static void note_result(FILE *csv,
                        rsa_stats_t *stats,
                        const char *category,
                        const char *operation,
                        int bits,
                        size_t msg_len,
                        const char *expected,
                        const char *observed,
                        int pass,
                        const char *notes)
{
    stats->total++;
    if (pass) {
        stats->pass++;
    } else {
        stats->fail++;
    }

    if (csv) {
        fprintf(csv, "%s,%s,%d,%zu,%s,%s,%s,%s\n",
                category,
                operation,
                bits,
                msg_len,
                expected,
                observed,
                pass ? "PASS" : "FAIL",
                notes ? notes : "");
    }
}

static int run_functional(FILE *csv, int bits, const char *provider)
{
    static const size_t oaep_lengths[] = {
        0u, 1u, 16u, 32u, 64u, 128u, 190u, 318u, 446u
    };
    static const size_t pss_lengths[] = {
        0u, 1u, 32u, 64u, 256u, 1024u, 4096u
    };

    rsa_stats_t stats;
    memset(&stats, 0, sizeof stats);

    if (csv) {
        fprintf(csv, "category,operation,bits,msg_len,expected,observed,result,notes\n");
    }

    printf("=== RSA functional tests (%d-bit, provider=%s) ===\n", bits, provider);

    EVP_PKEY *key = rsa_generate_key(bits);
    EVP_PKEY *wrong_key = rsa_generate_key(bits);
    if (!key || !wrong_key) {
        EVP_PKEY_free(key);
        EVP_PKEY_free(wrong_key);
        return 1;
    }

    const size_t modulus_len = rsa_modulus_bytes_from_bits(bits);
    const size_t max_oaep = rsa_oaep_sha256_max_plaintext(bits);

    unsigned char *msg = (unsigned char*)rsa_xmalloc(max_oaep ? max_oaep : 1u);
    unsigned char *dec = (unsigned char*)rsa_xmalloc(modulus_len);
    unsigned char *ct = (unsigned char*)rsa_xmalloc(modulus_len);
    unsigned char *ct_bad = (unsigned char*)rsa_xmalloc(modulus_len);

    for (size_t i = 0; i < sizeof oaep_lengths / sizeof oaep_lengths[0]; i++) {
        const size_t msg_len = oaep_lengths[i];
        if (msg_len > max_oaep) {
            continue;
        }

        rsa_rand_bytes(msg, msg_len);

        size_t ct_len = modulus_len;
        int enc_ok = rsa_oaep_encrypt(key, msg, msg_len, ct, &ct_len);
        note_result(csv, &stats, "oaep", "encrypt", bits, msg_len,
                    "success", enc_ok ? "success" : "fail", enc_ok,
                    "OAEP-SHA256");
        if (!enc_ok) {
            continue;
        }

        size_t dec_len = modulus_len;
        int dec_ok = rsa_oaep_decrypt(key, ct, ct_len, dec, &dec_len);
        int roundtrip_ok = dec_ok &&
            dec_len == msg_len &&
            (msg_len == 0u || memcmp(msg, dec, msg_len) == 0);
        note_result(csv, &stats, "oaep", "decrypt_roundtrip", bits, msg_len,
                    "success", roundtrip_ok ? "success" : "fail", roundtrip_ok,
                    "OAEP-SHA256");

        memcpy(ct_bad, ct, ct_len);
        ct_bad[0] ^= 0x01u;
        dec_len = modulus_len;
        int tamper_ret = rsa_oaep_decrypt(key, ct_bad, ct_len, dec, &dec_len);
        note_result(csv, &stats, "oaep_negative", "decrypt_corrupted_ciphertext",
                    bits, msg_len, "reject", tamper_ret ? "accepted" : "rejected",
                    !tamper_ret, "OAEP padding check");

        dec_len = modulus_len;
        int wrong_key_ret = rsa_oaep_decrypt(wrong_key, ct, ct_len, dec, &dec_len);
        note_result(csv, &stats, "oaep_negative", "decrypt_wrong_private_key",
                    bits, msg_len, "reject", wrong_key_ret ? "accepted" : "rejected",
                    !wrong_key_ret, "wrong RSA key");
    }

    if (max_oaep > 0u) {
        unsigned char *too_long = (unsigned char*)rsa_xmalloc(max_oaep + 1u);
        rsa_rand_bytes(too_long, max_oaep + 1u);
        size_t ct_len = modulus_len;
        int oversized_ok = rsa_oaep_encrypt(key, too_long, max_oaep + 1u, ct, &ct_len);
        note_result(csv, &stats, "oaep_negative", "encrypt_oversized_plaintext",
                    bits, max_oaep + 1u, "reject",
                    oversized_ok ? "accepted" : "rejected", !oversized_ok,
                    "OAEP-SHA256 plaintext limit");
        free(too_long);
    }

    unsigned char *sig = (unsigned char*)rsa_xmalloc(modulus_len);
    unsigned char *sig_bad = (unsigned char*)rsa_xmalloc(modulus_len);

    for (size_t i = 0; i < sizeof pss_lengths / sizeof pss_lengths[0]; i++) {
        const size_t msg_len = pss_lengths[i];
        unsigned char *pss_msg = (unsigned char*)rsa_xmalloc(msg_len ? msg_len : 1u);
        unsigned char *msg_bad = (unsigned char*)rsa_xmalloc(msg_len ? msg_len : 1u);
        rsa_rand_bytes(pss_msg, msg_len);
        memcpy(msg_bad, pss_msg, msg_len ? msg_len : 1u);
        if (msg_len > 0u) {
            msg_bad[0] ^= 0x80u;
        } else {
            msg_bad[0] = 0x80u;
        }

        size_t sig_len = modulus_len;
        int sign_ok = rsa_pss_sign(key, pss_msg, msg_len, sig, &sig_len);
        note_result(csv, &stats, "pss", "sign", bits, msg_len,
                    "success", sign_ok ? "success" : "fail", sign_ok,
                    "PSS-SHA256");
        if (!sign_ok) {
            free(pss_msg);
            free(msg_bad);
            continue;
        }

        int verify_ret = rsa_pss_verify(key, pss_msg, msg_len, sig, sig_len);
        note_result(csv, &stats, "pss", "verify", bits, msg_len,
                    "success", verify_ret == 1 ? "success" : "fail",
                    verify_ret == 1, "PSS-SHA256");

        memcpy(sig_bad, sig, sig_len);
        sig_bad[0] ^= 0x01u;
        verify_ret = rsa_pss_verify(key, pss_msg, msg_len, sig_bad, sig_len);
        note_result(csv, &stats, "pss_negative", "verify_corrupted_signature",
                    bits, msg_len, "reject", verify_ret == 1 ? "accepted" : "rejected",
                    verify_ret != 1, "PSS signature check");

        if (msg_len > 0u) {
            verify_ret = rsa_pss_verify(key, msg_bad, msg_len, sig, sig_len);
            note_result(csv, &stats, "pss_negative", "verify_modified_message",
                        bits, msg_len, "reject", verify_ret == 1 ? "accepted" : "rejected",
                        verify_ret != 1, "message integrity");
        }

        verify_ret = rsa_pss_verify(wrong_key, pss_msg, msg_len, sig, sig_len);
        note_result(csv, &stats, "pss_negative", "verify_wrong_public_key",
                    bits, msg_len, "reject", verify_ret == 1 ? "accepted" : "rejected",
                    verify_ret != 1, "wrong RSA key");

        free(pss_msg);
        free(msg_bad);
    }

    free(sig_bad);
    free(sig);
    free(ct_bad);
    free(ct);
    free(dec);
    free(msg);
    EVP_PKEY_free(wrong_key);
    EVP_PKEY_free(key);

    printf("\nRSA functional summary:\n");
    printf("+----------------------------+--------+\n");
    printf("| Total checks               | %6zu |\n", stats.total);
    printf("| Passed                     | %6zu |\n", stats.pass);
    printf("| Failed                     | %6zu |\n", stats.fail);
    printf("+----------------------------+--------+\n\n");

    return stats.fail == 0u ? 0 : 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [CSV_FILE] [RSA_BITS] [RSA_PROVIDER]\n", prog);
}

int main(int argc, char **argv)
{
    FILE *csv = NULL;
    int bits = 2048;
    const char *provider = "default";

    if (argc > 4) {
        usage(argv[0]);
        return 1;
    }
    if (argc >= 2 && strcmp(argv[1], "-") != 0) {
        csv = fopen(argv[1], "w");
        if (!csv) {
            perror("fopen CSV");
            return 1;
        }
        printf("Saving CSV results to: %s\n", argv[1]);
    }
    if (argc >= 3 && !rsa_parse_int_arg(argv[2], &bits)) {
        fprintf(stderr, "Invalid RSA_BITS: %s\n", argv[2]);
        if (csv) {
            fclose(csv);
        }
        return 1;
    }
    if (!rsa_validate_bits(bits)) {
        fprintf(stderr, "Unsupported RSA_BITS=%d; expected 2048, 3072, or 4096\n", bits);
        if (csv) {
            fclose(csv);
        }
        return 1;
    }
    if (argc >= 4) {
        provider = argv[3];
    }

    rsa_seed_rng();

    rsa_provider_state_t provider_state;
    if (!rsa_init_provider(&provider_state, provider)) {
        if (csv) {
            fclose(csv);
        }
        return 1;
    }

    int rc = run_functional(csv, bits, provider);

    rsa_cleanup_provider(&provider_state);
    if (csv) {
        fclose(csv);
    }
    return rc;
}
