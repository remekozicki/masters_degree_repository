#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

#include "../common/tests_common.h"

enum {
    PROBE_RET_ACCEPTED = 0,
    PROBE_RET_REJECTED = 2,
    PROBE_RET_INTERNAL = 3
};

enum {
    PROBE_ENC_NULL_M_WITH_MLEN = 1,
    PROBE_ENC_NULL_AD_WITH_ADLEN = 2,
    PROBE_ENC_NULL_NPUB = 3,
    PROBE_ENC_NULL_KEY = 4,
    PROBE_ENC_NULL_C = 5,
    PROBE_DEC_NULL_C_WITH_CLEN = 6,
    PROBE_DEC_NULL_AD_WITH_ADLEN = 7,
    PROBE_DEC_NULL_NPUB = 8,
    PROBE_DEC_NULL_KEY = 9,
    PROBE_DEC_NULL_M = 10
};

typedef struct {
    size_t total;
    size_t pass;
    size_t fail;
    size_t warn;
    size_t negative_total;
    size_t negative_rejected;
    size_t nonce_checks;
    size_t nonce_detected;
} stats_t;

static void write_csv(FILE *csv, const char *category, const char *test_name,
                      const char *expected, const char *observed, const char *result)
{
    if (!csv) {
        return;
    }

    fprintf(csv, "%s,%s,%s,%s,%s\n", category, test_name, expected, observed, result);
}

static void note_pass(stats_t *stats)
{
    stats->total++;
    stats->pass++;
}

static void note_fail(stats_t *stats)
{
    stats->total++;
    stats->fail++;
}

static void note_warn(stats_t *stats)
{
    stats->total++;
    stats->warn++;
}

static void note_negative(stats_t *stats, int rejected)
{
    stats->negative_total++;
    if (rejected) {
        stats->negative_rejected++;
    }
}

static void test_zero_length_nulls(FILE *csv, stats_t *stats)
{
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    rand_bytes(key, sizeof key);
    rand_bytes(npub, sizeof npub);

    unsigned long long clen = CRYPTO_ABYTES;
    unsigned char *c = (unsigned char*)xmalloc((size_t)(CRYPTO_ABYTES ? CRYPTO_ABYTES : 1));
    int enc_ret = crypto_aead_encrypt(c, &clen, NULL, 0, NULL, 0, NULL, npub, key);
    if (enc_ret == 0 && clen == (unsigned long long)CRYPTO_ABYTES) {
        note_pass(stats);
        write_csv(csv, "null_zero", "encrypt_mnull_adnull_len0", "success", "success", "PASS");
    } else {
        note_fail(stats);
        write_csv(csv, "null_zero", "encrypt_mnull_adnull_len0", "success", "fail", "FAIL");
        free(c);
        return;
    }

    unsigned char m[1] = {0};
    unsigned long long mlen = 0;
    int dec_ret = crypto_aead_decrypt(m, &mlen, NULL, c, clen, NULL, 0, npub, key);
    if (dec_ret == 0 && mlen == 0) {
        note_pass(stats);
        write_csv(csv, "null_zero", "decrypt_adnull_len0", "success", "success", "PASS");
    } else {
        note_fail(stats);
        write_csv(csv, "null_zero", "decrypt_adnull_len0", "success", "fail", "FAIL");
    }

    free(c);
}

static void test_overlap_buffers(FILE *csv, stats_t *stats)
{
    const size_t mlen = 32u;
    const size_t adlen = 16u;

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    unsigned char msg[32];
    unsigned char ad[16];

    rand_bytes(key, sizeof key);
    rand_bytes(npub, sizeof npub);
    rand_bytes(msg, sizeof msg);
    rand_bytes(ad, sizeof ad);

    unsigned long long clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
    unsigned char *buf = (unsigned char*)xmalloc((size_t)clen);
    memcpy(buf, msg, mlen);

    int ret = crypto_aead_encrypt(buf, &clen, buf, (unsigned long long)mlen,
                                  ad, (unsigned long long)adlen,
                                  NULL, npub, key);
    note_negative(stats, ret != 0);
    if (ret != 0) {
        note_pass(stats);
        write_csv(csv, "overlap", "encrypt_c_eq_m", "reject", "rejected", "PASS");
    } else {
        note_fail(stats);
        write_csv(csv, "overlap", "encrypt_c_eq_m", "reject", "accepted", "FAIL");
    }
    free(buf);

    clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
    unsigned char *storage = (unsigned char*)xmalloc((size_t)clen + 16u);
    unsigned char *c_out = storage;
    unsigned char *m_in = storage + 8u; /* partial overlap */
    memcpy(m_in, msg, mlen);
    ret = crypto_aead_encrypt(c_out, &clen, m_in, (unsigned long long)mlen,
                              ad, (unsigned long long)adlen,
                              NULL, npub, key);
    note_negative(stats, ret != 0);
    if (ret != 0) {
        note_pass(stats);
        write_csv(csv, "overlap", "encrypt_partial_overlap", "reject", "rejected", "PASS");
    } else {
        note_fail(stats);
        write_csv(csv, "overlap", "encrypt_partial_overlap", "reject", "accepted", "FAIL");
    }
    free(storage);

    unsigned long long good_clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
    unsigned char *good_c = (unsigned char*)xmalloc((size_t)good_clen);
    ret = crypto_aead_encrypt(good_c, &good_clen, msg, (unsigned long long)mlen,
                              ad, (unsigned long long)adlen,
                              NULL, npub, key);
    if (ret != 0) {
        note_fail(stats);
        write_csv(csv, "overlap", "decrypt_c_eq_m_setup", "success", "fail", "FAIL");
        free(good_c);
        return;
    }

    unsigned long long out_len = 0;
    ret = crypto_aead_decrypt(good_c, &out_len, NULL, good_c, good_clen,
                              ad, (unsigned long long)adlen, npub, key);
    note_negative(stats, ret != 0);
    if (ret != 0) {
        note_pass(stats);
        write_csv(csv, "overlap", "decrypt_c_eq_m", "reject", "rejected", "PASS");
    } else {
        note_fail(stats);
        write_csv(csv, "overlap", "decrypt_c_eq_m", "reject", "accepted", "FAIL");
    }
    free(good_c);
}

static void test_nonce_reuse(FILE *csv, stats_t *stats)
{
    const size_t mlen = 24u;
    const size_t adlen = 13u;
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    unsigned char msg[24];
    unsigned char ad[13];
    unsigned char c1[24 + CRYPTO_ABYTES];
    unsigned char c2[24 + CRYPTO_ABYTES];
    unsigned long long clen1 = (unsigned long long)(mlen + CRYPTO_ABYTES);
    unsigned long long clen2 = (unsigned long long)(mlen + CRYPTO_ABYTES);

    rand_bytes(key, sizeof key);
    rand_bytes(npub, sizeof npub);
    rand_bytes(msg, sizeof msg);
    rand_bytes(ad, sizeof ad);

    int r1 = crypto_aead_encrypt(c1, &clen1, msg, (unsigned long long)mlen,
                                 ad, (unsigned long long)adlen, NULL, npub, key);
    if (r1 != 0) {
        note_fail(stats);
        write_csv(csv, "nonce_reuse", "first_encrypt", "success", "fail", "FAIL");
        return;
    }
    note_pass(stats);
    write_csv(csv, "nonce_reuse", "first_encrypt", "success", "success", "PASS");

    int r2 = crypto_aead_encrypt(c2, &clen2, msg, (unsigned long long)mlen,
                                 ad, (unsigned long long)adlen, NULL, npub, key);
    stats->nonce_checks++;
    if (r2 != 0) {
        stats->nonce_detected++;
        note_pass(stats);
        write_csv(csv, "nonce_reuse", "second_encrypt_same_key_nonce", "reject_or_warn", "rejected", "PASS");
        return;
    }

    note_warn(stats);
    if (clen1 == clen2 && memcmp(c1, c2, (size_t)clen1) == 0) {
        write_csv(csv, "nonce_reuse", "second_encrypt_same_key_nonce", "reject_or_warn", "accepted_deterministic", "WARN");
    } else {
        write_csv(csv, "nonce_reuse", "second_encrypt_same_key_nonce", "reject_or_warn", "accepted", "WARN");
    }
}

static int run_probe_case(int case_id)
{
    const size_t mlen = 16u;
    const size_t adlen = 8u;

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    unsigned char msg[16];
    unsigned char ad[8];
    unsigned char c[16 + CRYPTO_ABYTES];
    unsigned char m_out[16];

    rand_bytes(key, sizeof key);
    rand_bytes(npub, sizeof npub);
    rand_bytes(msg, sizeof msg);
    rand_bytes(ad, sizeof ad);

    unsigned long long clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
    unsigned long long mlen_out = mlen;
    int ret = 0;

    if (case_id >= PROBE_DEC_NULL_C_WITH_CLEN) {
        ret = crypto_aead_encrypt(c, &clen, msg, (unsigned long long)mlen,
                                  ad, (unsigned long long)adlen,
                                  NULL, npub, key);
        if (ret != 0) {
            return PROBE_RET_INTERNAL;
        }
    }

    switch (case_id) {
        case PROBE_ENC_NULL_M_WITH_MLEN:
            ret = crypto_aead_encrypt(c, &clen, NULL, (unsigned long long)mlen,
                                      ad, (unsigned long long)adlen,
                                      NULL, npub, key);
            break;
        case PROBE_ENC_NULL_AD_WITH_ADLEN:
            ret = crypto_aead_encrypt(c, &clen, msg, (unsigned long long)mlen,
                                      NULL, (unsigned long long)adlen,
                                      NULL, npub, key);
            break;
        case PROBE_ENC_NULL_NPUB:
            ret = crypto_aead_encrypt(c, &clen, msg, (unsigned long long)mlen,
                                      ad, (unsigned long long)adlen,
                                      NULL, NULL, key);
            break;
        case PROBE_ENC_NULL_KEY:
            ret = crypto_aead_encrypt(c, &clen, msg, (unsigned long long)mlen,
                                      ad, (unsigned long long)adlen,
                                      NULL, npub, NULL);
            break;
        case PROBE_ENC_NULL_C:
            ret = crypto_aead_encrypt(NULL, &clen, msg, (unsigned long long)mlen,
                                      ad, (unsigned long long)adlen,
                                      NULL, npub, key);
            break;
        case PROBE_DEC_NULL_C_WITH_CLEN:
            ret = crypto_aead_decrypt(m_out, &mlen_out, NULL,
                                      NULL, clen,
                                      ad, (unsigned long long)adlen,
                                      npub, key);
            break;
        case PROBE_DEC_NULL_AD_WITH_ADLEN:
            ret = crypto_aead_decrypt(m_out, &mlen_out, NULL,
                                      c, clen,
                                      NULL, (unsigned long long)adlen,
                                      npub, key);
            break;
        case PROBE_DEC_NULL_NPUB:
            ret = crypto_aead_decrypt(m_out, &mlen_out, NULL,
                                      c, clen,
                                      ad, (unsigned long long)adlen,
                                      NULL, key);
            break;
        case PROBE_DEC_NULL_KEY:
            ret = crypto_aead_decrypt(m_out, &mlen_out, NULL,
                                      c, clen,
                                      ad, (unsigned long long)adlen,
                                      npub, NULL);
            break;
        case PROBE_DEC_NULL_M:
            ret = crypto_aead_decrypt(NULL, &mlen_out, NULL,
                                      c, clen,
                                      ad, (unsigned long long)adlen,
                                      npub, key);
            break;
        default:
            return PROBE_RET_INTERNAL;
    }

    return (ret != 0) ? PROBE_RET_REJECTED : PROBE_RET_ACCEPTED;
}

static int normalize_system_exit(int system_rc)
{
#if defined(_WIN32)
    return system_rc;
#else
    if (system_rc == -1) {
        return -1;
    }
    if (WIFEXITED(system_rc)) {
        return WEXITSTATUS(system_rc);
    }
    return 128;
#endif
}

static int run_probe_subprocess(const char *program_name, int case_id)
{
    char cmd[1024];
    const int has_sep = (strchr(program_name, '/') != NULL) ||
                        (strchr(program_name, '\\') != NULL);
#if defined(_WIN32)
    const char *prefix = has_sep ? "" : ".\\";
    int n = snprintf(cmd, sizeof cmd,
                     "\"%s%s\" --probe-case %d > NUL 2>&1",
                     prefix, program_name, case_id);
#else
    const char *prefix = has_sep ? "" : "./";
    int n = snprintf(cmd, sizeof cmd,
                     "\"%s%s\" --probe-case %d > /dev/null 2>&1",
                     prefix, program_name, case_id);
#endif
    if (n <= 0 || (size_t)n >= sizeof cmd) {
        return -1;
    }

    return normalize_system_exit(system(cmd));
}

static void test_null_pointer_probes(const char *program_name, FILE *csv, stats_t *stats)
{
    static const struct {
        int id;
        const char *name;
    } probes[] = {
        { PROBE_ENC_NULL_M_WITH_MLEN, "enc_null_m_with_mlen" },
        { PROBE_ENC_NULL_AD_WITH_ADLEN, "enc_null_ad_with_adlen" },
        { PROBE_ENC_NULL_NPUB, "enc_null_npub" },
        { PROBE_ENC_NULL_KEY, "enc_null_key" },
        { PROBE_ENC_NULL_C, "enc_null_c" },
        { PROBE_DEC_NULL_C_WITH_CLEN, "dec_null_c_with_clen" },
        { PROBE_DEC_NULL_AD_WITH_ADLEN, "dec_null_ad_with_adlen" },
        { PROBE_DEC_NULL_NPUB, "dec_null_npub" },
        { PROBE_DEC_NULL_KEY, "dec_null_key" },
        { PROBE_DEC_NULL_M, "dec_null_m" }
    };

    const size_t count = sizeof probes / sizeof probes[0];
    for (size_t i = 0; i < count; i++) {
        int rc = run_probe_subprocess(program_name, probes[i].id);
        note_negative(stats, rc == PROBE_RET_REJECTED);

        if (rc == PROBE_RET_REJECTED) {
            note_pass(stats);
            write_csv(csv, "null_invalid", probes[i].name, "reject", "rejected", "PASS");
        } else if (rc == PROBE_RET_ACCEPTED) {
            note_fail(stats);
            write_csv(csv, "null_invalid", probes[i].name, "reject", "accepted", "FAIL");
        } else if (rc == PROBE_RET_INTERNAL) {
            note_fail(stats);
            write_csv(csv, "null_invalid", probes[i].name, "reject", "internal_error", "FAIL");
        } else {
            char observed[64];
            snprintf(observed, sizeof observed, "crash_or_exit_%d", rc);
            note_fail(stats);
            write_csv(csv, "null_invalid", probes[i].name, "reject", observed, "FAIL");
        }
    }
}

static int run_api_tests(const char *program_name, FILE *csv)
{
    stats_t stats;
    memset(&stats, 0, sizeof stats);

    if (csv) {
        fprintf(csv, "category,test,expected,observed,result\n");
    }

    test_zero_length_nulls(csv, &stats);
    test_nonce_reuse(csv, &stats);
    test_overlap_buffers(csv, &stats);
    test_null_pointer_probes(program_name, csv, &stats);

    printf("\nAPI tests summary:\n");
    printf("+----------------------------+--------+\n");
    printf("| Total checks               | %6zu |\n", stats.total);
    printf("| Passed                     | %6zu |\n", stats.pass);
    printf("| Warnings                   | %6zu |\n", stats.warn);
    printf("| Failed                     | %6zu |\n", stats.fail);
    printf("| Negative checks            | %6zu |\n", stats.negative_total);
    printf("| Negatives rejected         | %6zu |\n", stats.negative_rejected);
    printf("| Nonce-reuse checks         | %6zu |\n", stats.nonce_checks);
    printf("| Nonce-reuse detections     | %6zu |\n", stats.nonce_detected);
    printf("+----------------------------+--------+\n\n");

    return (stats.fail == 0u) ? 0 : 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [CSV_FILE]\n"
            "       %s --probe-case ID\n", prog, prog);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--probe-case") == 0) {
        int case_id = atoi(argv[2]);
        return run_probe_case(case_id);
    }

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

    int rc = run_api_tests(argv[0], csv);

    if (csv) {
        fclose(csv);
    }
    return rc;
}
