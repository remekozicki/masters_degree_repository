#include "../throughput_and_latency/perf_shared.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CT_DEFAULT_SAMPLES = 6000u,
    CT_WARMUP_ITERS = 512u,
    CT_MAX_SIGNIFICANT_HITS = 64u
};

static const double CT_T_THRESHOLD = 4.5;

typedef struct {
    size_t mlen;
    size_t adlen;
} ct_case_t;

typedef struct {
    size_t n;
    double mean;
    double m2;
} ct_stat_t;

typedef struct {
    const char *operation;
    size_t mlen;
    size_t adlen;
    size_t samples;
    const char *class0_label;
    const char *class1_label;
    size_t n0;
    size_t n1;
    double mean0;
    double mean1;
    double t_stat;
    double abs_t;
    int significant;
} ct_result_t;

typedef struct {
    const char *operation;
    size_t mlen;
    size_t adlen;
    double abs_t;
} ct_hit_t;

static double ct_abs(double x)
{
    return (x < 0.0) ? -x : x;
}

static double ct_sqrt(double x)
{
    if (x <= 0.0) {
        return 0.0;
    }

    double g = (x >= 1.0) ? x : 1.0;
    for (int i = 0; i < 30; i++) {
        g = 0.5 * (g + x / g);
    }
    return g;
}

static void ct_stat_add(ct_stat_t *stat, double x)
{
    stat->n++;
    const double delta = x - stat->mean;
    stat->mean += delta / (double)stat->n;
    const double delta2 = x - stat->mean;
    stat->m2 += delta * delta2;
}

static void ct_compute_t(const ct_stat_t *a, const ct_stat_t *b, double *t_stat, double *abs_t)
{
    *t_stat = 0.0;
    *abs_t = 0.0;

    if (a->n < 2u || b->n < 2u) {
        return;
    }

    const double var_a = a->m2 / (double)(a->n - 1u);
    const double var_b = b->m2 / (double)(b->n - 1u);
    const double denom_sq = (var_a / (double)a->n) + (var_b / (double)b->n);
    if (denom_sq <= 0.0) {
        return;
    }

    const double denom = ct_sqrt(denom_sq);
    if (denom <= 0.0) {
        return;
    }

    *t_stat = (a->mean - b->mean) / denom;
    *abs_t = ct_abs(*t_stat);
}

static double ct_now_ticks(void)
{
#if HAVE_CYCLE_COUNTER
    return (double)perf_read_cycles();
#else
    return perf_timer_seconds() * 1e9;
#endif
}

static const char *ct_tick_unit(void)
{
#if HAVE_CYCLE_COUNTER
    return "cycles";
#else
    return "ns";
#endif
}

static void fill_class_payload(int class_id, unsigned char *msg, size_t mlen,
                               unsigned char *ad, size_t adlen)
{
    if (class_id == 0) {
        if (mlen > 0u) {
            memset(msg, 0, mlen);
        }
        if (adlen > 0u) {
            memset(ad, 0, adlen);
        }
    } else {
        if (mlen > 0u) {
            rand_bytes(msg, mlen);
        }
        if (adlen > 0u) {
            rand_bytes(ad, adlen);
        }
    }
}

static int random_class(void)
{
    unsigned char bit = 0;
    rand_bytes(&bit, 1u);
    return (int)(bit & 1u);
}

static void csv_write_header(FILE *csv)
{
    if (!csv) {
        return;
    }

    fprintf(csv,
            "operation,msg_len,ad_len,samples,class0_label,class1_label,"
            "class0_n,class1_n,mean_class0,mean_class1,t_stat,abs_t,threshold,"
            "significant,unit\n");
}

static void csv_write_row(FILE *csv, const ct_result_t *row)
{
    if (!csv) {
        return;
    }

    fprintf(csv,
            "%s,%zu,%zu,%zu,%s,%s,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.2f,%s,%s\n",
            row->operation,
            row->mlen,
            row->adlen,
            row->samples,
            row->class0_label,
            row->class1_label,
            row->n0,
            row->n1,
            row->mean0,
            row->mean1,
            row->t_stat,
            row->abs_t,
            CT_T_THRESHOLD,
            row->significant ? "yes" : "no",
            ct_tick_unit());
}

static void print_result_line(const ct_result_t *row)
{
    printf("%-7s mlen=%-5zu adlen=%-5zu | n0=%-5zu n1=%-5zu | "
           "mean(%s)=%.2f mean(%s)=%.2f | t=%.3f | %s\n",
           row->operation,
           row->mlen,
           row->adlen,
           row->n0,
           row->n1,
           row->class0_label,
           row->mean0,
           row->class1_label,
           row->mean1,
           row->t_stat,
           row->significant ? "SIGNIFICANT" : "not_significant");
}

static int run_encrypt_test(const ct_case_t *test_case, size_t samples, ct_result_t *out)
{
    memset(out, 0, sizeof *out);
    out->operation = "encrypt";
    out->mlen = test_case->mlen;
    out->adlen = test_case->adlen;
    out->samples = samples;
    out->class0_label = "zero";
    out->class1_label = "random";

    const size_t mlen = test_case->mlen;
    const size_t adlen = test_case->adlen;
    const size_t ct_len = mlen + CRYPTO_ABYTES;

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    rand_bytes(key, sizeof key);
    rand_bytes(npub, sizeof npub);

    unsigned char *msg = (unsigned char*)xmalloc(mlen ? mlen : 1u);
    unsigned char *ad = (unsigned char*)xmalloc(adlen ? adlen : 1u);
    unsigned char *ct = (unsigned char*)xmalloc(ct_len ? ct_len : 1u);

    for (size_t i = 0; i < CT_WARMUP_ITERS; i++) {
        const int class_id = (int)(i & 1u);
        fill_class_payload(class_id, msg, mlen, ad, adlen);
        unsigned long long clen = (unsigned long long)ct_len;
        if (crypto_aead_encrypt(ct, &clen,
                                msg, (unsigned long long)mlen,
                                ad, (unsigned long long)adlen,
                                NULL, npub, key) != 0 ||
            clen != (unsigned long long)ct_len) {
            free(msg);
            free(ad);
            free(ct);
            return 0;
        }
    }

    ct_stat_t stats[2];
    memset(stats, 0, sizeof stats);

    for (size_t i = 0; i < samples; i++) {
        const int class_id = random_class();
        fill_class_payload(class_id, msg, mlen, ad, adlen);

        unsigned long long clen = (unsigned long long)ct_len;
        const double t0 = ct_now_ticks();
        const int ret = crypto_aead_encrypt(ct, &clen,
                                            msg, (unsigned long long)mlen,
                                            ad, (unsigned long long)adlen,
                                            NULL, npub, key);
        const double t1 = ct_now_ticks();

        if (ret != 0 || clen != (unsigned long long)ct_len || t1 < t0) {
            free(msg);
            free(ad);
            free(ct);
            return 0;
        }
        ct_stat_add(&stats[class_id], t1 - t0);
    }

    out->n0 = stats[0].n;
    out->n1 = stats[1].n;
    out->mean0 = stats[0].mean;
    out->mean1 = stats[1].mean;
    ct_compute_t(&stats[0], &stats[1], &out->t_stat, &out->abs_t);
    out->significant = (out->abs_t >= CT_T_THRESHOLD) ? 1 : 0;

    free(msg);
    free(ad);
    free(ct);
    return 1;
}

static int run_decrypt_test(const ct_case_t *test_case, size_t samples, ct_result_t *out)
{
    memset(out, 0, sizeof *out);
    out->operation = "decrypt";
    out->mlen = test_case->mlen;
    out->adlen = test_case->adlen;
    out->samples = samples;
    out->class0_label = "zero";
    out->class1_label = "random";

    const size_t mlen = test_case->mlen;
    const size_t adlen = test_case->adlen;
    const size_t ct_len = mlen + CRYPTO_ABYTES;

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    rand_bytes(key, sizeof key);
    rand_bytes(npub, sizeof npub);

    unsigned char *msg = (unsigned char*)xmalloc(mlen ? mlen : 1u);
    unsigned char *ad = (unsigned char*)xmalloc(adlen ? adlen : 1u);
    unsigned char *ct = (unsigned char*)xmalloc(ct_len ? ct_len : 1u);
    unsigned char *dec = (unsigned char*)xmalloc(mlen ? mlen : 1u);

    for (size_t i = 0; i < CT_WARMUP_ITERS; i++) {
        const int class_id = (int)(i & 1u);
        fill_class_payload(class_id, msg, mlen, ad, adlen);

        unsigned long long clen = (unsigned long long)ct_len;
        if (crypto_aead_encrypt(ct, &clen,
                                msg, (unsigned long long)mlen,
                                ad, (unsigned long long)adlen,
                                NULL, npub, key) != 0 ||
            clen != (unsigned long long)ct_len) {
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 0;
        }

        unsigned long long out_mlen = 0ULL;
        if (crypto_aead_decrypt(dec, &out_mlen, NULL,
                                ct, clen,
                                ad, (unsigned long long)adlen,
                                npub, key) != 0 ||
            out_mlen != (unsigned long long)mlen) {
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 0;
        }
    }

    ct_stat_t stats[2];
    memset(stats, 0, sizeof stats);

    for (size_t i = 0; i < samples; i++) {
        const int class_id = random_class();
        fill_class_payload(class_id, msg, mlen, ad, adlen);

        unsigned long long clen = (unsigned long long)ct_len;
        if (crypto_aead_encrypt(ct, &clen,
                                msg, (unsigned long long)mlen,
                                ad, (unsigned long long)adlen,
                                NULL, npub, key) != 0 ||
            clen != (unsigned long long)ct_len) {
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 0;
        }

        unsigned long long out_mlen = 0ULL;
        const double t0 = ct_now_ticks();
        const int ret = crypto_aead_decrypt(dec, &out_mlen, NULL,
                                            ct, clen,
                                            ad, (unsigned long long)adlen,
                                            npub, key);
        const double t1 = ct_now_ticks();

        if (ret != 0 || out_mlen != (unsigned long long)mlen || t1 < t0) {
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 0;
        }
        if (mlen > 0u && memcmp(dec, msg, mlen) != 0) {
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 0;
        }

        ct_stat_add(&stats[class_id], t1 - t0);
    }

    out->n0 = stats[0].n;
    out->n1 = stats[1].n;
    out->mean0 = stats[0].mean;
    out->mean1 = stats[1].mean;
    ct_compute_t(&stats[0], &stats[1], &out->t_stat, &out->abs_t);
    out->significant = (out->abs_t >= CT_T_THRESHOLD) ? 1 : 0;

    free(msg);
    free(ad);
    free(ct);
    free(dec);
    return 1;
}

static int run_verify_test(const ct_case_t *test_case, size_t samples, ct_result_t *out)
{
    memset(out, 0, sizeof *out);
    out->operation = "verify";
    out->mlen = test_case->mlen;
    out->adlen = test_case->adlen;
    out->samples = samples;
    out->class0_label = "valid_tag";
    out->class1_label = "invalid_tag";

    const size_t mlen = test_case->mlen;
    const size_t adlen = test_case->adlen;
    const size_t ct_len = mlen + CRYPTO_ABYTES;

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    rand_bytes(key, sizeof key);
    rand_bytes(npub, sizeof npub);

    unsigned char *msg = (unsigned char*)xmalloc(mlen ? mlen : 1u);
    unsigned char *ad = (unsigned char*)xmalloc(adlen ? adlen : 1u);
    unsigned char *ct_valid = (unsigned char*)xmalloc(ct_len ? ct_len : 1u);
    unsigned char *ct_invalid = (unsigned char*)xmalloc(ct_len ? ct_len : 1u);
    unsigned char *dec = (unsigned char*)xmalloc(mlen ? mlen : 1u);

    if (mlen > 0u) {
        rand_bytes(msg, mlen);
    }
    if (adlen > 0u) {
        rand_bytes(ad, adlen);
    }

    unsigned long long clen = (unsigned long long)ct_len;
    if (crypto_aead_encrypt(ct_valid, &clen,
                            msg, (unsigned long long)mlen,
                            ad, (unsigned long long)adlen,
                            NULL, npub, key) != 0 ||
        clen != (unsigned long long)ct_len) {
        free(msg);
        free(ad);
        free(ct_valid);
        free(ct_invalid);
        free(dec);
        return 0;
    }

    memcpy(ct_invalid, ct_valid, ct_len);
    if (ct_len > 0u) {
        ct_invalid[ct_len - 1u] ^= 0x01u;
    }

    for (size_t i = 0; i < CT_WARMUP_ITERS; i++) {
        const int class_id = (int)(i & 1u);
        const unsigned char *ct_in = (class_id == 0) ? ct_valid : ct_invalid;
        unsigned long long out_mlen = 0ULL;
        const int ret = crypto_aead_decrypt(dec, &out_mlen, NULL,
                                            ct_in, (unsigned long long)ct_len,
                                            ad, (unsigned long long)adlen,
                                            npub, key);
        if (class_id == 0) {
            if (ret != 0 || out_mlen != (unsigned long long)mlen) {
                free(msg);
                free(ad);
                free(ct_valid);
                free(ct_invalid);
                free(dec);
                return 0;
            }
        } else {
            if (ret == 0) {
                free(msg);
                free(ad);
                free(ct_valid);
                free(ct_invalid);
                free(dec);
                return 0;
            }
        }
    }

    ct_stat_t stats[2];
    memset(stats, 0, sizeof stats);

    for (size_t i = 0; i < samples; i++) {
        const int class_id = random_class();
        const unsigned char *ct_in = (class_id == 0) ? ct_valid : ct_invalid;

        unsigned long long out_mlen = 0ULL;
        const double t0 = ct_now_ticks();
        const int ret = crypto_aead_decrypt(dec, &out_mlen, NULL,
                                            ct_in, (unsigned long long)ct_len,
                                            ad, (unsigned long long)adlen,
                                            npub, key);
        const double t1 = ct_now_ticks();

        if (t1 < t0) {
            free(msg);
            free(ad);
            free(ct_valid);
            free(ct_invalid);
            free(dec);
            return 0;
        }

        if (class_id == 0) {
            if (ret != 0 || out_mlen != (unsigned long long)mlen) {
                free(msg);
                free(ad);
                free(ct_valid);
                free(ct_invalid);
                free(dec);
                return 0;
            }
            if (mlen > 0u && memcmp(dec, msg, mlen) != 0) {
                free(msg);
                free(ad);
                free(ct_valid);
                free(ct_invalid);
                free(dec);
                return 0;
            }
        } else {
            if (ret == 0) {
                free(msg);
                free(ad);
                free(ct_valid);
                free(ct_invalid);
                free(dec);
                return 0;
            }
        }

        ct_stat_add(&stats[class_id], t1 - t0);
    }

    out->n0 = stats[0].n;
    out->n1 = stats[1].n;
    out->mean0 = stats[0].mean;
    out->mean1 = stats[1].mean;
    ct_compute_t(&stats[0], &stats[1], &out->t_stat, &out->abs_t);
    out->significant = (out->abs_t >= CT_T_THRESHOLD) ? 1 : 0;

    free(msg);
    free(ad);
    free(ct_valid);
    free(ct_invalid);
    free(dec);
    return 1;
}

static int parse_samples(const char *text, size_t *out_samples)
{
    if (!text || !out_samples) {
        return 0;
    }

    char *end = NULL;
    const unsigned long long parsed = strtoull(text, &end, 10);
    if (end == text || *end != '\0') {
        return 0;
    }
    if (parsed < 100u || parsed > 10000000u || parsed > (unsigned long long)SIZE_MAX) {
        return 0;
    }

    *out_samples = (size_t)parsed;
    return 1;
}

static int run_suite(FILE *csv, size_t samples, int strict_mode)
{
    const ct_case_t cases[] = {
        { 0u, 0u },
        { 16u, 16u },
        { 64u, 32u },
        { 256u, 32u },
        { 1024u, 64u }
    };

    const size_t case_count = sizeof cases / sizeof cases[0];
    const size_t total_checks = case_count * 3u;

    ct_hit_t hits[CT_MAX_SIGNIFICANT_HITS];
    size_t hit_count = 0u;
    size_t checks_done = 0u;

    printf("=== Constant-time sanity (dudect-style Welch t-test) ===\n");
    printf("Timing unit: %s\n", ct_tick_unit());
    printf("Samples per check: %zu\n", samples);
    printf("Significance threshold: |t| >= %.2f\n\n", CT_T_THRESHOLD);

    csv_write_header(csv);

    for (size_t i = 0; i < case_count; i++) {
        ct_result_t row;

        if (!run_encrypt_test(&cases[i], samples, &row)) {
            fprintf(stderr, "encrypt timing check failed for mlen=%zu adlen=%zu\n",
                    cases[i].mlen, cases[i].adlen);
            return 1;
        }
        print_result_line(&row);
        csv_write_row(csv, &row);
        checks_done++;
        if (row.significant && hit_count < CT_MAX_SIGNIFICANT_HITS) {
            hits[hit_count++] = (ct_hit_t){ row.operation, row.mlen, row.adlen, row.abs_t };
        }

        if (!run_decrypt_test(&cases[i], samples, &row)) {
            fprintf(stderr, "decrypt timing check failed for mlen=%zu adlen=%zu\n",
                    cases[i].mlen, cases[i].adlen);
            return 1;
        }
        print_result_line(&row);
        csv_write_row(csv, &row);
        checks_done++;
        if (row.significant && hit_count < CT_MAX_SIGNIFICANT_HITS) {
            hits[hit_count++] = (ct_hit_t){ row.operation, row.mlen, row.adlen, row.abs_t };
        }

        if (!run_verify_test(&cases[i], samples, &row)) {
            fprintf(stderr, "verify timing check failed for mlen=%zu adlen=%zu\n",
                    cases[i].mlen, cases[i].adlen);
            return 1;
        }
        print_result_line(&row);
        csv_write_row(csv, &row);
        checks_done++;
        if (row.significant && hit_count < CT_MAX_SIGNIFICANT_HITS) {
            hits[hit_count++] = (ct_hit_t){ row.operation, row.mlen, row.adlen, row.abs_t };
        }
    }

    printf("\nConstant-time summary:\n");
    printf("+-------------------------------+--------+\n");
    printf("| Checks executed               | %6zu |\n", checks_done);
    printf("| Checks planned                | %6zu |\n", total_checks);
    printf("| Significant findings          | %6zu |\n", hit_count);
    printf("| Threshold |t|                 | %6.2f |\n", CT_T_THRESHOLD);
    printf("+-------------------------------+--------+\n");

    if (hit_count > 0u) {
        printf("\nSignificant findings (possible leakage):\n");
        for (size_t i = 0; i < hit_count; i++) {
            printf("  - %s mlen=%zu adlen=%zu |t|=%.3f\n",
                   hits[i].operation, hits[i].mlen, hits[i].adlen, hits[i].abs_t);
        }
        printf("\n");
    } else {
        printf("\nNo statistically significant differences detected.\n\n");
    }

    if (strict_mode && hit_count > 0u) {
        return 1;
    }
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [CSV_FILE] [SAMPLES] [strict]\n"
            "  CSV_FILE : optional output path\n"
            "  SAMPLES  : optional, default %u (min 100)\n"
            "  strict   : optional literal; return non-zero when any |t| >= %.2f\n",
            prog, CT_DEFAULT_SAMPLES, CT_T_THRESHOLD);
}

int main(int argc, char **argv)
{
    if (argc > 4) {
        usage(argv[0]);
        return 1;
    }

    const char *csv_path = NULL;
    size_t samples = CT_DEFAULT_SAMPLES;
    int strict_mode = 0;

    if (argc >= 2) {
        csv_path = argv[1];
    }
    if (argc >= 3 && !parse_samples(argv[2], &samples)) {
        fprintf(stderr, "Invalid SAMPLES value: %s\n", argv[2]);
        usage(argv[0]);
        return 1;
    }
    if (argc == 4) {
        if (strcmp(argv[3], "strict") == 0) {
            strict_mode = 1;
        } else {
            fprintf(stderr, "Invalid mode: %s (expected: strict)\n", argv[3]);
            usage(argv[0]);
            return 1;
        }
    }

    FILE *csv = NULL;
    if (csv_path) {
        csv = fopen(csv_path, "w");
        if (!csv) {
            perror("fopen CSV");
            return 1;
        }
    }

    const int pin_ok = perf_pin_to_single_core();
    perf_print_stabilization_info(pin_ok);

    const int rc = run_suite(csv, samples, strict_mode);

    if (csv) {
        fclose(csv);
    }
    return rc;
}

