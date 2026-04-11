#include "perf_shared.h"

static const size_t throughput_msg_sizes[] = {
    0u, 16u, 64u, 256u, 1024u, 4096u, 16384u, 65536u, 262144u, 1048576u
};

static const size_t throughput_msg_sizes_count =
    sizeof(throughput_msg_sizes) / sizeof(throughput_msg_sizes[0]);

enum {
    THROUGHPUT_AD_LEN = 32,
    THROUGHPUT_SAMPLES = 3,
    THROUGHPUT_WARMUP_OPS = 512
};

static const unsigned long long THROUGHPUT_TARGET_BYTES = 16ULL * 1024ULL * 1024ULL;

static void throughput_iterations_for_size(size_t mlen, size_t *iters_out)
{
    if (mlen == 0u) {
        *iters_out = 50000u;
        return;
    }

    unsigned long long iters = THROUGHPUT_TARGET_BYTES / (unsigned long long)mlen;
    if (iters < 64ULL) {
        iters = 64ULL;
    }
    if (iters > 500000ULL) {
        iters = 500000ULL;
    }
    *iters_out = (size_t)iters;
}

static int run_throughput(FILE *csv, int pin_ok)
{
    printf("=== Throughput benchmark (MB/s) ===\n");

    if (csv) {
        fprintf(csv, "msg_len,ad_len,samples,iters_per_sample,enc_MBps,dec_MBps,enc_cycles_per_byte,dec_cycles_per_byte,pinning_core0,warmup_ops,notes\n");
    }

    for (size_t idx = 0; idx < throughput_msg_sizes_count; idx++) {
        const size_t mlen = throughput_msg_sizes[idx];
        const size_t adlen = THROUGHPUT_AD_LEN;

        unsigned char key[CRYPTO_KEYBYTES];
        unsigned char npub_base[CRYPTO_NPUBBYTES];
        rand_bytes(key, sizeof key);
        rand_bytes(npub_base, sizeof npub_base);

        unsigned char *msg = (unsigned char*)xmalloc(mlen ? mlen : 1u);
        unsigned char *ad = (unsigned char*)xmalloc(adlen);
        unsigned char *ct = (unsigned char*)xmalloc(mlen + CRYPTO_ABYTES);
        unsigned char *dec = (unsigned char*)xmalloc(mlen ? mlen : 1u);
        rand_bytes(msg, mlen);
        rand_bytes(ad, adlen);

        if (!perf_one_shot_encrypt_decrypt_ok(msg, mlen, ad, adlen, key, npub_base, ct, dec)) {
            fprintf(stderr, "Correctness precheck failed in throughput mode (mlen=%zu)\n", mlen);
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 1;
        }

        size_t iters = 0u;
        throughput_iterations_for_size(mlen, &iters);

        double enc_mbps_samples[THROUGHPUT_SAMPLES];
        double dec_mbps_samples[THROUGHPUT_SAMPLES];
        double enc_cpb_samples[THROUGHPUT_SAMPLES];
        double dec_cpb_samples[THROUGHPUT_SAMPLES];
        memset(enc_mbps_samples, 0, sizeof enc_mbps_samples);
        memset(dec_mbps_samples, 0, sizeof dec_mbps_samples);
        for (size_t s = 0; s < THROUGHPUT_SAMPLES; s++) {
            enc_cpb_samples[s] = -1.0;
            dec_cpb_samples[s] = -1.0;
        }

        int all_ok = 1;
        for (size_t sample = 0; sample < THROUGHPUT_SAMPLES && all_ok; sample++) {
            unsigned char npub_enc[CRYPTO_NPUBBYTES];
            memcpy(npub_enc, npub_base, sizeof npub_enc);
            for (size_t k = 0; k < sample; k++) {
                perf_bump_nonce(npub_enc, sizeof npub_enc);
            }

            if (!perf_warmup_encrypt(msg, mlen, ad, adlen, key, npub_enc, ct, THROUGHPUT_WARMUP_OPS)) {
                all_ok = 0;
                break;
            }

            unsigned long long expected_clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
            const double t0 = perf_timer_seconds();
            const unsigned long long c0 = perf_read_cycles();
            for (size_t i = 0; i < iters; i++) {
                unsigned long long clen = expected_clen;
                int ret = crypto_aead_encrypt(ct, &clen,
                                              msg, (unsigned long long)mlen,
                                              ad, (unsigned long long)adlen,
                                              NULL, npub_enc, key);
                if (ret != 0 || clen != expected_clen) {
                    all_ok = 0;
                    break;
                }
                perf_bump_nonce(npub_enc, sizeof npub_enc);
            }
            const unsigned long long c1 = perf_read_cycles();
            const double t1 = perf_timer_seconds();
            if (!all_ok) {
                break;
            }

            const double enc_secs = t1 - t0;
            const double enc_bytes = (double)mlen * (double)iters;
            enc_mbps_samples[sample] = (enc_secs > 0.0)
                ? (enc_bytes / (enc_secs * 1024.0 * 1024.0))
                : 0.0;
#if HAVE_CYCLE_COUNTER
            if (mlen > 0u && iters > 0u) {
                enc_cpb_samples[sample] = (double)(c1 - c0) / enc_bytes;
            }
#endif

            unsigned char npub_dec[CRYPTO_NPUBBYTES];
            memcpy(npub_dec, npub_base, sizeof npub_dec);
            unsigned long long clen_once = expected_clen;
            int ret = crypto_aead_encrypt(ct, &clen_once,
                                          msg, (unsigned long long)mlen,
                                          ad, (unsigned long long)adlen,
                                          NULL, npub_dec, key);
            if (ret != 0 || clen_once != expected_clen) {
                all_ok = 0;
                break;
            }

            if (!perf_warmup_decrypt(ct, clen_once, ad, adlen, key, npub_dec, dec, THROUGHPUT_WARMUP_OPS)) {
                all_ok = 0;
                break;
            }

            const double d0 = perf_timer_seconds();
            const unsigned long long dc0 = perf_read_cycles();
            for (size_t i = 0; i < iters; i++) {
                unsigned long long out_mlen = 0;
                ret = crypto_aead_decrypt(dec, &out_mlen, NULL,
                                          ct, clen_once,
                                          ad, (unsigned long long)adlen,
                                          npub_dec, key);
                if (ret != 0 || out_mlen != (unsigned long long)mlen) {
                    all_ok = 0;
                    break;
                }
            }
            const unsigned long long dc1 = perf_read_cycles();
            const double d1 = perf_timer_seconds();
            if (!all_ok) {
                break;
            }

            const double dec_secs = d1 - d0;
            dec_mbps_samples[sample] = (dec_secs > 0.0)
                ? (enc_bytes / (dec_secs * 1024.0 * 1024.0))
                : 0.0;
#if HAVE_CYCLE_COUNTER
            if (mlen > 0u && iters > 0u) {
                dec_cpb_samples[sample] = (double)(dc1 - dc0) / enc_bytes;
            }
#endif
        }

        if (!all_ok) {
            fprintf(stderr, "Throughput benchmark failed (mlen=%zu)\n", mlen);
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 1;
        }

        const double enc_mbps = perf_average(enc_mbps_samples, THROUGHPUT_SAMPLES);
        const double dec_mbps = perf_average(dec_mbps_samples, THROUGHPUT_SAMPLES);
        const double enc_cpb = perf_average(enc_cpb_samples, THROUGHPUT_SAMPLES);
        const double dec_cpb = perf_average(dec_cpb_samples, THROUGHPUT_SAMPLES);

        printf("throughput mlen=%-8zu adlen=%-3zu : enc=%.2f MB/s, dec=%.2f MB/s",
               mlen, adlen, enc_mbps, dec_mbps);
#if HAVE_CYCLE_COUNTER
        if (mlen > 0u) {
            printf(", enc=%.2f cyc/B, dec=%.2f cyc/B", enc_cpb, dec_cpb);
        }
#endif
        printf("\n");

        if (csv) {
            if (mlen > 0u && HAVE_CYCLE_COUNTER) {
                fprintf(csv, "%zu,%zu,%d,%zu,%.6f,%.6f,%.6f,%.6f,%d,%d,%s\n",
                        mlen, adlen, THROUGHPUT_SAMPLES, iters,
                        enc_mbps, dec_mbps, enc_cpb, dec_cpb,
                        pin_ok, THROUGHPUT_WARMUP_OPS, "mbps_and_cycles");
            } else {
                fprintf(csv, "%zu,%zu,%d,%zu,%.6f,%.6f,,,%d,%d,%s\n",
                        mlen, adlen, THROUGHPUT_SAMPLES, iters,
                        enc_mbps, dec_mbps,
                        pin_ok, THROUGHPUT_WARMUP_OPS, "mbps");
            }
        }

        free(msg);
        free(ad);
        free(ct);
        free(dec);
    }

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [CSV_FILE]\n", prog);
}

int main(int argc, char **argv)
{
    if (argc > 2) {
        usage(argv[0]);
        return 1;
    }

    FILE *csv = NULL;
    if (argc == 2) {
        csv = fopen(argv[1], "w");
        if (!csv) {
            perror("fopen CSV");
            return 1;
        }
    }

    int pin_ok = perf_pin_to_single_core();
    perf_print_stabilization_info(pin_ok);

    int rc = run_throughput(csv, pin_ok);
    if (csv) {
        fclose(csv);
    }
    return rc;
}
