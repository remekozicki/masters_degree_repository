#include "perf_shared.h"

enum {
    LATENCY_AD_LEN = 16,
    LATENCY_SAMPLES = 5,
    LATENCY_TOTAL_REPEATS = 10000,
    LATENCY_WARMUP_OPS = 512
};

static int run_latency(FILE *csv, int pin_ok)
{
    printf("=== Latency benchmark (us/op, 0..64 B) ===\n");

    if (csv) {
        fprintf(csv, "msg_len,ad_len,samples,repeats_per_sample,enc_us,dec_us,pinning_core0,warmup_ops,notes\n");
    }

    const size_t latency_min = 0u;
    const size_t latency_max = 64u;
    const size_t latency_count = latency_max - latency_min + 1u;
    const size_t repeats_per_sample = (size_t)(LATENCY_TOTAL_REPEATS / LATENCY_SAMPLES);

    for (size_t mlen = latency_min; mlen < latency_count; mlen++) {
        const size_t adlen = LATENCY_AD_LEN;

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
            fprintf(stderr, "Correctness precheck failed in latency mode (mlen=%zu)\n", mlen);
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 1;
        }

        double enc_us_samples[LATENCY_SAMPLES];
        double dec_us_samples[LATENCY_SAMPLES];
        memset(enc_us_samples, 0, sizeof enc_us_samples);
        memset(dec_us_samples, 0, sizeof dec_us_samples);

        int all_ok = 1;
        for (size_t sample = 0; sample < LATENCY_SAMPLES && all_ok; sample++) {
            unsigned char npub_enc[CRYPTO_NPUBBYTES];
            memcpy(npub_enc, npub_base, sizeof npub_enc);
            for (size_t k = 0; k < sample; k++) {
                perf_bump_nonce(npub_enc, sizeof npub_enc);
            }

            if (!perf_warmup_encrypt(msg, mlen, ad, adlen, key, npub_enc, ct, LATENCY_WARMUP_OPS)) {
                all_ok = 0;
                break;
            }

            const unsigned long long expected_clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
            const double t0 = perf_timer_seconds();
            for (size_t i = 0; i < repeats_per_sample; i++) {
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
            const double t1 = perf_timer_seconds();
            if (!all_ok) {
                break;
            }

            enc_us_samples[sample] = ((t1 - t0) * 1e6) / (double)repeats_per_sample;

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

            if (!perf_warmup_decrypt(ct, clen_once, ad, adlen, key, npub_dec, dec, LATENCY_WARMUP_OPS)) {
                all_ok = 0;
                break;
            }

            const double d0 = perf_timer_seconds();
            for (size_t i = 0; i < repeats_per_sample; i++) {
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
            const double d1 = perf_timer_seconds();
            if (!all_ok) {
                break;
            }

            dec_us_samples[sample] = ((d1 - d0) * 1e6) / (double)repeats_per_sample;
        }

        if (!all_ok) {
            fprintf(stderr, "Latency benchmark failed (mlen=%zu)\n", mlen);
            free(msg);
            free(ad);
            free(ct);
            free(dec);
            return 1;
        }

        const double enc_us = perf_average(enc_us_samples, LATENCY_SAMPLES);
        const double dec_us = perf_average(dec_us_samples, LATENCY_SAMPLES);

        printf("latency   mlen=%-2zu adlen=%-3zu : enc=%.3f us/op, dec=%.3f us/op\n",
               mlen, adlen, enc_us, dec_us);

        if (csv) {
            fprintf(csv, "%zu,%zu,%d,%zu,%.6f,%.6f,%d,%d,%s\n",
                    mlen, adlen, LATENCY_SAMPLES, repeats_per_sample,
                    enc_us, dec_us, pin_ok, LATENCY_WARMUP_OPS, "us_per_op");
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

    int rc = run_latency(csv, pin_ok);
    if (csv) {
        fclose(csv);
    }
    return rc;
}
