#include "rsa_common.h"

enum {
    RSA_LATENCY_SAMPLES = 5,
    RSA_THROUGHPUT_SAMPLES = 3
};

typedef struct {
    double us_per_op;
    double ops_per_sec;
    double cycles_per_op;
} rsa_perf_result_t;

typedef int (*rsa_perf_op_fn)(void *ctx);

typedef struct {
    EVP_PKEY *key;
    const unsigned char *msg;
    size_t msg_len;
    unsigned char *out;
    size_t out_cap;
} rsa_oaep_encrypt_case_t;

typedef struct {
    EVP_PKEY *key;
    const unsigned char *ct;
    size_t ct_len;
    size_t expected_msg_len;
    unsigned char *out;
    size_t out_cap;
} rsa_oaep_decrypt_case_t;

typedef struct {
    EVP_PKEY *key;
    const unsigned char *msg;
    size_t msg_len;
    unsigned char *sig;
    size_t sig_cap;
} rsa_pss_sign_case_t;

typedef struct {
    EVP_PKEY *key;
    const unsigned char *msg;
    size_t msg_len;
    const unsigned char *sig;
    size_t sig_len;
} rsa_pss_verify_case_t;

static int op_oaep_encrypt(void *opaque)
{
    rsa_oaep_encrypt_case_t *ctx = (rsa_oaep_encrypt_case_t*)opaque;
    size_t out_len = ctx->out_cap;
    int ok = rsa_oaep_encrypt(ctx->key, ctx->msg, ctx->msg_len, ctx->out, &out_len);
    if (ok && out_len > 0u) {
        rsa_common_sink ^= ctx->out[0];
    }
    return ok;
}

static int op_oaep_decrypt(void *opaque)
{
    rsa_oaep_decrypt_case_t *ctx = (rsa_oaep_decrypt_case_t*)opaque;
    size_t out_len = ctx->out_cap;
    int ok = rsa_oaep_decrypt(ctx->key, ctx->ct, ctx->ct_len, ctx->out, &out_len);
    ok = ok && out_len == ctx->expected_msg_len;
    if (ok && out_len > 0u) {
        rsa_common_sink ^= ctx->out[0];
    }
    return ok;
}

static int op_pss_sign(void *opaque)
{
    rsa_pss_sign_case_t *ctx = (rsa_pss_sign_case_t*)opaque;
    size_t sig_len = ctx->sig_cap;
    int ok = rsa_pss_sign(ctx->key, ctx->msg, ctx->msg_len, ctx->sig, &sig_len);
    if (ok && sig_len > 0u) {
        rsa_common_sink ^= ctx->sig[0];
    }
    return ok;
}

static int op_pss_verify(void *opaque)
{
    rsa_pss_verify_case_t *ctx = (rsa_pss_verify_case_t*)opaque;
    int ret = rsa_pss_verify(ctx->key, ctx->msg, ctx->msg_len, ctx->sig, ctx->sig_len);
    rsa_common_sink ^= (unsigned char)ret;
    return ret == 1;
}

static int measure_operation(rsa_perf_op_fn op,
                             void *ctx,
                             size_t samples,
                             size_t repeats,
                             rsa_perf_result_t *out)
{
    double us_samples[8];
    double ops_samples[8];
    double cycles_samples[8];

    if (samples > sizeof us_samples / sizeof us_samples[0]) {
        return 0;
    }

    for (size_t i = 0; i < RSA_WARMUP_OPS; i++) {
        if (!op(ctx)) {
            return 0;
        }
    }

    for (size_t s = 0; s < samples; s++) {
        const double t0 = rsa_timer_seconds();
        const unsigned long long c0 = rsa_read_cycles();
        for (size_t i = 0; i < repeats; i++) {
            if (!op(ctx)) {
                return 0;
            }
        }
        const unsigned long long c1 = rsa_read_cycles();
        const double t1 = rsa_timer_seconds();
        const double seconds = t1 - t0;

        us_samples[s] = seconds > 0.0 ? (seconds * 1e6) / (double)repeats : 0.0;
        ops_samples[s] = seconds > 0.0 ? (double)repeats / seconds : 0.0;
#if RSA_HAVE_CYCLE_COUNTER
        cycles_samples[s] = (double)(c1 - c0) / (double)repeats;
#else
        (void)c0;
        (void)c1;
        cycles_samples[s] = -1.0;
#endif
    }

    out->us_per_op = rsa_average_double(us_samples, samples);
    out->ops_per_sec = rsa_average_double(ops_samples, samples);
    out->cycles_per_op = rsa_average_double(cycles_samples, samples);
    return 1;
}

static size_t latency_repeats_for_bits(int bits)
{
    if (bits >= 4096) {
        return 12u;
    }
    if (bits >= 3072) {
        return 24u;
    }
    return 48u;
}

static size_t throughput_repeats_for_bits(int bits)
{
    if (bits >= 4096) {
        return 24u;
    }
    if (bits >= 3072) {
        return 48u;
    }
    return 96u;
}

static int run_perf_mode(FILE *csv, int bits, const char *provider, int throughput_mode)
{
    static const size_t oaep_lengths[] = {
        16u, 32u, 64u, 128u, 190u, 318u, 446u
    };
    static const size_t pss_lengths[] = {
        32u, 64u, 256u, 1024u
    };

    const size_t samples = throughput_mode ? RSA_THROUGHPUT_SAMPLES : RSA_LATENCY_SAMPLES;
    const size_t repeats = throughput_mode
        ? throughput_repeats_for_bits(bits)
        : latency_repeats_for_bits(bits);
    const char *mode_name = throughput_mode ? "throughput" : "latency";

    printf("=== RSA %s (%d-bit, provider=%s) ===\n", mode_name, bits, provider);

    if (csv) {
        fprintf(csv,
                "operation,bits,msg_len,samples,repeats_per_sample,us_per_op,ops_per_sec,input_kBps,cycles_per_op,pinning_core0,warmup_ops,provider,notes\n");
    }

    int pin_ok = rsa_pin_to_single_core();
    rsa_print_stabilization_info(pin_ok);

    EVP_PKEY *key = rsa_generate_key(bits);
    if (!key) {
        return 1;
    }

    const size_t modulus_len = rsa_modulus_bytes_from_bits(bits);
    const size_t max_oaep = rsa_oaep_sha256_max_plaintext(bits);
    unsigned char *msg = (unsigned char*)rsa_xmalloc(max_oaep ? max_oaep : 1u);
    unsigned char *ct = (unsigned char*)rsa_xmalloc(modulus_len);
    unsigned char *out = (unsigned char*)rsa_xmalloc(modulus_len);
    unsigned char *sig = (unsigned char*)rsa_xmalloc(modulus_len);

    for (size_t i = 0; i < sizeof oaep_lengths / sizeof oaep_lengths[0]; i++) {
        const size_t msg_len = oaep_lengths[i];
        if (msg_len > max_oaep) {
            continue;
        }
        rsa_rand_bytes(msg, msg_len);

        size_t ct_len = modulus_len;
        if (!rsa_oaep_encrypt(key, msg, msg_len, ct, &ct_len)) {
            fprintf(stderr, "RSA OAEP setup encrypt failed (msg_len=%zu)\n", msg_len);
            free(sig);
            free(out);
            free(ct);
            free(msg);
            EVP_PKEY_free(key);
            return 1;
        }

        rsa_oaep_encrypt_case_t enc_case = { key, msg, msg_len, ct, modulus_len };
        rsa_oaep_decrypt_case_t dec_case = { key, ct, ct_len, msg_len, out, modulus_len };

        rsa_perf_result_t enc_result;
        rsa_perf_result_t dec_result;
        if (!measure_operation(op_oaep_encrypt, &enc_case, samples, repeats, &enc_result)) {
            fprintf(stderr, "RSA OAEP encrypt benchmark failed (msg_len=%zu)\n", msg_len);
            free(sig);
            free(out);
            free(ct);
            free(msg);
            EVP_PKEY_free(key);
            return 1;
        }
        if (!measure_operation(op_oaep_decrypt, &dec_case, samples, repeats, &dec_result)) {
            fprintf(stderr, "RSA OAEP decrypt benchmark failed (msg_len=%zu)\n", msg_len);
            free(sig);
            free(out);
            free(ct);
            free(msg);
            EVP_PKEY_free(key);
            return 1;
        }

        printf("rsa_oaep_encrypt msg_len=%-4zu : %.3f us/op, %.2f ops/s\n",
               msg_len, enc_result.us_per_op, enc_result.ops_per_sec);
        printf("rsa_oaep_decrypt msg_len=%-4zu : %.3f us/op, %.2f ops/s\n",
               msg_len, dec_result.us_per_op, dec_result.ops_per_sec);

        if (csv) {
            fprintf(csv, "rsa_oaep_encrypt,%d,%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%d,%d,%s,OAEP-SHA256\n",
                    bits, msg_len, samples, repeats, enc_result.us_per_op,
                    enc_result.ops_per_sec,
                    enc_result.ops_per_sec * (double)msg_len / 1024.0,
                    enc_result.cycles_per_op, pin_ok, RSA_WARMUP_OPS, provider);
            fprintf(csv, "rsa_oaep_decrypt,%d,%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%d,%d,%s,OAEP-SHA256\n",
                    bits, msg_len, samples, repeats, dec_result.us_per_op,
                    dec_result.ops_per_sec,
                    dec_result.ops_per_sec * (double)msg_len / 1024.0,
                    dec_result.cycles_per_op, pin_ok, RSA_WARMUP_OPS, provider);
        }
    }

    for (size_t i = 0; i < sizeof pss_lengths / sizeof pss_lengths[0]; i++) {
        const size_t msg_len = pss_lengths[i];
        unsigned char *pss_msg = (unsigned char*)rsa_xmalloc(msg_len ? msg_len : 1u);
        rsa_rand_bytes(pss_msg, msg_len);

        size_t sig_len = modulus_len;
        if (!rsa_pss_sign(key, pss_msg, msg_len, sig, &sig_len)) {
            fprintf(stderr, "RSA PSS setup sign failed (msg_len=%zu)\n", msg_len);
            free(pss_msg);
            free(sig);
            free(out);
            free(ct);
            free(msg);
            EVP_PKEY_free(key);
            return 1;
        }

        rsa_pss_sign_case_t sign_case = { key, pss_msg, msg_len, sig, modulus_len };
        rsa_pss_verify_case_t verify_case = { key, pss_msg, msg_len, sig, sig_len };

        rsa_perf_result_t sign_result;
        rsa_perf_result_t verify_result;
        if (!measure_operation(op_pss_sign, &sign_case, samples, repeats, &sign_result)) {
            fprintf(stderr, "RSA PSS sign benchmark failed (msg_len=%zu)\n", msg_len);
            free(pss_msg);
            free(sig);
            free(out);
            free(ct);
            free(msg);
            EVP_PKEY_free(key);
            return 1;
        }
        if (!measure_operation(op_pss_verify, &verify_case, samples, repeats, &verify_result)) {
            fprintf(stderr, "RSA PSS verify benchmark failed (msg_len=%zu)\n", msg_len);
            free(pss_msg);
            free(sig);
            free(out);
            free(ct);
            free(msg);
            EVP_PKEY_free(key);
            return 1;
        }

        printf("rsa_pss_sign    msg_len=%-4zu : %.3f us/op, %.2f ops/s\n",
               msg_len, sign_result.us_per_op, sign_result.ops_per_sec);
        printf("rsa_pss_verify  msg_len=%-4zu : %.3f us/op, %.2f ops/s\n",
               msg_len, verify_result.us_per_op, verify_result.ops_per_sec);

        if (csv) {
            fprintf(csv, "rsa_pss_sign,%d,%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%d,%d,%s,PSS-SHA256\n",
                    bits, msg_len, samples, repeats, sign_result.us_per_op,
                    sign_result.ops_per_sec,
                    sign_result.ops_per_sec * (double)msg_len / 1024.0,
                    sign_result.cycles_per_op, pin_ok, RSA_WARMUP_OPS, provider);
            fprintf(csv, "rsa_pss_verify,%d,%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%d,%d,%s,PSS-SHA256\n",
                    bits, msg_len, samples, repeats, verify_result.us_per_op,
                    verify_result.ops_per_sec,
                    verify_result.ops_per_sec * (double)msg_len / 1024.0,
                    verify_result.cycles_per_op, pin_ok, RSA_WARMUP_OPS, provider);
        }

        free(pss_msg);
    }

    free(sig);
    free(out);
    free(ct);
    free(msg);
    EVP_PKEY_free(key);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s latency|throughput [CSV_FILE] [RSA_BITS] [RSA_PROVIDER]\n", prog);
}

int main(int argc, char **argv)
{
    FILE *csv = NULL;
    int bits = 2048;
    const char *provider = "default";
    int throughput_mode = 0;

    if (argc < 2 || argc > 5) {
        usage(argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "latency") == 0) {
        throughput_mode = 0;
    } else if (strcmp(argv[1], "throughput") == 0) {
        throughput_mode = 1;
    } else {
        usage(argv[0]);
        return 1;
    }
    if (argc >= 3 && strcmp(argv[2], "-") != 0) {
        csv = fopen(argv[2], "w");
        if (!csv) {
            perror("fopen CSV");
            return 1;
        }
        printf("Saving CSV results to: %s\n", argv[2]);
    }
    if (argc >= 4 && !rsa_parse_int_arg(argv[3], &bits)) {
        fprintf(stderr, "Invalid RSA_BITS: %s\n", argv[3]);
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
    if (argc >= 5) {
        provider = argv[4];
    }

    rsa_seed_rng();

    rsa_provider_state_t provider_state;
    if (!rsa_init_provider(&provider_state, provider)) {
        if (csv) {
            fclose(csv);
        }
        return 1;
    }

    int rc = run_perf_mode(csv, bits, provider, throughput_mode);

    rsa_cleanup_provider(&provider_state);
    if (csv) {
        fclose(csv);
    }
    if (rsa_common_sink == 0xffu) {
        fprintf(stderr, "sink=%u\n", (unsigned)rsa_common_sink);
    }
    return rc;
}
