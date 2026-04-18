#include "rsa_common.h"

#include <math.h>

enum {
    RSA_CT_DEFAULT_SAMPLES = 2000,
    RSA_CT_POOL_SIZE = 16
};

typedef struct {
    size_t n;
    double mean;
    double m2;
} rsa_t_stat_acc_t;

typedef struct {
    const char *operation;
    const char *class0_label;
    const char *class1_label;
    void *ctx;
    int (*prepare)(void *ctx, int cls, size_t sample_index);
    int (*op)(void *ctx, int cls, size_t sample_index);
} rsa_ct_case_t;

typedef struct {
    EVP_PKEY *key;
    size_t msg_len;
    unsigned char *zero_msg;
    unsigned char *random_msg;
    unsigned char *out;
    size_t out_cap;
} rsa_ct_encrypt_ctx_t;

typedef struct {
    EVP_PKEY *key;
    size_t msg_len;
    size_t ct_len;
    unsigned char *zero_ct_pool;
    unsigned char *random_ct_pool;
    unsigned char *out;
    size_t out_cap;
} rsa_ct_decrypt_ctx_t;

typedef struct {
    EVP_PKEY *key;
    size_t msg_len;
    unsigned char *zero_msg;
    unsigned char *random_msg;
    unsigned char *sig;
    size_t sig_cap;
} rsa_ct_sign_ctx_t;

typedef struct {
    EVP_PKEY *key;
    size_t msg_len;
    size_t sig_len;
    unsigned char *zero_msg_pool;
    unsigned char *random_msg_pool;
    unsigned char *zero_sig_pool;
    unsigned char *random_sig_pool;
} rsa_ct_verify_msg_ctx_t;

typedef struct {
    EVP_PKEY *key;
    size_t msg_len;
    size_t sig_len;
    unsigned char *msg;
    unsigned char *valid_sig_pool;
    unsigned char *invalid_sig_pool;
} rsa_ct_verify_valid_invalid_ctx_t;

static void t_stat_add(rsa_t_stat_acc_t *acc, double value)
{
    acc->n++;
    const double delta = value - acc->mean;
    acc->mean += delta / (double)acc->n;
    const double delta2 = value - acc->mean;
    acc->m2 += delta * delta2;
}

static double t_stat_variance(const rsa_t_stat_acc_t *acc)
{
    return acc->n > 1u ? acc->m2 / (double)(acc->n - 1u) : 0.0;
}

static double abs_double(double x)
{
    return x < 0.0 ? -x : x;
}

static int ct_prepare_encrypt(void *opaque, int cls, size_t sample_index)
{
    rsa_ct_encrypt_ctx_t *ctx = (rsa_ct_encrypt_ctx_t*)opaque;
    (void)sample_index;
    if (cls == 1) {
        rsa_rand_bytes(ctx->random_msg, ctx->msg_len);
    }
    return 1;
}

static int ct_op_encrypt(void *opaque, int cls, size_t sample_index)
{
    rsa_ct_encrypt_ctx_t *ctx = (rsa_ct_encrypt_ctx_t*)opaque;
    const unsigned char *msg = cls == 0 ? ctx->zero_msg : ctx->random_msg;
    size_t out_len = ctx->out_cap;
    (void)sample_index;
    int ok = rsa_oaep_encrypt(ctx->key, msg, ctx->msg_len, ctx->out, &out_len);
    if (ok && out_len > 0u) {
        rsa_common_sink ^= ctx->out[0];
    }
    return ok;
}

static int ct_prepare_sign(void *opaque, int cls, size_t sample_index)
{
    rsa_ct_sign_ctx_t *ctx = (rsa_ct_sign_ctx_t*)opaque;
    (void)sample_index;
    if (cls == 1) {
        rsa_rand_bytes(ctx->random_msg, ctx->msg_len);
    }
    return 1;
}

static int ct_op_sign(void *opaque, int cls, size_t sample_index)
{
    rsa_ct_sign_ctx_t *ctx = (rsa_ct_sign_ctx_t*)opaque;
    const unsigned char *msg = cls == 0 ? ctx->zero_msg : ctx->random_msg;
    size_t sig_len = ctx->sig_cap;
    (void)sample_index;
    int ok = rsa_pss_sign(ctx->key, msg, ctx->msg_len, ctx->sig, &sig_len);
    if (ok && sig_len > 0u) {
        rsa_common_sink ^= ctx->sig[0];
    }
    return ok;
}

static int ct_prepare_noop(void *opaque, int cls, size_t sample_index)
{
    (void)opaque;
    (void)cls;
    (void)sample_index;
    return 1;
}

static int ct_op_decrypt(void *opaque, int cls, size_t sample_index)
{
    rsa_ct_decrypt_ctx_t *ctx = (rsa_ct_decrypt_ctx_t*)opaque;
    const size_t pool_index = sample_index % (size_t)RSA_CT_POOL_SIZE;
    const unsigned char *pool = cls == 0 ? ctx->zero_ct_pool : ctx->random_ct_pool;
    const unsigned char *ct = pool + pool_index * ctx->ct_len;
    size_t out_len = ctx->out_cap;
    int ok = rsa_oaep_decrypt(ctx->key, ct, ctx->ct_len, ctx->out, &out_len);
    ok = ok && out_len == ctx->msg_len;
    if (ok && out_len > 0u) {
        rsa_common_sink ^= ctx->out[0];
    }
    return ok;
}

static int ct_op_verify_msg(void *opaque, int cls, size_t sample_index)
{
    rsa_ct_verify_msg_ctx_t *ctx = (rsa_ct_verify_msg_ctx_t*)opaque;
    const size_t pool_index = sample_index % (size_t)RSA_CT_POOL_SIZE;
    const unsigned char *msg_pool = cls == 0 ? ctx->zero_msg_pool : ctx->random_msg_pool;
    const unsigned char *sig_pool = cls == 0 ? ctx->zero_sig_pool : ctx->random_sig_pool;
    const unsigned char *msg = msg_pool + pool_index * ctx->msg_len;
    const unsigned char *sig = sig_pool + pool_index * ctx->sig_len;
    int ret = rsa_pss_verify(ctx->key, msg, ctx->msg_len, sig, ctx->sig_len);
    rsa_common_sink ^= (unsigned char)ret;
    return ret == 1;
}

static int ct_op_verify_valid_invalid(void *opaque, int cls, size_t sample_index)
{
    rsa_ct_verify_valid_invalid_ctx_t *ctx = (rsa_ct_verify_valid_invalid_ctx_t*)opaque;
    const size_t pool_index = sample_index % (size_t)RSA_CT_POOL_SIZE;
    const unsigned char *sig_pool = cls == 0 ? ctx->valid_sig_pool : ctx->invalid_sig_pool;
    const unsigned char *sig = sig_pool + pool_index * ctx->sig_len;
    int ret = rsa_pss_verify(ctx->key, ctx->msg, ctx->msg_len, sig, ctx->sig_len);
    rsa_common_sink ^= (unsigned char)ret;
    return cls == 0 ? (ret == 1) : (ret != 1);
}

static double ct_measure_once(rsa_ct_case_t *test_case, int cls, size_t sample_index, int *ok)
{
    if (!test_case->prepare(test_case->ctx, cls, sample_index)) {
        *ok = 0;
        return 0.0;
    }

#if RSA_HAVE_CYCLE_COUNTER
    const unsigned long long c0 = rsa_read_cycles();
    int ret = test_case->op(test_case->ctx, cls, sample_index);
    const unsigned long long c1 = rsa_read_cycles();
    *ok = ret;
    return (double)(c1 - c0);
#else
    const double t0 = rsa_timer_seconds();
    int ret = test_case->op(test_case->ctx, cls, sample_index);
    const double t1 = rsa_timer_seconds();
    *ok = ret;
    return (t1 - t0) * 1e9;
#endif
}

static int run_ct_case(FILE *csv,
                       rsa_ct_case_t *test_case,
                       int bits,
                       size_t msg_len,
                       size_t samples,
                       int strict,
                       const char *provider,
                       int *significant_count)
{
    rsa_t_stat_acc_t class0;
    rsa_t_stat_acc_t class1;
    memset(&class0, 0, sizeof class0);
    memset(&class1, 0, sizeof class1);

    for (size_t i = 0; i < RSA_WARMUP_OPS; i++) {
        int ok = 0;
        (void)ct_measure_once(test_case, 0, i, &ok);
        if (!ok) {
            fprintf(stderr, "CT warmup failed for %s\n", test_case->operation);
            return 1;
        }
        (void)ct_measure_once(test_case, 1, i, &ok);
        if (!ok) {
            fprintf(stderr, "CT warmup failed for %s\n", test_case->operation);
            return 1;
        }
    }

    for (size_t i = 0; i < samples; i++) {
        int ok = 0;
        int cls = (int)(rsa_xorshift32() & 1u);
        double value = ct_measure_once(test_case, cls, i, &ok);
        if (!ok) {
            fprintf(stderr, "CT measured operation failed for %s\n", test_case->operation);
            return 1;
        }

        if (cls == 0) {
            t_stat_add(&class0, value);
        } else {
            t_stat_add(&class1, value);
        }
    }

    const double var0 = t_stat_variance(&class0);
    const double var1 = t_stat_variance(&class1);
    const double denom = sqrt((var0 / (double)class0.n) + (var1 / (double)class1.n));
    const double t_stat = denom > 0.0 ? (class0.mean - class1.mean) / denom : 0.0;
    const double abs_t = abs_double(t_stat);
    const double threshold = 4.5;
    const int significant = abs_t >= threshold;
    const char *unit =
#if RSA_HAVE_CYCLE_COUNTER
        "cycles";
#else
        "ns";
#endif

    if (significant) {
        (*significant_count)++;
    }

    printf("ct-sanity %-31s n0=%-5zu n1=%-5zu mean0=%.2f mean1=%.2f t=%.2f %s\n",
           test_case->operation,
           class0.n,
           class1.n,
           class0.mean,
           class1.mean,
           t_stat,
           significant ? "SIGNIFICANT" : "ok");

    if (csv) {
        fprintf(csv,
                "%s,%d,%zu,%zu,%s,%s,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.1f,%s,%s,%s\n",
                test_case->operation,
                bits,
                msg_len,
                samples,
                test_case->class0_label,
                test_case->class1_label,
                class0.n,
                class1.n,
                class0.mean,
                class1.mean,
                t_stat,
                abs_t,
                threshold,
                significant ? "yes" : "no",
                unit,
                provider);
    }

    return strict && significant ? 2 : 0;
}

static int precompute_decrypt_pools(rsa_ct_decrypt_ctx_t *ctx)
{
    unsigned char *zero_msg = (unsigned char*)rsa_xmalloc(ctx->msg_len ? ctx->msg_len : 1u);
    unsigned char *random_msg = (unsigned char*)rsa_xmalloc(ctx->msg_len ? ctx->msg_len : 1u);
    memset(zero_msg, 0, ctx->msg_len);

    for (size_t i = 0; i < (size_t)RSA_CT_POOL_SIZE; i++) {
        size_t ct_len = ctx->ct_len;
        if (!rsa_oaep_encrypt(ctx->key, zero_msg, ctx->msg_len,
                              ctx->zero_ct_pool + i * ctx->ct_len, &ct_len)) {
            free(random_msg);
            free(zero_msg);
            return 0;
        }
        rsa_rand_bytes(random_msg, ctx->msg_len);
        ct_len = ctx->ct_len;
        if (!rsa_oaep_encrypt(ctx->key, random_msg, ctx->msg_len,
                              ctx->random_ct_pool + i * ctx->ct_len, &ct_len)) {
            free(random_msg);
            free(zero_msg);
            return 0;
        }
    }

    free(random_msg);
    free(zero_msg);
    return 1;
}

static int precompute_verify_msg_pools(rsa_ct_verify_msg_ctx_t *ctx)
{
    for (size_t i = 0; i < (size_t)RSA_CT_POOL_SIZE; i++) {
        unsigned char *zero_msg = ctx->zero_msg_pool + i * ctx->msg_len;
        unsigned char *random_msg = ctx->random_msg_pool + i * ctx->msg_len;
        unsigned char *zero_sig = ctx->zero_sig_pool + i * ctx->sig_len;
        unsigned char *random_sig = ctx->random_sig_pool + i * ctx->sig_len;
        memset(zero_msg, 0, ctx->msg_len);
        rsa_rand_bytes(random_msg, ctx->msg_len);

        size_t sig_len = ctx->sig_len;
        if (!rsa_pss_sign(ctx->key, zero_msg, ctx->msg_len, zero_sig, &sig_len)) {
            return 0;
        }
        if (sig_len != ctx->sig_len) {
            return 0;
        }

        sig_len = ctx->sig_len;
        if (!rsa_pss_sign(ctx->key, random_msg, ctx->msg_len, random_sig, &sig_len)) {
            return 0;
        }
        if (sig_len != ctx->sig_len) {
            return 0;
        }
    }

    return 1;
}

static int precompute_verify_valid_invalid_pools(rsa_ct_verify_valid_invalid_ctx_t *ctx)
{
    for (size_t i = 0; i < (size_t)RSA_CT_POOL_SIZE; i++) {
        unsigned char *valid_sig = ctx->valid_sig_pool + i * ctx->sig_len;
        unsigned char *invalid_sig = ctx->invalid_sig_pool + i * ctx->sig_len;
        size_t sig_len = ctx->sig_len;
        if (!rsa_pss_sign(ctx->key, ctx->msg, ctx->msg_len, valid_sig, &sig_len)) {
            return 0;
        }
        if (sig_len != ctx->sig_len) {
            return 0;
        }
        memcpy(invalid_sig, valid_sig, ctx->sig_len);
        invalid_sig[0] ^= 0x01u;
    }

    return 1;
}

static int run_ct_sanity(FILE *csv,
                         int bits,
                         const char *provider,
                         size_t samples,
                         int strict)
{
    printf("=== RSA constant-time sanity (%d-bit, provider=%s, samples=%zu) ===\n",
           bits, provider, samples);

    if (csv) {
        fprintf(csv,
                "operation,bits,msg_len,samples,class0,class1,n0,n1,mean0,mean1,t_stat,abs_t,threshold,significant,unit,provider\n");
    }

    int pin_ok = rsa_pin_to_single_core();
    rsa_print_stabilization_info(pin_ok);

    EVP_PKEY *key = rsa_generate_key(bits);
    if (!key) {
        return 1;
    }

    const size_t modulus_len = rsa_modulus_bytes_from_bits(bits);
    const size_t max_oaep = rsa_oaep_sha256_max_plaintext(bits);
    const size_t msg_len = max_oaep < 64u ? max_oaep : 64u;
    const size_t msg_alloc = msg_len ? msg_len : 1u;
    int significant_count = 0;
    int rc = 0;

    rsa_ct_encrypt_ctx_t enc_ctx;
    enc_ctx.key = key;
    enc_ctx.msg_len = msg_len;
    enc_ctx.zero_msg = (unsigned char*)rsa_xmalloc(msg_alloc);
    enc_ctx.random_msg = (unsigned char*)rsa_xmalloc(msg_alloc);
    enc_ctx.out = (unsigned char*)rsa_xmalloc(modulus_len);
    enc_ctx.out_cap = modulus_len;
    memset(enc_ctx.zero_msg, 0, msg_len);
    rsa_rand_bytes(enc_ctx.random_msg, msg_len);

    rsa_ct_decrypt_ctx_t dec_ctx;
    dec_ctx.key = key;
    dec_ctx.msg_len = msg_len;
    dec_ctx.ct_len = modulus_len;
    dec_ctx.zero_ct_pool = (unsigned char*)rsa_xmalloc((size_t)RSA_CT_POOL_SIZE * modulus_len);
    dec_ctx.random_ct_pool = (unsigned char*)rsa_xmalloc((size_t)RSA_CT_POOL_SIZE * modulus_len);
    dec_ctx.out = (unsigned char*)rsa_xmalloc(modulus_len);
    dec_ctx.out_cap = modulus_len;

    rsa_ct_sign_ctx_t sign_ctx;
    sign_ctx.key = key;
    sign_ctx.msg_len = msg_len;
    sign_ctx.zero_msg = (unsigned char*)rsa_xmalloc(msg_alloc);
    sign_ctx.random_msg = (unsigned char*)rsa_xmalloc(msg_alloc);
    sign_ctx.sig = (unsigned char*)rsa_xmalloc(modulus_len);
    sign_ctx.sig_cap = modulus_len;
    memset(sign_ctx.zero_msg, 0, msg_len);
    rsa_rand_bytes(sign_ctx.random_msg, msg_len);

    rsa_ct_verify_msg_ctx_t verify_msg_ctx;
    verify_msg_ctx.key = key;
    verify_msg_ctx.msg_len = msg_len;
    verify_msg_ctx.sig_len = modulus_len;
    verify_msg_ctx.zero_msg_pool = (unsigned char*)rsa_xmalloc((size_t)RSA_CT_POOL_SIZE * msg_alloc);
    verify_msg_ctx.random_msg_pool = (unsigned char*)rsa_xmalloc((size_t)RSA_CT_POOL_SIZE * msg_alloc);
    verify_msg_ctx.zero_sig_pool = (unsigned char*)rsa_xmalloc((size_t)RSA_CT_POOL_SIZE * modulus_len);
    verify_msg_ctx.random_sig_pool = (unsigned char*)rsa_xmalloc((size_t)RSA_CT_POOL_SIZE * modulus_len);

    rsa_ct_verify_valid_invalid_ctx_t verify_vi_ctx;
    verify_vi_ctx.key = key;
    verify_vi_ctx.msg_len = msg_len;
    verify_vi_ctx.sig_len = modulus_len;
    verify_vi_ctx.msg = (unsigned char*)rsa_xmalloc(msg_alloc);
    verify_vi_ctx.valid_sig_pool = (unsigned char*)rsa_xmalloc((size_t)RSA_CT_POOL_SIZE * modulus_len);
    verify_vi_ctx.invalid_sig_pool = (unsigned char*)rsa_xmalloc((size_t)RSA_CT_POOL_SIZE * modulus_len);
    rsa_rand_bytes(verify_vi_ctx.msg, msg_len);

    if (!precompute_decrypt_pools(&dec_ctx) ||
        !precompute_verify_msg_pools(&verify_msg_ctx) ||
        !precompute_verify_valid_invalid_pools(&verify_vi_ctx)) {
        fprintf(stderr, "RSA CT precomputation failed\n");
        rc = 1;
        goto done;
    }

    rsa_ct_case_t cases[] = {
        {
            "rsa_oaep_encrypt",
            "zero_plaintext",
            "random_plaintext",
            &enc_ctx,
            ct_prepare_encrypt,
            ct_op_encrypt
        },
        {
            "rsa_oaep_decrypt",
            "zero_plaintext_ciphertexts",
            "random_plaintext_ciphertexts",
            &dec_ctx,
            ct_prepare_noop,
            ct_op_decrypt
        },
        {
            "rsa_pss_sign",
            "zero_message",
            "random_message",
            &sign_ctx,
            ct_prepare_sign,
            ct_op_sign
        },
        {
            "rsa_pss_verify_message",
            "valid_zero_message",
            "valid_random_message",
            &verify_msg_ctx,
            ct_prepare_noop,
            ct_op_verify_msg
        },
        {
            "rsa_pss_verify_valid_invalid",
            "valid_signature",
            "invalid_signature",
            &verify_vi_ctx,
            ct_prepare_noop,
            ct_op_verify_valid_invalid
        }
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int case_rc = run_ct_case(csv, &cases[i], bits, msg_len, samples,
                                  strict, provider, &significant_count);
        if (case_rc != 0) {
            rc = case_rc;
            if (strict) {
                break;
            }
        }
    }

    printf("RSA ct-sanity significant findings: %d\n", significant_count);
    if (strict && significant_count > 0) {
        rc = 2;
    }

done:
    free(verify_vi_ctx.invalid_sig_pool);
    free(verify_vi_ctx.valid_sig_pool);
    free(verify_vi_ctx.msg);
    free(verify_msg_ctx.random_sig_pool);
    free(verify_msg_ctx.zero_sig_pool);
    free(verify_msg_ctx.random_msg_pool);
    free(verify_msg_ctx.zero_msg_pool);
    free(sign_ctx.sig);
    free(sign_ctx.random_msg);
    free(sign_ctx.zero_msg);
    free(dec_ctx.out);
    free(dec_ctx.random_ct_pool);
    free(dec_ctx.zero_ct_pool);
    free(enc_ctx.out);
    free(enc_ctx.random_msg);
    free(enc_ctx.zero_msg);
    EVP_PKEY_free(key);
    return rc;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [CSV_FILE] [RSA_BITS] [RSA_PROVIDER] [CT_SAMPLES] [strict]\n"
            "  RSA_BITS     2048 | 3072 | 4096 (default: 2048)\n"
            "  RSA_PROVIDER default | fips (default: default)\n"
            "  CT_SAMPLES   default: %d\n"
            "  strict       exit non-zero when |t| >= 4.5\n",
            prog,
            RSA_CT_DEFAULT_SAMPLES);
}

int main(int argc, char **argv)
{
    FILE *csv = NULL;
    int bits = 2048;
    const char *provider = "default";
    size_t samples = (size_t)RSA_CT_DEFAULT_SAMPLES;
    int strict = 0;

    if (argc > 6) {
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
    if (argc >= 5 && !rsa_parse_size_arg(argv[4], &samples)) {
        fprintf(stderr, "Invalid CT_SAMPLES: %s\n", argv[4]);
        if (csv) {
            fclose(csv);
        }
        return 1;
    }
    if (argc >= 6) {
        strict = strcmp(argv[5], "strict") == 0;
        if (!strict) {
            fprintf(stderr, "Invalid strict flag: %s\n", argv[5]);
            if (csv) {
                fclose(csv);
            }
            return 1;
        }
    }

    rsa_seed_rng();

    rsa_provider_state_t provider_state;
    if (!rsa_init_provider(&provider_state, provider)) {
        if (csv) {
            fclose(csv);
        }
        return 1;
    }

    int rc = run_ct_sanity(csv, bits, provider, samples, strict);

    rsa_cleanup_provider(&provider_state);
    if (csv) {
        fclose(csv);
    }
    if (rsa_common_sink == 0xffu) {
        fprintf(stderr, "sink=%u\n", (unsigned)rsa_common_sink);
    }
    return rc;
}
