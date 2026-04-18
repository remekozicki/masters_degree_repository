#ifndef RSA_COMMON_H
#define RSA_COMMON_H

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__has_include)
#if !__has_include(<openssl/evp.h>)
#error "OpenSSL 3.x headers are required. Set RSA_OPENSSL_CFLAGS and RSA_OPENSSL_LIBS when running make."
#endif
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_MAJOR < 3
#error "OpenSSL 3.x is required for provider-based RSA tests."
#endif

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <sched.h>
#include <time.h>
#else
#include <time.h>
#endif

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#define RSA_HAVE_CYCLE_COUNTER 1
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#else
#define RSA_HAVE_CYCLE_COUNTER 0
#endif

enum {
    RSA_SHA256_BYTES = 32,
    RSA_WARMUP_OPS = 4
};

typedef struct {
    OSSL_PROVIDER *base;
    OSSL_PROVIDER *provider;
    const char *name;
    int fips_enabled;
} rsa_provider_state_t;

static volatile unsigned char rsa_common_sink = 0;
static uint32_t rsa_rng_state = 0x9E3779B9u;

static inline void *rsa_xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1u);
    if (!p) {
        fprintf(stderr, "OOM\n");
        exit(1);
    }
    return p;
}

static inline uint32_t rsa_xorshift32(void)
{
    uint32_t x = rsa_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    if (x == 0u) {
        x = 0x6D2B79F5u;
    }
    rsa_rng_state = x;
    return x;
}

static inline void rsa_seed_rng(void)
{
    uint64_t seed = (uint64_t)time(NULL);
    seed ^= ((uint64_t)clock() << 32);
    seed ^= (uint64_t)(uintptr_t)&seed;
    rsa_rng_state = (uint32_t)(seed ^ (seed >> 32));
    if (rsa_rng_state == 0u) {
        rsa_rng_state = 0xA341316Cu;
    }
}

static inline void rsa_rand_bytes(unsigned char *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        buf[i] = (unsigned char)(rsa_xorshift32() & 0xffu);
    }
}

static inline int rsa_parse_size_arg(const char *text, size_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }
    *out = (size_t)value;
    return 1;
}

static inline int rsa_parse_int_arg(const char *text, int *out)
{
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }
    *out = (int)value;
    return 1;
}

static inline int rsa_validate_bits(int bits)
{
    return bits == 2048 || bits == 3072 || bits == 4096;
}

static inline size_t rsa_modulus_bytes_from_bits(int bits)
{
    return (size_t)((bits + 7) / 8);
}

static inline size_t rsa_oaep_sha256_max_plaintext(int bits)
{
    const size_t modulus_bytes = rsa_modulus_bytes_from_bits(bits);
    const size_t overhead = 2u * (size_t)RSA_SHA256_BYTES + 2u;
    return (modulus_bytes > overhead) ? (modulus_bytes - overhead) : 0u;
}

static inline double rsa_average_double(const double *values, size_t count)
{
    double sum = 0.0;
    for (size_t i = 0; i < count; i++) {
        sum += values[i];
    }
    return count ? (sum / (double)count) : 0.0;
}

static inline unsigned long long rsa_read_cycles(void)
{
#if RSA_HAVE_CYCLE_COUNTER
    return __rdtsc();
#else
    return 0ULL;
#endif
}

static inline double rsa_timer_seconds(void)
{
#if defined(_WIN32)
    LARGE_INTEGER freq;
    LARGE_INTEGER counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
#endif
}

static inline int rsa_pin_to_single_core(void)
{
#if defined(_WIN32)
    HANDLE thread = GetCurrentThread();
    DWORD_PTR previous = SetThreadAffinityMask(thread, (DWORD_PTR)1);
    return previous != 0;
#elif defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    return sched_setaffinity(0, sizeof(set), &set) == 0;
#else
    return 0;
#endif
}

static inline void rsa_print_stabilization_info(int pin_ok)
{
    printf("Stabilization:\n");
    printf("  - core pinning: %s\n", pin_ok ? "enabled (core 0)" : "not available");
    printf("  - cache warmup: enabled\n");
    printf("  - cpu governor/turbo: not modified by this tool (set manually)\n");
}

static inline void rsa_print_openssl_errors(const char *where)
{
    fprintf(stderr, "OpenSSL error at %s\n", where);
    ERR_print_errors_fp(stderr);
}

static inline int rsa_init_provider(rsa_provider_state_t *state, const char *provider_name)
{
    memset(state, 0, sizeof *state);
    if (!provider_name || provider_name[0] == '\0') {
        provider_name = "default";
    }
    state->name = provider_name;

    if (strcmp(provider_name, "fips") == 0) {
        state->base = OSSL_PROVIDER_load(NULL, "base");
        state->provider = OSSL_PROVIDER_load(NULL, "fips");
        if (!state->base || !state->provider) {
            rsa_print_openssl_errors("OSSL_PROVIDER_load(fips/base)");
            return 0;
        }
        if (!EVP_default_properties_enable_fips(NULL, 1)) {
            rsa_print_openssl_errors("EVP_default_properties_enable_fips");
            return 0;
        }
        state->fips_enabled = 1;
        return 1;
    }

    if (strcmp(provider_name, "default") == 0) {
        state->provider = OSSL_PROVIDER_load(NULL, "default");
        if (!state->provider) {
            rsa_print_openssl_errors("OSSL_PROVIDER_load(default)");
            return 0;
        }
        return 1;
    }

    fprintf(stderr, "Unsupported RSA_PROVIDER='%s'; expected 'default' or 'fips'\n", provider_name);
    return 0;
}

static inline void rsa_cleanup_provider(rsa_provider_state_t *state)
{
    if (state->fips_enabled) {
        (void)EVP_default_properties_enable_fips(NULL, 0);
    }
    if (state->provider) {
        OSSL_PROVIDER_unload(state->provider);
    }
    if (state->base) {
        OSSL_PROVIDER_unload(state->base);
    }
}

static inline EVP_PKEY *rsa_generate_key(int bits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *key = NULL;
    BIGNUM *pubexp = NULL;

    if (!ctx) {
        rsa_print_openssl_errors("EVP_PKEY_CTX_new_from_name(RSA)");
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        rsa_print_openssl_errors("EVP_PKEY_keygen_init");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        rsa_print_openssl_errors("EVP_PKEY_CTX_set_rsa_keygen_bits");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    pubexp = BN_new();
    if (!pubexp || !BN_set_word(pubexp, RSA_F4)) {
        rsa_print_openssl_errors("BN_set_word(RSA_F4)");
        BN_free(pubexp);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, pubexp) <= 0) {
        rsa_print_openssl_errors("EVP_PKEY_CTX_set1_rsa_keygen_pubexp");
        BN_free(pubexp);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    BN_free(pubexp);
    if (EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, 2) <= 0) {
        rsa_print_openssl_errors("EVP_PKEY_CTX_set_rsa_keygen_primes");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_generate(ctx, &key) <= 0) {
        rsa_print_openssl_errors("EVP_PKEY_generate");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

static inline int rsa_setup_oaep_sha256(EVP_PKEY_CTX *ctx)
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        return 0;
    }
    return 1;
}

static inline int rsa_oaep_encrypt(EVP_PKEY *key,
                                   const unsigned char *msg,
                                   size_t msg_len,
                                   unsigned char *out,
                                   size_t *out_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    int ok = 0;
    size_t len = *out_len;

    if (!ctx) {
        return 0;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        goto done;
    }
    if (!rsa_setup_oaep_sha256(ctx)) {
        goto done;
    }
    if (EVP_PKEY_encrypt(ctx, out, &len, msg, msg_len) <= 0) {
        goto done;
    }

    *out_len = len;
    ok = 1;

done:
    if (!ok) {
        ERR_clear_error();
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static inline int rsa_oaep_decrypt(EVP_PKEY *key,
                                   const unsigned char *ct,
                                   size_t ct_len,
                                   unsigned char *out,
                                   size_t *out_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    int ok = 0;
    size_t len = *out_len;

    if (!ctx) {
        return 0;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        goto done;
    }
    if (!rsa_setup_oaep_sha256(ctx)) {
        goto done;
    }
    if (EVP_PKEY_decrypt(ctx, out, &len, ct, ct_len) <= 0) {
        goto done;
    }

    *out_len = len;
    ok = 1;

done:
    if (!ok) {
        ERR_clear_error();
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static inline int rsa_setup_pss_sha256(EVP_PKEY_CTX *ctx)
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        return 0;
    }
    return 1;
}

static inline int rsa_pss_sign(EVP_PKEY *key,
                               const unsigned char *msg,
                               size_t msg_len,
                               unsigned char *sig,
                               size_t *sig_len)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;
    size_t len = *sig_len;

    if (!mdctx) {
        return 0;
    }
    if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, key) <= 0) {
        goto done;
    }
    if (!rsa_setup_pss_sha256(pctx)) {
        goto done;
    }
    if (EVP_DigestSignUpdate(mdctx, msg, msg_len) <= 0) {
        goto done;
    }
    if (EVP_DigestSignFinal(mdctx, NULL, &len) <= 0) {
        goto done;
    }
    if (len > *sig_len) {
        goto done;
    }
    if (EVP_DigestSignFinal(mdctx, sig, &len) <= 0) {
        goto done;
    }

    *sig_len = len;
    ok = 1;

done:
    if (!ok) {
        ERR_clear_error();
    }
    EVP_MD_CTX_free(mdctx);
    return ok;
}

static inline int rsa_pss_verify(EVP_PKEY *key,
                                 const unsigned char *msg,
                                 size_t msg_len,
                                 const unsigned char *sig,
                                 size_t sig_len)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ret = -1;

    if (!mdctx) {
        return -1;
    }
    if (EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, key) <= 0) {
        goto done;
    }
    if (!rsa_setup_pss_sha256(pctx)) {
        goto done;
    }
    if (EVP_DigestVerifyUpdate(mdctx, msg, msg_len) <= 0) {
        goto done;
    }
    ret = EVP_DigestVerifyFinal(mdctx, sig, sig_len);

done:
    if (ret != 1) {
        ERR_clear_error();
    }
    EVP_MD_CTX_free(mdctx);
    if (ret == 1) {
        return 1;
    }
    if (ret == 0) {
        return 0;
    }
    return -1;
}

#endif
