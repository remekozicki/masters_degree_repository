#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "crypto_aead.h"

static const size_t test_lengths[] = {
    0u, 1u, 2u, 15u, 16u, 17u, 31u, 32u, 33u,
    64u, 256u, 1024u, 4096u, 16384u, 65536u
};

enum {
    MAX_TEST_LENGTH = 65536u,
    MAX_CT_LENGTH = MAX_TEST_LENGTH + CRYPTO_ABYTES
};

typedef struct {
    size_t malloc_calls;
    size_t calloc_calls;
    size_t realloc_calls;
    size_t free_calls;
} alloc_counters_t;

typedef struct {
    size_t stack_peak_bytes;
    alloc_counters_t alloc;
} measurement_t;

typedef struct {
    size_t max_encrypt_stack_bytes;
    size_t max_encrypt_len;
    size_t max_decrypt_stack_bytes;
    size_t max_decrypt_len;
    alloc_counters_t total_alloc;
} summary_t;

static unsigned char g_key[CRYPTO_KEYBYTES];
static unsigned char g_npub[CRYPTO_NPUBBYTES];
static unsigned char g_msg[MAX_TEST_LENGTH ? MAX_TEST_LENGTH : 1u];
static unsigned char g_ad[MAX_TEST_LENGTH ? MAX_TEST_LENGTH : 1u];
static unsigned char g_ct[MAX_CT_LENGTH ? MAX_CT_LENGTH : 1u];
static unsigned char g_dec[MAX_TEST_LENGTH ? MAX_TEST_LENGTH : 1u];

static volatile int g_stack_tracking = 0;
static volatile int g_alloc_tracking = 0;
static uintptr_t g_stack_base = 0u;
static uintptr_t g_stack_min = 0u;
static alloc_counters_t g_alloc_counters;

static void fill_buffer(unsigned char *buf, size_t len, unsigned char seed)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char)(seed + (unsigned char)(31u * i));
    }
}

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
#endif
static uintptr_t frame_address_current(void) __attribute__((no_instrument_function));
static uintptr_t frame_address_current(void)
{
    void *frame = __builtin_frame_address(0);
    return (frame != NULL) ? (uintptr_t)frame : 0u;
}

static uintptr_t frame_address_caller(void) __attribute__((no_instrument_function));
static uintptr_t frame_address_caller(void)
{
    void *frame = __builtin_frame_address(1);
    return (frame != NULL) ? (uintptr_t)frame : 0u;
}
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

void __cyg_profile_func_enter(void *this_fn, void *call_site)
    __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *this_fn, void *call_site)
    __attribute__((no_instrument_function));

void __cyg_profile_func_enter(void *this_fn, void *call_site)
{
    (void)this_fn;
    (void)call_site;

    if (!g_stack_tracking) {
        return;
    }

    uintptr_t frame = frame_address_caller();
    if (frame == 0u) {
        frame = frame_address_current();
    }

    if (frame != 0u && frame < g_stack_min) {
        g_stack_min = frame;
    }
}

void __cyg_profile_func_exit(void *this_fn, void *call_site)
{
    (void)this_fn;
    (void)call_site;
}

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *ptr, size_t size);
void __real_free(void *ptr);

void *__wrap_malloc(size_t size) __attribute__((no_instrument_function));
void *__wrap_malloc(size_t size)
{
    if (g_alloc_tracking) {
        g_alloc_counters.malloc_calls++;
    }
    return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size) __attribute__((no_instrument_function));
void *__wrap_calloc(size_t count, size_t size)
{
    if (g_alloc_tracking) {
        g_alloc_counters.calloc_calls++;
    }
    return __real_calloc(count, size);
}

void *__wrap_realloc(void *ptr, size_t size) __attribute__((no_instrument_function));
void *__wrap_realloc(void *ptr, size_t size)
{
    if (g_alloc_tracking) {
        g_alloc_counters.realloc_calls++;
    }
    return __real_realloc(ptr, size);
}

void __wrap_free(void *ptr) __attribute__((no_instrument_function));
void __wrap_free(void *ptr)
{
    if (g_alloc_tracking) {
        g_alloc_counters.free_calls++;
    }
    __real_free(ptr);
}

static void measurement_begin(void) __attribute__((no_instrument_function));
static void measurement_begin(void)
{
    memset(&g_alloc_counters, 0, sizeof g_alloc_counters);
    g_stack_base = frame_address_caller();
    if (g_stack_base == 0u) {
        g_stack_base = frame_address_current();
    }
    g_stack_min = g_stack_base;
    g_alloc_tracking = 1;
    g_stack_tracking = 1;
}

static void measurement_end(measurement_t *measurement)
    __attribute__((no_instrument_function));
static void measurement_end(measurement_t *measurement)
{
    g_stack_tracking = 0;
    g_alloc_tracking = 0;

    measurement->stack_peak_bytes = (g_stack_base > g_stack_min)
        ? (size_t)(g_stack_base - g_stack_min)
        : 0u;
    measurement->alloc = g_alloc_counters;
}

static size_t alloc_total(const alloc_counters_t *alloc)
{
    return alloc->malloc_calls + alloc->calloc_calls +
           alloc->realloc_calls + alloc->free_calls;
}

static void add_alloc(alloc_counters_t *dst, const alloc_counters_t *src)
{
    dst->malloc_calls += src->malloc_calls;
    dst->calloc_calls += src->calloc_calls;
    dst->realloc_calls += src->realloc_calls;
    dst->free_calls += src->free_calls;
}

static void write_csv_row(FILE *csv, const char *operation,
                          size_t mlen, size_t adlen,
                          const measurement_t *measurement)
{
    if (!csv) {
        return;
    }

    fprintf(csv, "%s,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%s\n",
            operation,
            mlen,
            adlen,
            measurement->stack_peak_bytes,
            measurement->alloc.malloc_calls,
            measurement->alloc.calloc_calls,
            measurement->alloc.realloc_calls,
            measurement->alloc.free_calls,
            alloc_total(&measurement->alloc) == 0u ? "no" : "yes");
}

static int run_case(FILE *csv, summary_t *summary, size_t len)
{
    const size_t mlen = len;
    const size_t adlen = len;

    fill_buffer(g_key, sizeof g_key, (unsigned char)(0x10u + (len & 0xFFu)));
    fill_buffer(g_npub, sizeof g_npub, (unsigned char)(0x40u + (len & 0xFFu)));
    fill_buffer(g_msg, mlen, (unsigned char)(0x70u + (len & 0xFFu)));
    fill_buffer(g_ad, adlen, (unsigned char)(0xA0u + (len & 0xFFu)));
    memset(g_ct, 0, mlen + CRYPTO_ABYTES);
    memset(g_dec, 0, mlen ? mlen : 1u);

    measurement_t encrypt_measurement;
    measurement_begin();
    unsigned long long clen = 0u;
    int enc_ret = crypto_aead_encrypt(g_ct, &clen,
                                      g_msg, (unsigned long long)mlen,
                                      g_ad, (unsigned long long)adlen,
                                      NULL, g_npub, g_key);
    measurement_end(&encrypt_measurement);

    if (enc_ret != 0 || clen != (unsigned long long)(mlen + CRYPTO_ABYTES)) {
        fprintf(stderr, "encrypt failed for len=%zu (ret=%d, clen=%llu)\n",
                len, enc_ret, clen);
        return 1;
    }

    write_csv_row(csv, "encrypt", mlen, adlen, &encrypt_measurement);
    add_alloc(&summary->total_alloc, &encrypt_measurement.alloc);
    if (encrypt_measurement.stack_peak_bytes > summary->max_encrypt_stack_bytes) {
        summary->max_encrypt_stack_bytes = encrypt_measurement.stack_peak_bytes;
        summary->max_encrypt_len = len;
    }

    measurement_t decrypt_measurement;
    measurement_begin();
    unsigned long long out_mlen = 0u;
    int dec_ret = crypto_aead_decrypt(g_dec, &out_mlen, NULL,
                                      g_ct, clen,
                                      g_ad, (unsigned long long)adlen,
                                      g_npub, g_key);
    measurement_end(&decrypt_measurement);

    if (dec_ret != 0 || out_mlen != (unsigned long long)mlen ||
        (mlen > 0u && memcmp(g_msg, g_dec, mlen) != 0)) {
        fprintf(stderr, "decrypt failed for len=%zu (ret=%d, mlen=%llu)\n",
                len, dec_ret, out_mlen);
        return 1;
    }

    write_csv_row(csv, "decrypt", mlen, adlen, &decrypt_measurement);
    add_alloc(&summary->total_alloc, &decrypt_measurement.alloc);
    if (decrypt_measurement.stack_peak_bytes > summary->max_decrypt_stack_bytes) {
        summary->max_decrypt_stack_bytes = decrypt_measurement.stack_peak_bytes;
        summary->max_decrypt_len = len;
    }

    return 0;
}

static int run_runtime(FILE *csv)
{
    summary_t summary;
    memset(&summary, 0, sizeof summary);

    if (csv) {
        fprintf(csv,
                "operation,msg_len,ad_len,stack_peak_bytes,malloc_calls,calloc_calls,"
                "realloc_calls,free_calls,alloc_present\n");
    }

    const size_t count = sizeof test_lengths / sizeof test_lengths[0];
    for (size_t i = 0; i < count; i++) {
        if (run_case(csv, &summary, test_lengths[i]) != 0) {
            return 1;
        }
    }

    printf("\nLightweight runtime summary:\n");
    printf("+----------------------------+-------------+\n");
    printf("| Max encrypt stack [B]      | %11zu |\n", summary.max_encrypt_stack_bytes);
    printf("| Encrypt peak length [B]    | %11zu |\n", summary.max_encrypt_len);
    printf("| Max decrypt stack [B]      | %11zu |\n", summary.max_decrypt_stack_bytes);
    printf("| Decrypt peak length [B]    | %11zu |\n", summary.max_decrypt_len);
    printf("| malloc calls               | %11zu |\n", summary.total_alloc.malloc_calls);
    printf("| calloc calls               | %11zu |\n", summary.total_alloc.calloc_calls);
    printf("| realloc calls              | %11zu |\n", summary.total_alloc.realloc_calls);
    printf("| free calls                 | %11zu |\n", summary.total_alloc.free_calls);
    printf("+----------------------------+-------------+\n\n");

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

    int rc = run_runtime(csv);

    if (csv) {
        fclose(csv);
    }

    return rc;
}
