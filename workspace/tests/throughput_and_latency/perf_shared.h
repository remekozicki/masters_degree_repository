#ifndef PERF_SHARED_H
#define PERF_SHARED_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <sched.h>
#include <time.h>
#else
#include <time.h>
#endif

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#define HAVE_CYCLE_COUNTER 1
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#else
#define HAVE_CYCLE_COUNTER 0
#endif

#include "../../common/tests_common.h"

static inline double perf_average(const double *values, size_t count)
{
    double sum = 0.0;
    for (size_t i = 0; i < count; i++) {
        sum += values[i];
    }
    return (count == 0u) ? 0.0 : (sum / (double)count);
}

static inline unsigned long long perf_read_cycles(void)
{
#if HAVE_CYCLE_COUNTER
    return __rdtsc();
#else
    return 0ULL;
#endif
}

static inline double perf_timer_seconds(void)
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

static inline int perf_pin_to_single_core(void)
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

static inline void perf_bump_nonce(unsigned char *npub, size_t npub_len)
{
    for (size_t i = 0; i < npub_len; i++) {
        npub[i] = (unsigned char)(npub[i] + 1u);
        if (npub[i] != 0u) {
            break;
        }
    }
}

static inline int perf_one_shot_encrypt_decrypt_ok(const unsigned char *msg, size_t mlen,
                                                   const unsigned char *ad, size_t adlen,
                                                   const unsigned char *key,
                                                   const unsigned char *npub,
                                                   unsigned char *ct,
                                                   unsigned char *dec)
{
    unsigned long long clen = (unsigned long long)(mlen + CRYPTO_ABYTES);
    int enc_ret = crypto_aead_encrypt(ct, &clen,
                                      msg, (unsigned long long)mlen,
                                      ad, (unsigned long long)adlen,
                                      NULL, npub, key);
    if (enc_ret != 0 || clen != (unsigned long long)(mlen + CRYPTO_ABYTES)) {
        return 0;
    }

    unsigned long long out_mlen = 0;
    int dec_ret = crypto_aead_decrypt(dec, &out_mlen, NULL,
                                      ct, clen,
                                      ad, (unsigned long long)adlen,
                                      npub, key);
    if (dec_ret != 0 || out_mlen != (unsigned long long)mlen) {
        return 0;
    }
    if (mlen > 0u && memcmp(msg, dec, mlen) != 0) {
        return 0;
    }
    return 1;
}

static inline int perf_warmup_encrypt(const unsigned char *msg, size_t mlen,
                                      const unsigned char *ad, size_t adlen,
                                      const unsigned char *key,
                                      unsigned char *npub,
                                      unsigned char *ct,
                                      size_t ops)
{
    unsigned long long expected = (unsigned long long)(mlen + CRYPTO_ABYTES);
    for (size_t i = 0; i < ops; i++) {
        unsigned long long clen = expected;
        int ret = crypto_aead_encrypt(ct, &clen,
                                      msg, (unsigned long long)mlen,
                                      ad, (unsigned long long)adlen,
                                      NULL, npub, key);
        if (ret != 0 || clen != expected) {
            return 0;
        }
        perf_bump_nonce(npub, CRYPTO_NPUBBYTES);
    }
    return 1;
}

static inline int perf_warmup_decrypt(const unsigned char *ct, unsigned long long clen,
                                      const unsigned char *ad, size_t adlen,
                                      const unsigned char *key,
                                      const unsigned char *npub,
                                      unsigned char *dec,
                                      size_t ops)
{
    for (size_t i = 0; i < ops; i++) {
        unsigned long long out_mlen = 0;
        int ret = crypto_aead_decrypt(dec, &out_mlen, NULL,
                                      ct, clen,
                                      ad, (unsigned long long)adlen,
                                      npub, key);
        if (ret != 0) {
            return 0;
        }
    }
    return 1;
}

static inline void perf_print_stabilization_info(int pin_ok)
{
    printf("Stabilization:\n");
    printf("  - core pinning: %s\n", pin_ok ? "enabled (core 0)" : "not available");
    printf("  - cache warmup: enabled\n");
    printf("  - cpu governor/turbo: not modified by this tool (set manually)\n");
}

#endif /* PERF_SHARED_H */
