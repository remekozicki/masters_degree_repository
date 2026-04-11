#include "tests_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* ------------------------ utilities ------------------------ */

int hex2bin(const char *hex, unsigned char **out, size_t *outlen) {
    while (*hex && isspace((unsigned char)*hex)) hex++;
    if (*hex == '\0') {
        *out = NULL;
        *outlen = 0;
        return 0;
    }

    size_t n = strlen(hex);
    while (n && isspace((unsigned char)hex[n - 1])) n--;
    if ((n % 2u) != 0u) return -1;

    *out = (unsigned char*)malloc(n / 2u);
    if (!*out) return -2;
    *outlen = n / 2u;

    for (size_t i = 0; i < n; i += 2u) {
        char buf[3] = {hex[i], hex[i + 1], 0};
        char *end = NULL;
        unsigned long v = strtoul(buf, &end, 16);
        if (end != buf + 2) {
            free(*out);
            *out = NULL;
            *outlen = 0;
            return -3;
        }
        (*out)[i / 2u] = (unsigned char)v;
    }

    return 0;
}

void* xmalloc(size_t n) {
    void *p = malloc(n ? n : 1u);
    if (!p) {
        fprintf(stderr, "OOM\n");
        exit(1);
    }
    return p;
}

/* xorshift32 seeded once per process */
static uint32_t rng_state = 0u;
static int rng_seeded = 0;

static void seed_rng(void) {
    uint64_t seed = (uint64_t)time(NULL);
    seed ^= ((uint64_t)clock() << 32);
    seed ^= (uint64_t)(uintptr_t)&seed;

    uint32_t folded = (uint32_t)(seed ^ (seed >> 32));
    if (folded == 0u) {
        folded = 0xA341316Cu;
    }

    rng_state = folded;
    rng_seeded = 1;
}

static uint32_t xorshift32(void) {
    if (!rng_seeded) {
        seed_rng();
    }

    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    if (x == 0u) {
        x = 0x6D2B79F5u;
    }

    rng_state = x;
    return x;
}

void rand_bytes(unsigned char *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = (unsigned char)(xorshift32() & 0xFFu);
    }
}
