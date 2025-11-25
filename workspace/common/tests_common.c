#include "tests_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ------------------------ narzędzia ------------------------ */

int hex2bin(const char *hex, unsigned char **out, size_t *outlen) {
    while (*hex && isspace((unsigned char)*hex)) hex++;
    if (*hex == '\0') { // pusty string
        *out = NULL; *outlen = 0; return 0;
    }
    size_t n = strlen(hex);
    while (n && isspace((unsigned char)hex[n-1])) n--;
    if (n % 2 != 0) return -1;

    *out = (unsigned char*)malloc(n/2);
    if (!*out) return -2;
    *outlen = n/2;

    for (size_t i=0;i<n;i+=2) {
        char buf[3] = {hex[i], hex[i+1], 0};
        char *end = NULL;
        unsigned long v = strtoul(buf, &end, 16);
        if (end != buf+2) {
            free(*out);
            *out = NULL;
            *outlen = 0;
            return -3;
        }
        (*out)[i/2] = (unsigned char)v;
    }
    return 0;
}

void* xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "OOM\n");
        exit(1);
    }
    return p;
}

/* prosty xorshift32 do deterministycznych testów */
static uint32_t rng_state = 0x12345678u;
static uint32_t xorshift32(void) {
    uint32_t x = rng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    rng_state = x; return x;
}

void rand_bytes(unsigned char *buf, size_t n) {
    for (size_t i=0;i<n;i++) buf[i] = (unsigned char)(xorshift32() & 0xFF);
}
