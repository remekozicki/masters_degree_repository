#ifndef TESTS_COMMON_H
#define TESTS_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* From api.h we take CRYPTO_* constants. */
#include "api.h"
#include "crypto_aead.h"

/* Test utilities. */
int hex2bin(const char *hex, unsigned char **out, size_t *outlen);
void *xmalloc(size_t n);
void rand_bytes(unsigned char *buf, size_t n);

/* Keep RNG state private inside tests_common.c.
   Only rand_bytes() is exposed externally. */

#endif /* TESTS_COMMON_H */
