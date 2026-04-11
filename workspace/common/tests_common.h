#ifndef TESTS_COMMON_H
#define TESTS_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* z api.h bierzemy CRYPTO_* */
#include "api.h"
#include "crypto_aead.h"

/* narzędzia */
int hex2bin(const char *hex, unsigned char **out, size_t *outlen);
void *xmalloc(size_t n);
void rand_bytes(unsigned char *buf, size_t n);

/* globalny stan RNG można zostawić wewnątrz tests_common.c,
   na zewnątrz widoczne tylko rand_bytes() */

#endif /* TESTS_COMMON_H */
