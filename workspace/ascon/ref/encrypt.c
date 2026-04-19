#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include "word.h"
#include <stdint.h>
#include <stddef.h>

static int ranges_overlap(const unsigned char* a, unsigned long long alen,
                          const unsigned char* b, unsigned long long blen) {
  if (alen == 0ULL || blen == 0ULL || a == NULL || b == NULL) {
    return 0;
  }

  const uintptr_t a_start = (uintptr_t)a;
  const uintptr_t b_start = (uintptr_t)b;

  if (alen > (unsigned long long)(UINTPTR_MAX - a_start) ||
      blen > (unsigned long long)(UINTPTR_MAX - b_start)) {
    return 1;
  }

  const uintptr_t a_end = a_start + (uintptr_t)alen;
  const uintptr_t b_end = b_start + (uintptr_t)blen;
  return (a_start < b_end && b_start < a_end) ? 1 : 0;
}

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;
  if (c == NULL || clen == NULL || npub == NULL || k == NULL) {
    return -1;
  }
  if (mlen > 0ULL && m == NULL) {
    return -1;
  }
  if (adlen > 0ULL && ad == NULL) {
    return -1;
  }

  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;
  if (*clen < mlen) {
    return -1;
  }
  if (ranges_overlap(c, *clen, m, mlen)) {
    return -1;
  }

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  state_t s;
  s.x0 = ASCON_128_IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("initialization", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
      s.x0 ^= LOADBYTES(ad, 8);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x0 ^= LOADBYTES(ad, adlen);
    s.x0 ^= PAD(adlen);
    P6(&s);
  }
  /* domain separation */
  s.x4 ^= 1;
  printstate("process associated data", &s);

  /* full plaintext blocks */
  while (mlen >= ASCON_128_RATE) {
    s.x0 ^= LOADBYTES(m, 8);
    STOREBYTES(c, s.x0, 8);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }
  /* final plaintext block */
  s.x0 ^= LOADBYTES(m, mlen);
  STOREBYTES(c, s.x0, mlen);
  s.x0 ^= PAD(mlen);
  c += mlen;
  printstate("process plaintext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization", &s);

  /* set tag */
  STOREBYTES(c, s.x3, 8);
  STOREBYTES(c + 8, s.x4, 8);

  return 0;
}
