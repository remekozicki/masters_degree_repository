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

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;
  if (mlen == NULL || c == NULL || npub == NULL || k == NULL) return -1;
  if (clen < CRYPTO_ABYTES) {
    *mlen = 0;
    return -1;
  }
  if (adlen > 0ULL && ad == NULL) {
    *mlen = 0;
    return -1;
  }

  /* set plaintext size */
  *mlen = clen - CRYPTO_ABYTES;
  if (*mlen > 0ULL && m == NULL) {
    *mlen = 0;
    return -1;
  }
  if (ranges_overlap(m, *mlen, c, clen)) {
    *mlen = 0;
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

  /* full ciphertext blocks */
  clen -= CRYPTO_ABYTES;
  while (clen >= ASCON_128_RATE) {
    uint64_t c0 = LOADBYTES(c, 8);
    STOREBYTES(m, s.x0 ^ c0, 8);
    s.x0 = c0;
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    clen -= ASCON_128_RATE;
  }
  /* final ciphertext block */
  uint64_t c0 = LOADBYTES(c, clen);
  STOREBYTES(m, s.x0 ^ c0, clen);
  s.x0 = CLEARBYTES(s.x0, clen);
  s.x0 |= c0;
  s.x0 ^= PAD(clen);
  c += clen;
  printstate("process ciphertext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization", &s);

  /* set tag */
  uint8_t t[16];
  STOREBYTES(t, s.x3, 8);
  STOREBYTES(t + 8, s.x4, 8);

  /* verify tag (should be constant time, check compiler output) */
  int result = 0;
  for (int i = 0; i < CRYPTO_ABYTES; ++i) result |= c[i] ^ t[i];
  result = (((result - 1) >> 8) & 1) - 1;

  return result;
}
