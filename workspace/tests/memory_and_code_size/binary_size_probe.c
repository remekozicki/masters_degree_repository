#include <stdint.h>
#include <stddef.h>

#include "api.h"
#include "crypto_aead.h"

static volatile unsigned long long probe_sink = 0u;

int main(void)
{
    unsigned char key[CRYPTO_KEYBYTES] = {0};
    unsigned char npub[CRYPTO_NPUBBYTES] = {0};
    unsigned char msg[1] = {0};
    unsigned char ad[1] = {0};
    unsigned char ct[1 + CRYPTO_ABYTES] = {0};
    unsigned char dec[1] = {0};

    unsigned long long clen = 0u;
    unsigned long long mlen = 0u;

    int enc_ret = crypto_aead_encrypt(ct, &clen, msg, 0u, ad, 0u, NULL, npub, key);
    int dec_ret = crypto_aead_decrypt(dec, &mlen, NULL, ct, clen, ad, 0u, npub, key);

    probe_sink = (unsigned long long)enc_ret +
                 (unsigned long long)dec_ret +
                 clen + mlen + ct[0] + dec[0];

    return probe_sink != 0u;
}
