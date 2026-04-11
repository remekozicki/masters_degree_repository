/*
GIFT-COFB
Prepared by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 23 Mar 2019
*/
#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "api.h"
#include "crypto_aead.h"
#define TAGBYTES   CRYPTO_ABYTES

#include "gift128.h"

typedef unsigned char block[16];
typedef unsigned char half_block[8];

static int constcmp(const unsigned char *a, const unsigned char *b, size_t length) {
    unsigned char diff = 0;
    for (size_t i = 0; i < length; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return (int)diff;
}

static int ranges_overlap(const unsigned char *a, unsigned long long alen,
                          const unsigned char *b, unsigned long long blen) {
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

/* ------------------------------------------------------------------------- */

static void padding(block d, const block s, unsigned no_of_bytes){
    unsigned i;
    block tmp;
    if(no_of_bytes==0){
        for(i=0; i<16; i++)
            tmp[i] = 0;
        tmp[0] = 0x80;
    }
    else if (no_of_bytes<16){
        for(i=0; i<no_of_bytes; i++)
            tmp[i] = s[i];
        tmp[no_of_bytes] = 0x80;
        for(i=no_of_bytes+1; i<16; i++)
            tmp[i] = 0;
    }
    else{
        for(i=0; i<16; i++)
            tmp[i] = s[i];
    }
    for(i=0; i<16; i++)
            d[i] = tmp[i];
}

/* ------------------------------------------------------------------------- */

static void xor_block(block d, const block s1, const block s2, unsigned no_of_bytes) {
    unsigned i;
    for (i=0; i<no_of_bytes; i++)
        d[i] = s1[i] ^ s2[i];
}

static void xor_topbar_block(block d, const block s1, const half_block s2) {
    unsigned i;
    block tmp;
    for (i=0; i<8; i++)
        tmp[i] = s1[i] ^ s2[i];
    for (i=8; i<16; i++)
        tmp[i] = s1[i];

    for(i=0; i<16; i++)
        d[i] = tmp[i];
}

/* ------------------------------------------------------------------------- */

static void double_half_block(half_block d, const half_block s) {
    unsigned i;
    half_block tmp;
    /*x^{64} + x^4 + x^3 + x + 1*/
    for (i=0; i<7; i++)
        tmp[i] = (s[i] << 1) | (s[i+1] >> 7);
    tmp[7] = (s[7] << 1) ^ ((s[0] >> 7) * 27);

    for(i=0; i<8; i++)
        d[i] = tmp[i];
}

static void triple_half_block(half_block d, const half_block s) {
    unsigned i;
    half_block tmp;
    double_half_block(tmp,s);
    for (i=0; i<8; i++)
        d[i] = s[i] ^ tmp[i];
}
/* ------------------------------------------------------------------------- */

static void G(block d, const block s){
    unsigned i;
    block tmp;
    /*Y[1],Y[2] -> Y[2],Y[1]<<<1*/
    for(i=0; i<8; i++){
        tmp[i] = s[8+i];
    }
    for(i=0; i<7; i++){
        tmp[i+8] = s[i]<<1 | s[i+1]>>7;
    }
    tmp[7+8] = s[7]<<1 | s[0]>>7;

    for(i=0; i<16; i++)
        d[i] = tmp[i];
}

static void pho1(block d, block Y, const block M, unsigned no_of_bytes) {
    block tmpM;
    G(Y,Y);
    padding(tmpM,M,no_of_bytes);
    xor_block(d,Y,tmpM,16);
}

static void pho(block Y, const block M, block X, block C, unsigned no_of_bytes) {
    xor_block(C,Y,M,no_of_bytes);
    pho1(X,Y,M,no_of_bytes);
}

static void phoprime(block Y, const block C, block X, block M, unsigned no_of_bytes) {
    xor_block(M,Y,C,no_of_bytes);
    pho1(X,Y,M,no_of_bytes);

}

/* ------------------------------------------------------------------------- */

static int cofb_crypt(unsigned char *out, const unsigned char *k, const unsigned char *n,
                     const unsigned char *a, unsigned alen,
                     const unsigned char *in, unsigned inlen, int encrypting) {

    unsigned i;
    unsigned emptyA, emptyM;

    if ( ! encrypting ) {
        if (inlen < TAGBYTES) return -1;
        inlen -= TAGBYTES;
    }

    if(alen==0)
        emptyA=1;
    else
        emptyA=0;

    if(inlen==0)
        emptyM=1;
    else
        emptyM=0;

    /*Mask-Gen*/
    block Y,input;
    half_block offset;
    /*nonce is 128-bit*/
    for(i=0;i<16;i++)
        input[i] = n[i];

    giftb128(input,k,Y);
    for(i=0;i<8;i++)
        offset[i] = Y[i];


        /*Process AD*/
        /*non-empty A*/
    /*full blocks*/
    while(alen>16){
        /* X[i] = (A[i] + G(Y[i-1])) + offset */
        pho1(input,Y,a,16);
        /* offset = 2*offset */
        double_half_block(offset,offset);
        xor_topbar_block(input, input, offset);
        /* Y[i] = E(X[i]) */
        giftb128(input, k, Y);

        a = a + 16;
        alen -= 16;
    }

    /* last block */
    /* full block: offset = 3*offset */
    /* partial block: offset = 3^2*offset */
    triple_half_block(offset,offset);
    if((alen%16!=0)||(emptyA)){
        triple_half_block(offset,offset);
    }

    if(emptyM){
        /* empty M: offset = 3^2*offset */
        triple_half_block(offset,offset);
        triple_half_block(offset,offset);
    }

    /* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
    pho1(input,Y,a,alen);

    xor_topbar_block(input, input, offset);
    /* Y[a] = E(X[a]) */
    giftb128(input, k, Y);


    /* Process M */
    /* full blocks */
    while (inlen>16){
        double_half_block(offset,offset);
        /* C[i] = Y[i+a-1] + M[i]*/
        /* X[i] = M[i] + G(Y[i+a-1]) + offset */
        if(encrypting){
            pho(Y,in,input,out,16);
        }
        else{
            phoprime(Y,in,input,out,16);
        }

        xor_topbar_block(input,input,offset);
        /* Y[i] = E(X[i+a]) */
        giftb128(input, k, Y);

        in = in + 16;
        out = out + 16;
        inlen -= 16;
    }

    if(!emptyM){
        /* full block: offset = 3*offset */
        /* empty data / partial block: offset = 3^2*offset */
        triple_half_block(offset,offset);
        if(inlen%16!=0){
            triple_half_block(offset,offset);
        }
        /* last block */
        /* C[m] = Y[m+a-1] + M[m]*/
        /* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
        if(encrypting){
            pho(Y,in,input,out,inlen);
            out += inlen;
        }
        else{
            phoprime(Y,in,input,out,inlen);
            in += inlen;
        }


        xor_topbar_block(input,input,offset);
        /* T = E(X[m+a]) */
        giftb128(input, k, Y);
    }

    if (encrypting) {
        memcpy(out, Y, TAGBYTES);
        return 0;
    } else
        return (constcmp(in, Y, TAGBYTES) ? -1 : 0);     /* Check for validity */
}

/* ------------------------------------------------------------------------- */

#define COFB_ENCRYPT 1
#define COFB_DECRYPT 0

void cofb_encrypt(unsigned char *c, const unsigned char *k, const unsigned char *n,
                 const unsigned char *a, unsigned abytes,
                 const unsigned char *p, unsigned pbytes) {
    cofb_crypt(c, k, n, a, abytes, p, pbytes, COFB_ENCRYPT);
}

/* ------------------------------------------------------------------------- */

int cofb_decrypt(unsigned char *p, const unsigned char *k, const unsigned char *n,
                const unsigned char *a, unsigned abytes,
                const unsigned char *c, unsigned cbytes) {
    return cofb_crypt(p, k, n, a, abytes, c, cbytes, COFB_DECRYPT);
}

/* ------------------------------------------------------------------------- */

int crypto_aead_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k
)
{
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
    if (mlen > (unsigned long long)UINT_MAX || adlen > (unsigned long long)UINT_MAX) {
        return -1;
    }
    *clen = mlen + TAGBYTES;
    if (*clen < mlen) {
        return -1;
    }
    if (ranges_overlap(c, *clen, m, mlen)) {
        return -1;
    }
    return cofb_crypt(c, k, npub, ad,
            (unsigned)adlen, m, (unsigned)mlen, COFB_ENCRYPT);
}

int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
    (void)nsec;
    if (mlen == NULL || c == NULL || npub == NULL || k == NULL) {
        return -1;
    }
    if (clen < TAGBYTES) {
        *mlen = 0;
        return -1;
    }
    if (adlen > 0ULL && ad == NULL) {
        *mlen = 0;
        return -1;
    }
    if (clen > (unsigned long long)UINT_MAX || adlen > (unsigned long long)UINT_MAX) {
        *mlen = 0;
        return -1;
    }
    *mlen = clen - TAGBYTES;
    if (*mlen > 0ULL && m == NULL) {
        *mlen = 0;
        return -1;
    }
    if (ranges_overlap(m, *mlen, c, clen)) {
        *mlen = 0;
        return -1;
    }
    return cofb_crypt(m, k, npub,
            ad, (unsigned)adlen, c, (unsigned)clen, COFB_DECRYPT);
}

