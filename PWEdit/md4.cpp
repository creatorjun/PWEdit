/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

 /**
    @file md4.c
    MD4 Support
 */

#ifdef LTC_MD4

const hash_descriptor_t md4_desc =
{
    "md4",
    5,
    20,
    64,

    /* OID */
   { 1, 2, 840, 113549, 2, 4,  },
   6,

    &md4_init,
    &md4_process,
    &md4_done,
    &md4_test,
    NULL
};

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define G(x,y,z) ((x & y) | (x & z) | (y & z))
#define H(x,y,z) (x^y^z)

#define R(a,b,c,d,k,s) a = ROL(a + F(b,c,d) + k, s);
#define S(a,b,c,d,k,s) a = ROL(a + G(b,c,d) + k + 0x5a827999UL, s);
#define T(a,b,c,d,k,s) a = ROL(a + H(b,c,d) + k + 0x6ed9eba1UL, s);

static int md4_compress(hash_state* md, const unsigned char* in)
{
    ulong32 a, b, c, d, X[16];
    int i;

    /* copy the state into 512-bits of internal RAM */
    for (i = 0; i < 16; i++) {
        LOAD32L(X[i], in + (4 * i));
    }

    a = md->md4.A;
    b = md->md4.B;
    c = md->md4.C;
    d = md->md4.D;

    R(a, b, c, d, X[0], 3);
    R(d, a, b, c, X[1], 7);
    R(c, d, a, b, X[2], 11);
    R(b, c, d, a, X[3], 19);
    R(a, b, c, d, X[4], 3);
    R(d, a, b, c, X[5], 7);
    R(c, d, a, b, X[6], 11);
    R(b, c, d, a, X[7], 19);
    R(a, b, c, d, X[8], 3);
    R(d, a, b, c, X[9], 7);
    R(c, d, a, b, X[10], 11);
    R(b, c, d, a, X[11], 19);
    R(a, b, c, d, X[12], 3);
    R(d, a, b, c, X[13], 7);
    R(c, d, a, b, X[14], 11);
    R(b, c, d, a, X[15], 19);

    S(a, b, c, d, X[0], 3);
    S(d, a, b, c, X[4], 5);
    S(c, d, a, b, X[8], 9);
    S(b, c, d, a, X[12], 13);
    S(a, b, c, d, X[1], 3);
    S(d, a, b, c, X[5], 5);
    S(c, d, a, b, X[9], 9);
    S(b, c, d, a, X[13], 13);
    S(a, b, c, d, X[2], 3);
    S(d, a, b, c, X[6], 5);
    S(c, d, a, b, X[10], 9);
    S(b, c, d, a, X[14], 13);
    S(a, b, c, d, X[3], 3);
    S(d, a, b, c, X[7], 5);
    S(c, d, a, b, X[11], 9);
    S(b, c, d, a, X[15], 13);

    T(a, b, c, d, X[0], 3);
    T(d, a, b, c, X[8], 9);
    T(c, d, a, b, X[4], 11);
    T(b, c, d, a, X[12], 15);
    T(a, b, c, d, X[2], 3);
    T(d, a, b, c, X[10], 9);
    T(c, d, a, b, X[6], 11);
    T(b, c, d, a, X[14], 15);
    T(a, b, c, d, X[1], 3);
    T(d, a, b, c, X[9], 9);
    T(c, d, a, b, X[5], 11);
    T(b, c, d, a, X[13], 15);
    T(a, b, c, d, X[3], 3);
    T(d, a, b, c, X[11], 9);
    T(c, d, a, b, X[7], 11);
    T(b, c, d, a, X[15], 15);

    md->md4.A = md->md4.A + a;
    md->md4.B = md->md4.B + b;
    md->md4.C = md->md4.C + c;
    md->md4.D = md->md4.D + d;

    return CRYPT_OK;
}

#undef F
#undef G
#undef H
#undef R
#undef S
#undef T

/**
  Initialize the hash state
  @param md   The hash state to initialize
  @return CRYPT_OK if successful
*/
int md4_init(hash_state* md)
{
    LTC_ARGCHK(md != NULL);
    md->md4.A = 0x67452301UL;
    md->md4.B = 0xefcdab89UL;
    md->md4.C = 0x98badcfeUL;
    md->md4.D = 0x10325476UL;
    md->md4.curlen = 0;
    md->md4.length = 0;
    return CRYPT_OK;
}

/**
   Process a block of text
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int md4_process(hash_state* md, const unsigned char* in, unsigned long inlen)
{
    unsigned long n;
    int           err;
    LTC_ARGCHK(md != NULL);
    LTC_ARGCHK(in != NULL);
    if (md->md4.curlen > sizeof(md->md4.buf)) {
        return CRYPT_INVALID_ARG;
    }

    while (inlen > 0) {
        if (md->md4.curlen == 0 && inlen >= 64) {
            if ((err = md4_compress(md, in)) != CRYPT_OK) {
                return err;
            }
            md->md4.length += 64 * 8;
            in += 64;
            inlen -= 64;
        }
        else {
            n = MIN(inlen, (64 - md->md4.curlen));
            XMEMCPY(md->md4.buf + md->md4.curlen, in, (size_t)n);
            md->md4.curlen += n;
            in += n;
            inlen -= n;
            if (md->md4.curlen == 64) {
                if ((err = md4_compress(md, md->md4.buf)) != CRYPT_OK) {
                    return err;
                }
                md->md4.length += 8 * 64;
                md->md4.curlen = 0;
            }
        }
    }
    return CRYPT_OK;
}

/**
   Terminate the hash
   @param md     The hash state
   @param out [out] The destination of the hash (16 bytes)
   @return CRYPT_OK if successful
*/
int md4_done(hash_state* md, unsigned char* out)
{
    int err;

    LTC_ARGCHK(md != NULL);
    LTC_ARGCHK(out != NULL);

    if (md->md4.curlen >= sizeof(md->md4.buf)) {
        return CRYPT_INVALID_ARG;
    }

    /* increase the length of the message */
    md->md4.length += md->md4.curlen * 8;

    /* append the '1' bit */
    md->md4.buf[md->md4.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->md4.curlen > 56) {
        while (md->md4.curlen < 64) {
            md->md4.buf[md->md4.curlen++] = (unsigned char)0;
        }
        if ((err = md4_compress(md, md->md4.buf)) != CRYPT_OK) {
            return err;
        }
        md->md4.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->md4.curlen < 56) {
        md->md4.buf[md->md4.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64L(md->md4.length, md->md4.buf + 56);

    if ((err = md4_compress(md, md->md4.buf)) != CRYPT_OK) {
        return err;
    }

    /* copy output */
    STORE32L(md->md4.A, out + 0);
    STORE32L(md->md4.B, out + 4);
    STORE32L(md->md4.C, out + 8);
    STORE32L(md->md4.D, out + 12);

    return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
*/
int md4_test(void)
{
#ifndef LTC_TEST
    return CRYPT_NOP;
#else
    static const struct {
        char* msg;
        unsigned char hash[16];
    } tests[] = {
        { "",
          { 0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0 }
        },
        { "a",
          { 0xbd, 0x34, 0x98, 0x39, 0x76, 0x29, 0x0b, 0x7b, 0x93, 0x2c, 0xf2, 0x71, 0x53, 0x16, 0x5b, 0xf3 }
        },
        { "abc",
          { 0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d }
        },
        { "message digest",
          { 0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b }
        },
        { "abcdefghijklmnopqrstuvwxyz",
          { 0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd, 0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41, 0x2d, 0xa9 }
        },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
          { 0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41, 0xdb, 0x35, 0x1c, 0xe6, 0x27, 0xe1, 0x53, 0xe7, 0xf0, 0xe4 }
        },
        { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
          { 0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x1a, 0x3d, 0xe9, 0xaa, 0x43, 0xc2, 0x0f, 0x4e, 0x3f }
        }
    };
    int i;
    unsigned char tmp[16];
    hash_state md;

    for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
        md4_init(&md);
        md4_process(&md, (unsigned char*)tests[i].msg, strlen(tests[i].msg));
        md4_done(&md, tmp);
        if (XMEMCMP(tmp, tests[i].hash, 16) != 0) {
            return CRYPT_FAIL_TESTVECTOR;
        }
    }
    return CRYPT_OK;
#endif
}

#endif