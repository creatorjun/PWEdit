#include "tomcrypt_pwedit.h"

// From misc.c
void zeromem(volatile void* out, size_t outlen)
{
    volatile char* mem = (volatile char*)out;
    while (outlen-- > 0) {
        *mem++ = 0;
    }
}

// From md4.c
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
    for (i = 0; i < 16; i++) {
        LOAD32L(X[i], in + (4 * i));
    }
    a = md->A; b = md->B; c = md->C; d = md->D;
    R(a, b, c, d, X[0], 3); R(d, a, b, c, X[1], 7); R(c, d, a, b, X[2], 11); R(b, c, d, a, X[3], 19);
    R(a, b, c, d, X[4], 3); R(d, a, b, c, X[5], 7); R(c, d, a, b, X[6], 11); R(b, c, d, a, X[7], 19);
    R(a, b, c, d, X[8], 3); R(d, a, b, c, X[9], 7); R(c, d, a, b, X[10], 11); R(b, c, d, a, X[11], 19);
    R(a, b, c, d, X[12], 3); R(d, a, b, c, X[13], 7); R(c, d, a, b, X[14], 11); R(b, c, d, a, X[15], 19);
    S(a, b, c, d, X[0], 3); S(d, a, b, c, X[4], 5); S(c, d, a, b, X[8], 9); S(b, c, d, a, X[12], 13);
    S(a, b, c, d, X[1], 3); S(d, a, b, c, X[5], 5); S(c, d, a, b, X[9], 9); S(b, c, d, a, X[13], 13);
    S(a, b, c, d, X[2], 3); S(d, a, b, c, X[6], 5); S(c, d, a, b, X[10], 9); S(b, c, d, a, X[14], 13);
    S(a, b, c, d, X[3], 3); S(d, a, b, c, X[7], 5); S(c, d, a, b, X[11], 9); S(b, c, d, a, X[15], 13);
    T(a, b, c, d, X[0], 3); T(d, a, b, c, X[8], 9); T(c, d, a, b, X[4], 11); T(b, c, d, a, X[12], 15);
    T(a, b, c, d, X[2], 3); T(d, a, b, c, X[10], 9); T(c, d, a, b, X[6], 11); T(b, c, d, a, X[14], 15);
    T(a, b, c, d, X[1], 3); T(d, a, b, c, X[9], 9); T(c, d, a, b, X[5], 11); T(b, c, d, a, X[13], 15);
    T(a, b, c, d, X[3], 3); T(d, a, b, c, X[11], 9); T(c, d, a, b, X[7], 11); T(b, c, d, a, X[15], 15);
    md->A += a; md->B += b; md->C += c; md->D += d;
    return CRYPT_OK;
}

int md4_init(hash_state* md)
{
    md->A = 0x67452301UL; md->B = 0xefcdab89UL;
    md->C = 0x98badcfeUL; md->D = 0x10325476UL;
    md->curlen = 0; md->length = 0;
    return CRYPT_OK;
}

int md4_process(hash_state* md, const unsigned char* in, unsigned long inlen)
{
    unsigned long n;
    while (inlen > 0) {
        if (md->curlen == 0 && inlen >= 64) {
            md4_compress(md, in);
            md->length += 64 * 8; in += 64; inlen -= 64;
        }
        else {
            n = MIN(inlen, (64 - (unsigned long)md->curlen));
            XMEMCPY(md->buf + md->curlen, in, (size_t)n);
            md->curlen += (int)n; in += n; inlen -= n;
            if (md->curlen == 64) {
                md4_compress(md, md->buf);
                md->length += 8 * 64; md->curlen = 0;
            }
        }
    }
    return CRYPT_OK;
}

int md4_done(hash_state* md, unsigned char* out)
{
    md->length += (unsigned long long)md->curlen * 8;
    md->buf[md->curlen++] = (unsigned char)0x80;
    if (md->curlen > 56) {
        while (md->curlen < 64) md->buf[md->curlen++] = 0;
        md4_compress(md, md->buf);
        md->curlen = 0;
    }
    while (md->curlen < 56) md->buf[md->curlen++] = 0;
    STORE64L(md->length, md->buf + 56);
    md4_compress(md, md->buf);
    STORE32L(md->A, out + 0); STORE32L(md->B, out + 4);
    STORE32L(md->C, out + 8); STORE32L(md->D, out + 12);
    return CRYPT_OK;
}

// From des.c
static const ulong32 sbox[8][64] = {
{0x801082,0x20000008,0x800000,0x801000,0x1002,0x1080,0x20009000,0x9082,0x20001000,0x9000,0x20000080,0x800002,0x8002,0x20001082,0x20001002,0x809080,0,0x1000,0x20008080,0x1082,0x9080,0x20000000,0x800080,0x20008002,0x809002,0x8000,0x20009082,0x20000090,0x1008,0x20001090,0x9002,0x82,0x20009002,0x800090,0x801080,0x200000,0x1090,0x80000090,0x800008,0x90,0x80,0x801008,0x800082,0x20008090,0x10,0x20000880,0x20000800,0x1088,0x8090,0x80001008,0x200010,0x20008000,0x80001000,0x8,0x80001082,0x801090,0x800010,0x2,0x80001090,0x8010,0x20000890,0x20000882,0x20001080},
{0x100,0x1000000,0x1000008,0x4000100,0,0x4000008,0x1000000,0,0x100,0x1000008,0x4000000,0x4000108,0x8,0x1000100,0x4000100,0x1000108,0x4000008,0x100000,0x400000,0x400000,0x1000100,0x108,0x100000,0x1000108,0x8,0x4000108,0x40000,0x40040,0x1000040,0x40000,0x1000040,0x40},
{0x1000000,0x40040,0x100000,0x100000,0x40,0x10000,0x40008,0x40000,0x10008,0x40008,0x10000,0,0x4000040,0x4000040,0x10040,0x1000008,0x4000000,0x10008,0x100,0x4000100,0x10040,0x4000100,0x108,0x1000108,0x8,0x1000100,0x400000},
{0x2000001,0x20000,0x1020000,0x2000001,0x1000000,0x1020000,0x20000,0x1,0x10000,0x1000000,0x1,0x1002001,0,0x1020001,0,0x20001,0x10000,0x1002000,0x20001,0x1002001,0x1020001,0x1002000,0x20000,0x1000001,0x2000000,0x2000000,0x1000001,0x2000040,0x20040,0x1000000,0x40},
{0x2000040,0x1000000,0x40,0x1000040,0x10000,0x10040,0x10040,0x2000000,0x20000,0x10000,0,0x1000040,0,0x20040,0x2000000,0x40000,0x1000000,0x1000000,0x40000,0x10040,0x40001,0x1,0x10001,0x10001,0x40041,0x40001,0x10000,0x10000,0x40000,0x40040,0,0x40,0x40041,0,0x40040,0x40,0x1},
{0x40000,0x4000000,0x1040000,0x40000,0,0x400,0x4000000,0x1040400,0x40000,0x1040000,0x400,0,0x40400,0x1000000,0x1000400,0x1000000,0x40400,0x1000400,0x4000400,0x4000000,0x4000400,0x400000,0x40000,0x100000,0x1040000,0x100000,0x400000,0x40400,0x400,0x1000400,0x4000400,0x1040400,0x1000400,0x400,0x400000,0x1040000,0x40400},
{0x2000,0x4000000,0x4002000,0x2000000,0x200000,0,0x200,0x200000,0,0x4000000,0x2000200,0x2000,0x4002000,0x2000000,0x200200,0x200200,0x200,0x2000200,0x4002000,0x4000200,0x4000200,0x4000000,0x200000,0x4000200,0x200,0x2000200,0x4000000,0x2000,0x2000200,0,0x4002000,0x200200,0x200,0x200000,0x2000,0x4002000,0x2000000},
{0x400,0x10000,0x10000,0x400,0x10404,0x10000,0x404,0x10400,0x404,0,0x400,0x10404,0x10004,0x10400,0x4,0,0x10004,0x4,0x8000000,0x400000,0x4000,0x8004000,0x8000000,0x4000,0x400000,0,0x400,0x8004000,0x8000400,0x400,0,0x4000,0x8000400,0x400000,0x8000000,0x8000400,0x4000,0x400000,0x8000000,0x400,0x8004000,0x8004000,0,0x8000400,0x400}
};

static const ulong32 PC1[] = { 0xf0f0f0f0,0x0f0f0f0f,0xf0f0f0f0,0x0f0f0f0f,0xcccccccc,0x33333333,0xcccccccc,0x33333333,0xf0f0f0f0,0x0f0f0f0f,0xf0f0f0f0,0x0f0f0f0f,0xff00ff00,0x00ff00ff,0xff00ff00,0x00ff00ff,0xf0f0cccc,0x33330f0f,0xccccf0f0,0x0f0f3333 };
static const ulong32 PC2[] = { 0x000000ff,0x0000ff00,0x00ff0000,0xff000000,0x000000ff,0x0000ff00,0x00ff0000,0xff000000,0xf0f0f0f0,0x0f0f0f0f,0xf0f0f0f0,0x0f0f0f0f,0xcccccccc,0x33333333,0xcccccccc,0x33333333 };
static const ulong32 SHIFTS[] = { 0x1,0x1,0x2,0x2,0x2,0x2,0x2,0x2,0x1,0x2,0x2,0x2,0x2,0x2,0x2,0x1 };

#define PERM(a,b,t) (t=a,a=b,b=t)
#define APPLY_SBOX(L,S,T,R) T=R; R=(L^ROL(R,13))&15; L^=S[4][R]; R>>=4; R=(L^ROL(R,29))&15; L^=S[5][R]; R>>=4; R=(L^ROL(R,5))&15; L^=S[6][R]; R>>=4; R=(L^ROL(R,21))&15; L^=S[7][R]; R>>=4; R=(L^ROL(R,17))&15; L^=S[0][R]; R>>=4; R=(L^ROL(R,1))&15; L^=S[1][R]; R>>=4; R=(L^ROL(R,25))&15; L^=S[2][R]; R>>=4; R=(L^ROL(R,9))&15;  L^=S[3][R]; L^=T;

static void des_key_setup(const unsigned char* key, symmetric_key* skey)
{
    ulong32 K[2], T, L, R, A, B, * K2;
    int i;
    K2 = skey->des.ek;
    LOAD32H(K[0], key); LOAD32H(K[1], key + 4);
    A = (K[0] & PC1[0]) | (ROL(K[0], 4) & PC1[1]); B = (K[0] & PC1[2]) | (ROL(K[0], 4) & PC1[3]);
    L = (A & PC1[8]) | (ROL(A, 2) & PC1[9]) | (B & PC1[10]) | (ROL(B, 2) & PC1[11]);
    A = (K[1] & PC1[4]) | (ROL(K[1], 4) & PC1[5]); B = (K[1] & PC1[6]) | (ROL(K[1], 4) & PC1[7]);
    R = (A & PC1[12]) | (ROL(A, 2) & PC1[13]) | (B & PC1[14]) | (ROL(B, 2) & PC1[15]);
    T = ((K[0] & PC1[16]) | (ROL(K[1], 4) & PC1[17])) & 0x0f0f0f0f; R |= ROL(T, 4);
    T = ((ROL(K[0], 20) & PC1[18]) | (ROL(K[1], 24) & PC1[19])) & 0x0f0f0f0f; L |= T;
    for (i = 0; i < 16; i++) {
        L = (ROL(L, SHIFTS[i]) & 0x0fffffff); R = (ROL(R, SHIFTS[i]) & 0x0fffffff);
        A = (L & PC2[8]) | (ROL(L, 2) & PC2[9]); B = (L & PC2[10]) | (ROL(L, 2) & PC2[11]);
        K2[i + i] = (A & PC2[0]) | (ROL(A, 8) & PC2[1]) | (B & PC2[2]) | (ROL(B, 8) & PC2[3]);
        A = (R & PC2[12]) | (ROL(R, 2) & PC2[13]); B = (R & PC2[14]) | (ROL(R, 2) & PC2[15]);
        K2[i + i + 1] = (A & PC2[4]) | (ROL(A, 8) & PC2[5]) | (B & PC2[6]) | (ROL(B, 8) & PC2[7]);
    }
}

int des_setup(const unsigned char* key, int keylen, int rounds, symmetric_key* skey)
{
    (void)rounds;
    if (keylen != 8) return CRYPT_INVALID_KEYSIZE;
    des_key_setup(key, skey);
    return CRYPT_OK;
}

void des_ecb_encrypt(const unsigned char* pt, unsigned char* ct, symmetric_key* skey)
{
    ulong32 L, R, T, * K;
    K = skey->des.ek; LOAD32H(L, pt); LOAD32H(R, pt + 4);
    T = ((L >> 4) ^ R) & 0x0f0f0f0f; R ^= T; L ^= (T << 4); T = ((L >> 16) ^ R) & 0xffff; R ^= T; L ^= (T << 16);
    T = ((R >> 2) ^ L) & 0x33333333; L ^= T; R ^= (T << 2); T = ((R >> 8) ^ L) & 0xff00ff; L ^= T; R ^= (T << 8);
    T = ((L >> 1) ^ R) & 0x55555555; R ^= T; L ^= (T << 1); PERM(L, R, T); T = ((L >> 8) ^ R) & 0xff00ff; R ^= T; L ^= (T << 8);
    T = ((L >> 2) ^ R) & 0x33333333; R ^= T; L ^= (T << 2);
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[0]; R ^= K[1];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[2]; R ^= K[3];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[4]; R ^= K[5];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[6]; R ^= K[7];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[8]; R ^= K[9];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[10]; R ^= K[11];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[12]; R ^= K[13];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[14]; R ^= K[15];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[16]; R ^= K[17];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[18]; R ^= K[19];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[20]; R ^= K[21];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[22]; R ^= K[23];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[24]; R ^= K[25];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[26]; R ^= K[27];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[28]; R ^= K[29];
    APPLY_SBOX(L, sbox, T, R); APPLY_SBOX(R, sbox, T, L); L ^= K[30]; R ^= K[31];
    L = R;
    T = ((L >> 2) ^ R) & 0x33333333; R ^= T; L ^= (T << 2); T = ((L >> 8) ^ R) & 0xff00ff; R ^= T; L ^= (T << 8);
    PERM(L, R, T); T = ((R >> 1) ^ L) & 0x55555555; L ^= T; R ^= (T << 1); T = ((R >> 8) ^ L) & 0xff00ff; L ^= T; R ^= (T << 8);
    T = ((R >> 2) ^ L) & 0x33333333; R ^= T; L ^= (T << 2); T = ((L >> 16) ^ R) & 0xffff; R ^= T; L ^= (T << 16);
    T = ((L >> 4) ^ R) & 0x0f0f0f0f; R ^= T; L ^= (T << 4);
    STORE32H(R, ct); STORE32H(L, ct + 4);
}

void des_done(symmetric_key* skey)
{
    zeromem(skey, sizeof(symmetric_key));
}