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
    @file des.c
    DES implementation by Tom St Denis
 */

#ifdef LTC_DES

 /* DES S-box tables */
static const ulong32 sbox[8][64] = {
{ 0x801082, 0x20000008, 0x800000, 0x801000, 0x1002, 0x1080, 0x20009000, 0x9082, 0x20001000, 0x9000, 0x20000080, 0x800002, 0x8002, 0x20001082, 0x20001002, 0x809080, 0, 0x1000, 0x20008080, 0x1082, 0x9080, 0x20000000, 0x800080, 0x20008002, 0x809002, 0x8000, 0x20009082, 0x20000090, 0x1008, 0x20001090, 0x9002, 0x82, 0x20009002, 0x800090, 0x801080, 0x200000, 0x1090, 0x80000090, 0x800008, 0x90, 0x80, 0x801008, 0x800082, 0x20008090, 0x10, 0x20000880, 0x20000800, 0x1088, 0x8090, 0x80001008, 0x200010, 0x20008000, 0x80001000, 0x8, 0x80001082, 0x801090, 0x800010, 0x2, 0x80001090, 0x8010, 0x20000890, 0x20000882, 0x20001080, 0x100, 0x1000000, 0x1000008, 0x4000100, 0x0, 0x4000008, 0x1000000, 0x0, 0x100, 0x1000008, 0x4000000, 0x4000108, 0x8, 0x1000100, 0x4000100, 0x1000108, 0x4000008, 0x100000, 0x400000, 0x400000, 0x1000100, 0x108, 0x100000, 0x1000108, 0x8, 0x4000108, 0x40000, 0x40040, 0x1000040, 0x40000, 0x1000040, 0x40, 0x1000000, 0x40040, 0x100000, 0x100000, 0x40, 0x10000, 0x40008, 0x40000, 0x10008, 0x40008, 0x10000, 0x0, 0x4000040, 0x4000040, 0x10040, 0x1000008, 0x4000000, 0x10008, 0x100, 0x4000100, 0x10040, 0x4000100, 0x108, 0x1000108, 0x8, 0x1000100, 0x400000, 0x2000001, 0x20000, 0x1020000, 0x2000001, 0x1000000, 0x1020000, 0x20000, 0x1, 0x10000, 0x1000000, 0x1, 0x1002001, 0x0, 0x1020001, 0x0, 0x20001, 0x10000, 0x1002000, 0x20001, 0x1002001, 0x1020001, 0x1002000, 0x20000, 0x1000001, 0x2000000, 0x2000000, 0x1000001, 0x2000040, 0x20040, 0x1000000, 0x40, 0x2000040, 0x1000000, 0x40, 0x1000040, 0x10000, 0x10040, 0x10040, 0x2000000, 0x20000, 0x10000, 0x0, 0x1000040, 0x0, 0x20040, 0x2000000, 0x40000, 0x1000000, 0x1000000, 0x40000, 0x10040, 0x40001, 0x1, 0x10001, 0x10001, 0x40041, 0x40001, 0x10000, 0x10000, 0x40000, 0x40040, 0x0, 0x40, 0x40041, 0x0, 0x40040, 0x40, 0x1, 0x40000, 0x4000000, 0x1040000, 0x40000, 0x0, 0x400, 0x4000000, 0x1040400, 0x40000, 0x1040000, 0x400, 0x0, 0x40400, 0x1000000, 0x1000400, 0x1000000, 0x40400, 0x1000400, 0x4000400, 0x4000000, 0x4000400, 0x400000, 0x40000, 0x100000, 0x1040000, 0x100000, 0x400000, 0x40400, 0x400, 0x1000400, 0x4000400, 0x1040400, 0x1000400, 0x400, 0x400000, 0x1040000, 0x40400, 0x2000, 0x4000000, 0x4002000, 0x2000000, 0x200000, 0x0, 0x200, 0x200000, 0x0, 0x4000000, 0x2000200, 0x2000, 0x4002000, 0x2000000, 0x200200, 0x200200, 0x200, 0x2000200, 0x4002000, 0x4000200, 0x4000200, 0x4000000, 0x200000, 0x4000200, 0x200, 0x2000200, 0x4000000, 0x2000, 0x2000200, 0x0, 0x4000200, 0x200200, 0x200, 0x200000, 0x2000, 0x4002000, 0x2000000, 0x400, 0x10000, 0x10000, 0x400, 0x10404, 0x10000, 0x404, 0x10400, 0x404, 0x0, 0x400, 0x10404, 0x10004, 0x10400, 0x4, 0x0, 0x10004, 0x4, 0x8000000, 0x400000, 0x4000, 0x8004000, 0x8000000, 0x4000, 0x400000, 0x0, 0x400, 0x8004000, 0x8000400, 0x400, 0x0, 0x4000, 0x8000400, 0x400000, 0x8000000, 0x8000400, 0x4000, 0x400000, 0x8000000, 0x400, 0x8004000, 0x8004000, 0x0, 0x8000400, 0x400
};

/* 32-bit permutation tables */
static const ulong32 IP[] = {
   0x0f0f0f0f, 0x00ff00ff, 0x0000ffff, 0xaaaaaaaa,
   0xcccccccc, 0xf0f0f0f0, 0xff00ff00, 0xffff0000
};
static const ulong32 FP[] = {
   0x0f0f0f0f, 0x00ff00ff, 0x0000ffff, 0x55555555,
   0x33333333, 0x0f0f0f0f, 0x00ff00ff, 0x0000ffff
};

/* PC1 table */
static const ulong32 PC1[] = {
   0xf0f0f0f0, 0x0f0f0f0f, 0xf0f0f0f0, 0x0f0f0f0f,
   0xcccccccc, 0x33333333, 0xcccccccc, 0x33333333,
   0xf0f0f0f0, 0x0f0f0f0f, 0xf0f0f0f0, 0x0f0f0f0f,
   0xff00ff00, 0x00ff00ff, 0xff00ff00, 0x00ff00ff,
   0xf0f0cccc, 0x33330f0f, 0xccccf0f0, 0x0f0f3333
};

/* PC2 table */
static const ulong32 PC2[] = {
   0x000000ff, 0x0000ff00, 0x00ff0000, 0xff000000,
   0x000000ff, 0x0000ff00, 0x00ff0000, 0xff000000,
   0xf0f0f0f0, 0x0f0f0f0f, 0xf0f0f0f0, 0x0f0f0f0f,
   0xcccccccc, 0x33333333, 0xcccccccc, 0x33333333
};

/* left circular shift table */
static const ulong32 SHIFTS[] = {
   0x00000001, 0x00000001, 0x00000002, 0x00000002,
   0x00000002, 0x00000002, 0x00000002, 0x00000002,
   0x00000001, 0x00000002, 0x00000002, 0x00000002,
   0x00000002, 0x00000002, 0x00000002, 0x00000001
};

#define PERM(a,b,t) (t=a,a=b,b=t)

#define APPLY_SBOX(L,S,T,R)                                                                   \
T=R; R=(L^ROL(R,13))&15; L^=S[4][R]; R>>=4; R=(L^ROL(R,29))&15; L^=S[5][R]; R>>=4; \
R=(L^ROL(R,5))&15;  L^=S[6][R]; R>>=4; R=(L^ROL(R,21))&15; L^=S[7][R]; R>>=4;      \
R=(L^ROL(R,17))&15; L^=S[0][R]; R>>=4; R=(L^ROL(R,1))&15;  L^=S[1][R]; R>>=4;      \
R=(L^ROL(R,25))&15; L^=S[2][R]; R>>=4; R=(L^ROL(R,9))&15;  L^=S[3][R]; L^=T;

static void des_key_setup(const unsigned char* key, symmetric_key* skey)
{
   ulong32 K[2], T, L, R, A, B,* K2;
   int i, j;

   K2 = skey->des.ek;

   LOAD32H(K[0], key);
   LOAD32H(K[1], key + 4);

   /* test parity bits */
   i = K[0] ^ K[1];
   i ^= ROL(i, 4);
   i ^= ROL(i, 8);
   i ^= ROL(i, 16);
   if (~i & 1) {
       /* odd parity */
       L = (K[0] & 0xfefefefe) | (~K[1] & 0x01010101);
       R = (K[1] & 0xfefefefe) | (~K[0] & 0x01010101);
       K[0] = L; K[1] = R;
    }

   /* apply PC1 to K */
   A = (K[0] & PC1[0]) | (ROL(K[0], 4) & PC1[1]);
   B = (K[0] & PC1[2]) | (ROL(K[0], 4) & PC1[3]);
   L = (A & PC1[8]) | (ROL(A, 2) & PC1[9]) |
       (B & PC1[10]) | (ROL(B, 2) & PC1[11]);
   A = (K[1] & PC1[4]) | (ROL(K[1], 4) & PC1[5]);
   B = (K[1] & PC1[6]) | (ROL(K[1], 4) & PC1[7]);
   R = (A & PC1[12]) | (ROL(A, 2) & PC1[13]) |
       (B & PC1[14]) | (ROL(B, 2) & PC1[15]);
   T = ((K[0] & PC1[16]) | (ROL(K[1], 4) & PC1[17])) & 0x0f0f0f0f;
   R |= ROL(T, 4);
   T = ((ROL(K[0], 20) & PC1[18]) | (ROL(K[1], 24) & PC1[19])) & 0x0f0f0f0f;
   L |= T;

   /* make 16 rounds of keys */
   for (i = 0; i < 16; i++) {
       /* shift for round */
       j = SHIFTS[i];
       L = (ROL(L, j) & 0x0fffffff);
       R = (ROL(R, j) & 0x0fffffff);

       /* apply PC2 to get EK */
       A = (L & PC2[8]) | (ROL(L, 2) & PC2[9]);
       B = (L & PC2[10]) | (ROL(L, 2) & PC2[11]);
       K2[i + i] = (A & PC2[0]) | (ROL(A, 8) & PC2[1]) |
                   (B & PC2[2]) | (ROL(B, 8) & PC2[3]);
       A = (R & PC2[12]) | (ROL(R, 2) & PC2[13]);
       B = (R & PC2[14]) | (ROL(R, 2) & PC2[15]);
       K2[i + i + 1] = (A & PC2[4]) | (ROL(A, 8) & PC2[5]) |
                   (B & PC2[6]) | (ROL(B, 8) & PC2[7]);
    }
 }

/**
  Setup a DES key
  @param key    The key to setup
  @param keylen The length of the key
  @param rounds Not used
  @param skey   The destination of the setup key
  @return CRYPT_OK if successful
*/
int des_setup(const unsigned char* key, int keylen, int rounds, symmetric_key* skey)
{
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (keylen != 8) {
      return CRYPT_INVALID_KEYSIZE;
   }

   if (rounds != 0 && rounds != 16) {
      return CRYPT_INVALID_ROUNDS;
   }

   des_key_setup(key, skey);

   return CRYPT_OK;
}

/**
   Encrypt a block with DES
   @param pt     The plaintext to encrypt
   @param ct     [out] The ciphertext
   @param skey   The scheduled key
*/
void des_ecb_encrypt(const unsigned char* pt, unsigned char* ct, symmetric_key* skey)
{
   ulong32 L, R, T,* K;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(skey != NULL);

   K = skey->des.ek;
   LOAD32H(L, pt);
   LOAD32H(R, pt + 4);

   /*- PERM(L, R, T, IP); */
   T = ((L >> 4) ^ R) & 0x0f0f0f0f; R ^= T; L ^= (T << 4);
   T = ((L >> 16) ^ R) & 0x0000ffff; R ^= T; L ^= (T << 16);
   T = ((R >> 2) ^ L) & 0x33333333; L ^= T; R ^= (T << 2);
   T = ((R >> 8) ^ L) & 0x00ff00ff; L ^= T; R ^= (T << 8);
   T = ((L >> 1) ^ R) & 0x55555555; R ^= T; L ^= (T << 1);
   PERM(L, R, T);
   T = ((L >> 8) ^ R) & 0x00ff00ff; R ^= T; L ^= (T << 8);
   T = ((L >> 2) ^ R) & 0x33333333; R ^= T; L ^= (T << 2);

   /* 16 rounds */
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[0]; R ^= K[1];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[2]; R ^= K[3];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[4]; R ^= K[5];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[6]; R ^= K[7];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[8]; R ^= K[9];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[10]; R ^= K[11];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[12]; R ^= K[13];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[14]; R ^= K[15];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[16]; R ^= K[17];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[18]; R ^= K[19];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[20]; R ^= K[21];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[22]; R ^= K[23];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[24]; R ^= K[25];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[26]; R ^= K[27];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[28]; R ^= K[29];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[30]; R ^= K[31];
   L = R;

   /*- PERM(R, L, T, FP); */
   T = ((L >> 2) ^ R) & 0x33333333; R ^= T; L ^= (T << 2);
   T = ((L >> 8) ^ R) & 0x00ff00ff; R ^= T; L ^= (T << 8);
   PERM(L, R, T);
   T = ((R >> 1) ^ L) & 0x55555555; L ^= T; R ^= (T << 1);
   T = ((R >> 8) ^ L) & 0x00ff00ff; L ^= T; R ^= (T << 8);
   T = ((R >> 2) ^ L) & 0x33333333; L ^= T; R ^= (T << 2);
   T = ((L >> 16) ^ R) & 0x0000ffff; R ^= T; L ^= (T << 16);
   T = ((L >> 4) ^ R) & 0x0f0f0f0f; R ^= T; L ^= (T << 4);

   STORE32H(R, ct);
   STORE32H(L, ct + 4);
}

/**
   Decrypt a block with DES
   @param ct     The ciphertext to decrypt
   @param pt     [out] The plaintext
   @param skey   The scheduled key
*/
void des_ecb_decrypt(const unsigned char* ct, unsigned char* pt, symmetric_key* skey)
{
   ulong32 L, R, T,* K;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(skey != NULL);

   K = skey->des.dk;
   LOAD32H(L, ct);
   LOAD32H(R, ct + 4);

   /*- PERM(L, R, T, IP); */
   T = ((L >> 4) ^ R) & 0x0f0f0f0f; R ^= T; L ^= (T << 4);
   T = ((L >> 16) ^ R) & 0x0000ffff; R ^= T; L ^= (T << 16);
   T = ((R >> 2) ^ L) & 0x33333333; L ^= T; R ^= (T << 2);
   T = ((R >> 8) ^ L) & 0x00ff00ff; L ^= T; R ^= (T << 8);
   T = ((L >> 1) ^ R) & 0x55555555; R ^= T; L ^= (T << 1);
   PERM(L, R, T);
   T = ((L >> 8) ^ R) & 0x00ff00ff; R ^= T; L ^= (T << 8);
   T = ((L >> 2) ^ R) & 0x33333333; R ^= T; L ^= (T << 2);

   /* 16 rounds */
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[30]; R ^= K[31];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[28]; R ^= K[29];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[26]; R ^= K[27];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[24]; R ^= K[25];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[22]; R ^= K[23];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[20]; R ^= K[21];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[18]; R ^= K[19];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[16]; R ^= K[17];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[14]; R ^= K[15];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[12]; R ^= K[13];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[10]; R ^= K[11];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[8]; R ^= K[9];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[6]; R ^= K[7];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[4]; R ^= K[5];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[2]; R ^= K[3];
   APPLY_SBOX(L,sbox,T,R);
   APPLY_SBOX(R,sbox,T,L);
   L ^= K[0]; R ^= K[1];
   L = R;

   /*- PERM(R, L, T, FP); */
   T = ((L >> 2) ^ R) & 0x33333333; R ^= T; L ^= (T << 2);
   T = ((L >> 8) ^ R) & 0x00ff00ff; R ^= T; L ^= (T << 8);
   PERM(L, R, T);
   T = ((R >> 1) ^ L) & 0x55555555; L ^= T; R ^= (T << 1);
   T = ((R >> 8) ^ L) & 0x00ff00ff; L ^= T; R ^= (T << 8);
   T = ((R >> 2) ^ L) & 0x33333333; R ^= T; L ^= (T << 2);
   T = ((L >> 16) ^ R) & 0x0000ffff; R ^= T; L ^= (T << 16);
   T = ((L >> 4) ^ R) & 0x0f0f0f0f; R ^= T; L ^= (T << 4);

   STORE32H(R, pt);
   STORE32H(L, pt + 4);
}

/**
   Test the DES-ECB code
   @return CRYPT_OK if successful
*/
int des_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
   static const unsigned char key[8] =
      { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
   static const unsigned char pt[8] =
      { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
   static const unsigned char ct[8] =
      { 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 };
   unsigned char tmp[2][8];
   symmetric_key skey;
   int err;

   if ((err = des_setup(key, 8, 0, &skey)) != CRYPT_OK) {
      return err;
   }

   des_ecb_encrypt(pt, tmp[0], &skey);
   des_ecb_decrypt(ct, tmp[1], &skey);

   if (XMEMCMP(tmp[0], ct, 8) != 0 || XMEMCMP(tmp[1], pt, 8) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }
   return CRYPT_OK;
 #endif
}

/**
  Terminate the context
  @param skey    The scheduled key
*/
void des_done(symmetric_key* skey)
{
   zeromem(skey, sizeof(symmetric_key));
}


/**
  Gets suitable key size
  @param keysize [in/out] The length of the recommended key (in octets).  An error is thrown if the key size is not valid.
  @return CRYPT_OK if the key size is acceptable.
*/
int des_keysize(int* keysize)
{
   LTC_ARGCHK(keysize != NULL);
   if (*keysize != 8) {
      return CRYPT_INVALID_KEYSIZE;
   }
   return CRYPT_OK;
}

const cipher_descriptor_t des_desc =
{
    "des",
    1,
    8, 8, 8, 16,
    &des_setup,
    &des_ecb_encrypt,
    &des_ecb_decrypt,
    &des_test,
    &des_done,
    &des_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* 3DES */
#ifdef LTC_DES3

const cipher_descriptor_t des3_desc =
{
    "3des",
    4,
    16, 24, 8, 16,
    &three_des_setup,
    &three_des_ecb_encrypt,
    &three_des_ecb_decrypt,
    &three_des_test,
    &three_des_done,
    &three_des_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};


/**
   Setup a 3DES key
   @param key    The key to load
   @param keylen The length of the key
   @param rounds The number of rounds to perform (ignored)
   @param skey   The destination of the scheduled key
   @return CRYPT_OK if successful
*/
int three_des_setup(const unsigned char* key, int keylen, int rounds, symmetric_key* skey)
{
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   if (keylen != 16 && keylen != 24) {
      return CRYPT_INVALID_KEYSIZE;
   }

   if (rounds != 0 && rounds != 16) {
      return CRYPT_INVALID_ROUNDS;
   }

   des_key_setup(key, &skey->des3.key[0]);
   des_key_setup(key + 8, &skey->des3.key[1]);
   if (keylen == 24) {
      des_key_setup(key + 16, &skey->des3.key[2]);
   }
 else {
 des_key_setup(key, &skey->des3.key[2]);
}
return CRYPT_OK;
}

/**
  Encrypt with 3DES
  @param pt      The plaintext
  @param ct      [out] The ciphertext
  @param skey    The scheduled key
*/
void three_des_ecb_encrypt(const unsigned char* pt, unsigned char* ct, symmetric_key* skey)
{
   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(skey != NULL);
   des_ecb_encrypt(pt, ct, &skey->des3.key[0]);
   des_ecb_decrypt(ct, ct, &skey->des3.key[1]);
   des_ecb_encrypt(ct, ct, &skey->des3.key[2]);
}

/**
  Decrypt with 3DES
  @param ct      The ciphertext
  @param pt      [out] The plaintext
  @param skey    The scheduled key
*/
void three_des_ecb_decrypt(const unsigned char* ct, unsigned char* pt, symmetric_key* skey)
{
   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(skey != NULL);
   des_ecb_decrypt(ct, pt, &skey->des3.key[2]);
   des_ecb_encrypt(pt, pt, &skey->des3.key[1]);
   des_ecb_decrypt(pt, pt, &skey->des3.key[0]);
}

/**
  Test 3DES
  @return CRYPT_OK if successful
*/
int three_des_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
   static const unsigned char key[24] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
      0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67
   };
   static const unsigned char pt[8] =
      { 0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74 };
   static const unsigned char ct[8] =
      { 0xcb, 0xf1, 0x82, 0xde, 0x5f, 0x27, 0x51, 0x5a };
   unsigned char tmp[2][8];
   symmetric_key skey;
   int err;

   if ((err = three_des_setup(key, 24, 0, &skey)) != CRYPT_OK) {
      return err;
   }
   three_des_ecb_encrypt(pt, tmp[0], &skey);
   three_des_ecb_decrypt(ct, tmp[1], &skey);

   if (XMEMCMP(tmp[0], ct, 8) != 0 || XMEMCMP(tmp[1], pt, 8) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }
   return CRYPT_OK;
 #endif
}

/**
  Terminate a 3DES context
  @param skey   The scheduled key
*/
void three_des_done(symmetric_key* skey)
{
   zeromem(skey, sizeof(symmetric_key));
}

/**
  Gets suitable key size
  @param keysize [in/out] The length of the recommended key (in octets).  An error is thrown if the key size is not valid.
  @return CRYPT_OK if the key size is acceptable.
*/
int three_des_keysize(int* keysize)
{
   LTC_ARGCHK(keysize != NULL);
   if (*keysize != 16 && *keysize != 24) {
      return CRYPT_INVALID_KEYSIZE;
   }
   return CRYPT_OK;
}

#endif

#endif