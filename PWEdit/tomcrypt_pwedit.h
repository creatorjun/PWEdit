#pragma once

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

    // --- Custom Type Definitions ---
    typedef uint64_t ulong64;
    typedef uint32_t ulong32;
    typedef uint16_t ulong16;
    typedef uint8_t  ulong8;

    // --- MSVC-Specific Macros ---
#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl,_byteswap_ulong)
#define ROL(x, y) _lrotl(x, y)
#define ROR(x, y) _lrotr(x, y)
#define BSWAP(x) _byteswap_ulong(x)

#define XMEMCPY               memcpy
#define XMEMSET               memset
#define XMEMCMP               memcmp

#define STORE32L(x, y)        \
do { (y)[0] = (ulong8)((x));      \
     (y)[1] = (ulong8)((x)>>8);   \
     (y)[2] = (ulong8)((x)>>16);  \
     (y)[3] = (ulong8)((x)>>24); } while(0)

#define LOAD32L(x, y)         \
do { x = ( ((ulong32)((y)[3]))<<24) | \
         ( ((ulong32)((y)[2]))<<16) | \
         ( ((ulong32)((y)[1]))<<8)  | \
           ((ulong32)((y)[0])); } while(0)

#define STORE64L(x, y)        \
do { (y)[0] = (ulong8)((x));      \
     (y)[1] = (ulong8)((x)>>8);   \
     (y)[2] = (ulong8)((x)>>16);  \
     (y)[3] = (ulong8)((x)>>24);  \
     (y)[4] = (ulong8)((x)>>32);  \
     (y)[5] = (ulong8)((x)>>40);  \
     (y)[6] = (ulong8)((x)>>48);  \
     (y)[7] = (ulong8)((x)>>56); } while(0)

#define STORE32H(x, y)        \
do { (y)[0] = (ulong8)((x)>>24);  \
     (y)[1] = (ulong8)((x)>>16);  \
     (y)[2] = (ulong8)((x)>>8);   \
     (y)[3] = (ulong8)((x)); } while(0)

#define LOAD32H(x, y)         \
do { x = ( ((ulong32)((y)[0]))<<24) | \
         ( ((ulong32)((y)[1]))<<16) | \
         ( ((ulong32)((y)[2]))<<8)  | \
           ((ulong32)((y)[3])); } while(0)

#ifndef MIN
#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

// --- Error Codes ---
    enum {
        CRYPT_OK = 0,
        CRYPT_ERROR,
        CRYPT_INVALID_KEYSIZE,
        CRYPT_INVALID_ROUNDS,
        CRYPT_FAIL_TESTVECTOR,
        CRYPT_INVALID_ARG
    };

    // --- Structures ---
#define MAXBLOCKSIZE  128

    typedef struct {
        ulong32 ek[32], dk[32];
    } des_key;

    typedef union symmetric_key_ {
        des_key des;
        char    pad[MAXBLOCKSIZE * 2];
    } symmetric_key;

    typedef struct hash_state_ {
        ulong32 A, B, C, D;
        ulong64 length;
        unsigned char buf[64];
        int curlen;
    } hash_state;

    // --- Function Prototypes ---
    int des_setup(const unsigned char* key, int keylen, int rounds, symmetric_key* skey);
    void des_ecb_encrypt(const unsigned char* pt, unsigned char* ct, symmetric_key* skey);
    void des_done(symmetric_key* skey);

    int md4_init(hash_state* md);
    int md4_process(hash_state* md, const unsigned char* in, unsigned long inlen);
    int md4_done(hash_state* md, unsigned char* out);

    void zeromem(volatile void* out, size_t outlen);

#ifdef __cplusplus
}
#endif