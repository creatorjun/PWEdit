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
   @file misc.c
   Misc utility functions, Tom St Denis
 */

 /**
   Zero a block of memory
   @param out    The destination of the memory to zero
   @param outlen The length of the block to zero (octets)
 */
void zeromem(volatile void* out, size_t outlen)
{
    volatile char* mem = (volatile char*)out;
    while (outlen-- > 0) {
        *mem++ = 0;
    }
}


/* error code to string */
static const char* err_2_str[] =
{
   "CRYPT_OK",
   "CRYPT_ERROR",
   "CRYPT_NOP",

   "CRYPT_INVALID_KEYSIZE",
   "CRYPT_INVALID_ROUNDS",
   "CRYPT_FAIL_TESTVECTOR",

   "CRYPT_BUFFER_OVERFLOW",
   "CRYPT_INVALID_PACKET",

   "CRYPT_INVALID_PRNGSIZE",
   "CRYPT_ERROR_READPRNG",

   "CRYPT_INVALID_CIPHER",
   "CRYPT_INVALID_HASH",
   "CRYPT_INVALID_PRNG",

   "CRYPT_MEM",

   "CRYPT_PK_TYPE_MISMATCH",
   "CRYPT_PK_NOT_PRIVATE",

   "CRYPT_INVALID_ARG",
   "CRYPT_FILE_NOTFOUND",

   "CRYPT_PK_INVALID_TYPE",
   "CRYPT_PK_INVALID_SYSTEM",
   "CRYPT_PK_DUP",
   "CRYPT_PK_NOT_FOUND",
   "CRYPT_PK_INVALID_SIZE",

   "CRYPT_INVALID_PRIME_SIZE",
   "CRYPT_PK_INVALID_PADDING"
};

/**
   Convert an error code to a human readable string
   @param err    The error code
   @return A pointer to a null terminated string that describes the error
*/
const char* error_to_string(int err)
{
    if (err < 0 || err >= (int)(sizeof(err_2_str) / sizeof(err_2_str[0]))) {
        return "Invalid error code.";
    }
    else {
        return err_2_str[err];
    }
}

/*
   And now a list of all file names and functions
*/
const char* crypt_build_settings =
"LibTomCrypt " SCRYPT "\n"
"Built on " __DATE__ " at " __TIME__ "\n"
"TIMING_RESISTANT\n"
"DES\nMD4\n";