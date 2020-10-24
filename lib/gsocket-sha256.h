/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef HAVE_LIBCRYPTO
#warning "***** No OpenSSL. Using INTERNAL SHA256. *****"

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest
#define SHA256_DIGEST_LENGTH	32

unsigned char *GS_SHA256(const unsigned char *d, size_t n, unsigned char *md);

#else
/* HERE: HAVE_LIBCRYPTO is set and OpenSSL is available */
# define GS_SHA256(d, n, md)	SHA256(d, n, md)
#endif /* HAVE_LIBCRYPTO */

