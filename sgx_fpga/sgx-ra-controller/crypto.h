/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef _CRYPTO_INIT_H
#define _CRYPTO_INIT_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

#include <openssl/bn.h>
#include <sgx_key_exchange.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define KEY_PUBLIC	0
#define KEY_PRIVATE	1

#ifdef __cplusplus
extern "C" {
#endif

/* General */
void crypto_init();
void crypto_destroy();

void crypto_perror (const char *prefix);

/*  AES-CMAC */

int cmac128(unsigned char key[16], unsigned char *message, size_t mlen,
	unsigned char mac[16]);

/* EC key operations */

int key_load_file (EVP_PKEY **key, const char *filename, int type);
int key_load (EVP_PKEY **key, const char *hexstring, int type);

EVP_PKEY *key_from_sgx_ec256 (sgx_ec256_public_t *k);
EVP_PKEY *key_private_from_bytes (const unsigned char buf[32]);
int key_to_sgx_ec256 (sgx_ec256_public_t *k, EVP_PKEY *key);

unsigned char *key_shared_secret (EVP_PKEY *key, EVP_PKEY *peerkey, size_t *slen);
EVP_PKEY *key_generate();

/* SHA256 */

int sha256_digest(const unsigned char *msg, size_t mlen, unsigned char digest[32]);

/* HMAC */

int sha256_verify(const unsigned char *msg, size_t mlen, unsigned char *sig,
	size_t sigsz, EVP_PKEY *pkey, int *result);

/* ECDSA signature */

int ecdsa_sign(unsigned char *msg, size_t mlen, EVP_PKEY *key,
	unsigned char r[32], unsigned char s[32], unsigned char digest[32]);

/* Certs */

int cert_load_file (X509 **cert, const char *filename);
int cert_load_size (X509 **cert, const char *pemdata, size_t sz);
int cert_load (X509 **cert, const char *pemdata);
X509_STORE *cert_init_ca(X509 *cert);
int cert_verify(X509_STORE *store, STACK_OF(X509) *chain);
STACK_OF(X509) *cert_stack_build(X509 **certs);
void cert_stack_free(STACK_OF(X509) *chain);

/* certs to client */
RSA* createPrivateRSA(const char* key);
RSA* createPublicRSA(const char* key);
bool RSASign( RSA* rsa,
              const unsigned char* Msg,
              size_t MsgLen,
              unsigned char** EncMsg,
              size_t* MsgLenEnc);
bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic);
void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text);
void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);
char* signMessage(const char* privateKey, unsigned char* plainText);
bool verifySignature(const char* publicKey, char* plainText, char* signatureBase64);
void produce_cert_client(uint64_t eid, unsigned char* cert);

#ifdef __cplusplus
};
#endif

#endif

