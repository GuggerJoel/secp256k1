/**********************************************************************
 * Copyright (c) 2017 Joel Gugger                                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_PAILLIER_H
#define SECP256K1_PAILLIER_H

#include "include/secp256k1.h"
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mpz_t modulus;
    mpz_t generator;
    mpz_t bigModulus;
} secp256k1_paillier_pubkey;

typedef struct {
    mpz_t modulus;
    mpz_t prime1;
    mpz_t prime2;
    mpz_t generator;
    mpz_t bigModulus;
    mpz_t privateExponent;
    mpz_t coefficient;
} secp256k1_paillier_privkey;

typedef struct {
    mpz_t message;
    mpz_t nonce;
} secp256k1_paillier_encrypted_message;

typedef int (*secp256k1_paillier_nonce_function)(
    mpz_t nonce,
    const mpz_t max
);

secp256k1_paillier_privkey* secp256k1_paillier_privkey_create(void);

secp256k1_paillier_encrypted_message* secp256k1_paillier_message_create(void);

void secp256k1_paillier_message_destroy(secp256k1_paillier_encrypted_message *m);

secp256k1_paillier_pubkey* secp256k1_paillier_pubkey_create(void);

secp256k1_paillier_pubkey* secp256k1_paillier_pubkey_get(const secp256k1_paillier_privkey *privkey);

void secp256k1_paillier_privkey_reset(secp256k1_paillier_privkey *privkey);

void secp256k1_paillier_pubkey_reset(secp256k1_paillier_pubkey *pubkey);

void secp256k1_paillier_privkey_destroy(secp256k1_paillier_privkey *privkey);

void secp256k1_paillier_pubkey_destroy(secp256k1_paillier_pubkey *pubkey);

/**
HEPrivateKey ::= SEQUENCE {
    version           INTEGER,
    modulus           INTEGER,  -- p * q
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    generator         INTEGER,
    privateExponent   INTEGER,  -- (p - 1) * (q - 1)
    coefficient       INTEGER   -- (inverse of privateExponent) mod (p * q)
}
*/
int secp256k1_paillier_privkey_parse(
    secp256k1_paillier_privkey *privkey,
    secp256k1_paillier_pubkey *pubkey,
    const unsigned char *input,
    size_t inputlen
);

/**
HEPublicKey ::= SEQUENCE {
    version           INTEGER,
    modulus           INTEGER,  -- p * q
    generator         INTEGER
}
*/
int secp256k1_paillier_pubkey_parse(
    secp256k1_paillier_pubkey *pubkey,
    const unsigned char *input,
    size_t inputlen
);

/**
HEEncryptedMessage ::= SEQUENCE {
    message           INTEGER
}
*/
int secp256k1_paillier_message_parse(
    secp256k1_paillier_encrypted_message *message,
    const unsigned char *input,
    size_t inputlen
);

/**
HEEncryptedMessage ::= SEQUENCE {
    message           INTEGER
}
*/
unsigned char* secp256k1_paillier_message_serialize(
    size_t *outputlen,
    const secp256k1_paillier_encrypted_message *message
);

int secp256k1_paillier_encrypt(
    secp256k1_paillier_encrypted_message *res,
    const unsigned char *data,
    const size_t lenght,
    const secp256k1_paillier_pubkey *pubkey,
    const secp256k1_paillier_nonce_function noncefp
);

int secp256k1_paillier_encrypt_mpz(
    secp256k1_paillier_encrypted_message *res,
    const mpz_t m,
    const secp256k1_paillier_pubkey *pubkey,
    const secp256k1_paillier_nonce_function noncefp
);

int secp256k1_paillier_encrypt_scalar(
    secp256k1_paillier_encrypted_message *res,
    const secp256k1_scalar *scalar,
    const secp256k1_paillier_pubkey *pubkey,
    const secp256k1_paillier_nonce_function noncefp
);

void secp256k1_paillier_decrypt(
    mpz_t res,
    const secp256k1_paillier_encrypted_message *c,
    const secp256k1_paillier_privkey *privkey
);

void secp256k1_paillier_mult(
    secp256k1_paillier_encrypted_message *res,
    const secp256k1_paillier_encrypted_message *c,
    const mpz_t s,
    const secp256k1_paillier_pubkey *pubkey
);

void secp256k1_paillier_add(
    secp256k1_paillier_encrypted_message *res,
    const secp256k1_paillier_encrypted_message *op1,
    const secp256k1_paillier_encrypted_message *op2,
    const secp256k1_paillier_pubkey *pubkey
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_PAILLIER_H */
