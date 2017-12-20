#ifndef SECP256K1_PAILLIER_H
#define SECP256K1_PAILLIER_H

#include "secp256k1.h"
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
HEPublicKey ::= SEQUENCE {
    version           INTEGER,
    modulus           INTEGER,  -- p * q
    generator         INTEGER   -- n + 1
}
*/
typedef struct {
    mpz_t modulus;
    mpz_t generator;
    mpz_t bigModulus;
} secp256k1_paillier_pubkey;

/**
HEPrivateKey ::= SEQUENCE {
    version           INTEGER,
    modulus           INTEGER,  -- p * q
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    generator         INTEGER,  -- n + 1
    privateExponent   INTEGER,  -- (p - 1) * (q - 1)
    coefficient       INTEGER   -- (inverse of privateExponent) mod (p * q)
}
*/
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
    secp256k1_paillier_pubkey *pubkey
);

secp256k1_paillier_privkey* secp256k1_paillier_privkey_create(void);
secp256k1_paillier_encrypted_message* secp256k1_paillier_message_create(void);
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
    generator         INTEGER,  -- n + 1
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
    generator         INTEGER   -- n + 1
}
*/
int secp256k1_paillier_pubkey_parse(
    secp256k1_paillier_pubkey *pubkey,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_paillier_message_parse(
    secp256k1_paillier_encrypted_message *message,
    const unsigned char *input,
    size_t inputlen
);

unsigned char* secp256k1_paillier_message_serialize(
    size_t *outputlen,
    secp256k1_paillier_encrypted_message *message
);

int secp256k1_paillier_encrypt(
    secp256k1_paillier_encrypted_message *res,
    const unsigned char *data,
    size_t lenght,
    secp256k1_paillier_pubkey *pubkey,
    secp256k1_paillier_nonce_function noncefp
);

void secp256k1_paillier_decrypt(mpz_t message, mpz_t cipher, secp256k1_paillier_privkey *privkey);

void secp256k1_paillier_mult(mpz_t res, mpz_t cipher, mpz_t scalar, secp256k1_paillier_pubkey *pubkey);

void secp256k1_paillier_add(mpz_t res, mpz_t op1, mpz_t op2, secp256k1_paillier_pubkey *pubkey);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_PAILLIER_H */
