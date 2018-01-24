#ifndef SECP256K1_ECZKP_H
#define SECP256K1_ECZKP_H

#include "secp256k1.h"
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
ZKPParameter ::= SEQUENCE {
    modulus            INTEGER,
    h1                 INTEGER,
    h2                 INTEGER
}*/
typedef struct {
    mpz_t modulus;
    mpz_t h1;
    mpz_t h2;
} secp256k1_eczkp_parameter;

/**
ECZKPPi ::= SEQUENCE {
    version            INTEGER,
    z1                 INTEGER,
    z2                 INTEGER,
    y                  OCTET STRING,
    e                  INTEGER,
    s1                 INTEGER,
    s2                 INTEGER,
    s3                 INTEGER,
    t1                 INTEGER,
    t2                 INTEGER,
    t3                 INTEGER,
    t4                 INTEGER
}*/
typedef struct {
    mpz_t version;
    mpz_t z1;
    mpz_t z2;
    secp256k1_pubkey y;
    mpz_t e;
    mpz_t s1;
    mpz_t s2;
    mpz_t s3;
    mpz_t t1;
    mpz_t t2;
    mpz_t t3;
    mpz_t t4;
} secp256k1_eczkp_pi;

/*
ECZKPPiPrim ::= SEQUENCE {
    version            INTEGER,
    z1                 INTEGER,
    z2                 INTEGER,
    z3                 INTEGER,
    y                  OCTET STRING,
    e                  INTEGER,
    s1                 INTEGER,
    s2                 INTEGER,
    s3                 INTEGER,
    s4                 INTEGER,
    t1                 INTEGER,
    t2                 INTEGER,
    t3                 INTEGER,
    t4                 INTEGER,
    t5                 INTEGER,
    t6                 INTEGER,
    t7                 INTEGER
}*/
typedef struct {
    mpz_t version;
    mpz_t z1;
    mpz_t z2;
    mpz_t z3;
    secp256k1_pubkey y;
    mpz_t e;
    mpz_t s1;
    mpz_t s2;
    mpz_t s3;
    mpz_t s4;
    mpz_t t1;
    mpz_t t2;
    mpz_t t3;
    mpz_t t4;
    mpz_t t5;
    mpz_t t6;
    mpz_t t7;
} secp256k1_eczkp_pi2;

typedef int (*secp256k1_eczkp_rdn_function)(
    mpz_t res,
    const mpz_t max,
    const int flag
);

#define SECP256K1_THRESHOLD_RND_INV 0x01
#define SECP256K1_THRESHOLD_RND_STD 0x00

secp256k1_eczkp_parameter* secp256k1_eczkp_parameter_create(void);

void secp256k1_eczkp_parameter_destroy(secp256k1_eczkp_parameter *eczkp);

secp256k1_eczkp_pi* secp256k1_eczkp_pi_create(void);

void secp256k1_eczkp_pi_destroy(secp256k1_eczkp_pi *eczkp_pi);

secp256k1_eczkp_pi2* secp256k1_eczkp_pi2_create(void);

void secp256k1_eczkp_pi2_destroy(secp256k1_eczkp_pi2 *eczkp_pi2);

/**
ZKPParameter ::= SEQUENCE {
    modulus            INTEGER,
    h1                 INTEGER,
    h2                 INTEGER
}
*/
int secp256k1_eczkp_parameter_parse(
    secp256k1_eczkp_parameter *eczkp,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_eczkp_pi_parse(
    const secp256k1_context *ctx,
    secp256k1_eczkp_pi *eczkp_pi,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_eczkp_pi2_parse(
    const secp256k1_context *ctx,
    secp256k1_eczkp_pi2 *eczkp_pi2,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_eczkp_pi_generate(
    const secp256k1_context *ctx,
    secp256k1_eczkp_pi *pi,
    const secp256k1_eczkp_parameter *zkp,
    const secp256k1_paillier_encrypted_message *m1,
    const secp256k1_paillier_encrypted_message *m2,
    const secp256k1_scalar *sx1,
    const secp256k1_scalar *sx2,
    const secp256k1_pubkey *c,
    const secp256k1_pubkey *w1,
    const secp256k1_pubkey *w2,
    const secp256k1_paillier_pubkey *pubkey,
    const secp256k1_eczkp_rdn_function rdnfp
);

int secp256k1_eczkp_pi_verify(
    const secp256k1_context *ctx,
    secp256k1_eczkp_pi *pi,
    const secp256k1_eczkp_parameter *zkp,
    const secp256k1_paillier_encrypted_message *m1,
    const secp256k1_paillier_encrypted_message *m2,
    const secp256k1_pubkey *c,
    const secp256k1_pubkey *w1,
    const secp256k1_pubkey *w2,
    const secp256k1_paillier_pubkey *pubkey
);

int secp256k1_eczkp_pi2_generate(
    const secp256k1_context *ctx,
    secp256k1_eczkp_pi2 *pi2,
    const secp256k1_eczkp_parameter *zkp,
    const secp256k1_paillier_encrypted_message *m1,
    const secp256k1_paillier_encrypted_message *m2,
    const secp256k1_paillier_encrypted_message *m3,
    const secp256k1_paillier_encrypted_message *m4,
    const secp256k1_paillier_encrypted_message *r,
    const secp256k1_scalar *sx1,
    const secp256k1_scalar *sx2,
    const mpz_t x3,
    const secp256k1_scalar *sx4,
    const secp256k1_scalar *sx5,
    const secp256k1_pubkey *c,
    const secp256k1_pubkey *w2,
    const secp256k1_paillier_pubkey *pairedkey,
    const secp256k1_paillier_pubkey *pubkey,
    const secp256k1_eczkp_rdn_function rdnfp
);

int secp256k1_eczkp_pi2_verify(
    const secp256k1_context *ctx,
    secp256k1_eczkp_pi2 *pi2,
    const secp256k1_eczkp_parameter *zkp,
    const secp256k1_paillier_encrypted_message *m1,
    const secp256k1_paillier_encrypted_message *m2,
    const secp256k1_paillier_encrypted_message *m3,
    const secp256k1_paillier_encrypted_message *m4,
    const secp256k1_pubkey *c,
    const secp256k1_pubkey *w2,
    const secp256k1_paillier_pubkey *pubkey,
    const secp256k1_paillier_pubkey *pairedkey
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECZKP_H */
