#ifndef SECP256K1_THRESHOLD_H
#define SECP256K1_THRESHOLD_H

#include "secp256k1.h"
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
ThresholdParameters ::= SEQUENCE {
    k           OCTET STRING,
    z           OCTET STRING,
    r           OCTET STRING
}
*/
typedef struct {
    secp256k1_scalar k;
    secp256k1_scalar z;
    secp256k1_pubkey r;
} secp256k1_threshold_signature_params;

/**
ThresholdCallMsg ::= SEQUENCE {
    alpha         HEEncryptedMessage,
    zeta          HEEncryptedMessage
}
*/
typedef struct {
    secp256k1_paillier_encrypted_message *alpha;
    secp256k1_paillier_encrypted_message *zeta;
} secp256k1_threshold_call_msg;

/**
ThresholdChallengeMsg ::= SEQUENCE {
    r2             OCTET STRING
}
*/
typedef struct {
    secp256k1_pubkey r2;
} secp256k1_threshold_challenge_msg;

/**
ThresholdResponseChallengeMsg ::= SEQUENCE {
    r              OCTET STRING,
    pi             ECZKPPi
}
*/
typedef struct {
    secp256k1_pubkey r;
    secp256k1_eczkp_pi *pi;
} secp256k1_threshold_response_challenge_msg;

/**
ThresholdTerminateMsg ::= SEQUENCE {
    mu             HEEncryptedMessage,
    mu2            HEEncryptedMessage,
    pi2            ECZKPPiPrim
}
*/
typedef struct {
    secp256k1_paillier_encrypted_message *mu;
    secp256k1_paillier_encrypted_message *mu2;
    secp256k1_eczkp_pi2 *pi2;
} secp256k1_threshold_terminate_msg;

#define SECP256K1_THRESHOLD_PARAMS_FULL 0x01
#define SECP256K1_THRESHOLD_PARAMS_SHORT 0x00

void secp256k1_threshold_params_clear(secp256k1_threshold_signature_params *p);

void secp256k1_threshold_init_call_msg(secp256k1_threshold_call_msg *m);

void secp256k1_threshold_init_challenge_msg(secp256k1_threshold_challenge_msg *m);

void secp256k1_threshold_init_response_challenge_msg(secp256k1_threshold_response_challenge_msg *m);

void secp256k1_threshold_init_terminate_msg(secp256k1_threshold_terminate_msg *m);

int secp256k1_threshold_params_parse(
    const secp256k1_context* ctx,
    secp256k1_threshold_signature_params *p,
    const unsigned char *input,
    size_t inputlen
);

unsigned char* secp256k1_threshold_params_serialize(
    const secp256k1_context* ctx,
    size_t *outputlen,
    const secp256k1_threshold_signature_params *p,
    int flag
);

int secp256k1_threshold_call_msg_parse(
    secp256k1_threshold_call_msg *m,
    const unsigned char *input,
    size_t inputlen
);

unsigned char* secp256k1_threshold_call_msg_serialize(
    size_t *outputlen,
    const secp256k1_threshold_call_msg *m
);

int secp256k1_threshold_challenge_msg_parse(
    const secp256k1_context* ctx,
    secp256k1_threshold_challenge_msg *m,
    const unsigned char *input,
    size_t inputlen
);

unsigned char* secp256k1_threshold_challenge_msg_serialize(
    const secp256k1_context* ctx,
    size_t *outputlen,
    const secp256k1_threshold_challenge_msg *m
);

int secp256k1_threshold_response_challenge_msg_parse(
    const secp256k1_context* ctx,
    secp256k1_threshold_response_challenge_msg *m,
    const unsigned char *input,
    size_t inputlen
);

unsigned char* secp256k1_threshold_response_challenge_msg_serialize(
    const secp256k1_context* ctx,
    size_t *outputlen,
    const secp256k1_threshold_response_challenge_msg *m
);

int secp256k1_threshold_terminate_msg_parse(
    const secp256k1_context* ctx,
    secp256k1_threshold_terminate_msg *m,
    const unsigned char *input,
    size_t inputlen
);

unsigned char* secp256k1_threshold_terminate_msg_serialize(
    const secp256k1_context* ctx,
    size_t *outputlen,
    const secp256k1_threshold_terminate_msg *m
);

/*
ThresholdECPrivateKey ::= SEQUENCE {
    version              INTEGER,
    privateShare         OCTET STRING,
    privateEnc           HEPrivateKey,
    pairedPublicEnc      HEPublicKey,
    zkpParameters        ZKPParameter,
    pairedPublicShare    OCTET STRING,
    publicKey            OCTET STRING,
    parameters       [0] ECParameters {{ NamedCurve }} OPTIONAL
}*/ 
int secp256k1_threshold_privkey_parse(
    const secp256k1_context *ctx,
    secp256k1_scalar *secshare,
    secp256k1_paillier_privkey *paillierkey,
    secp256k1_paillier_pubkey *pairedkey,
    secp256k1_eczkp_parameter *zkp,
    secp256k1_pubkey *pairedpubkey,
    secp256k1_pubkey *pubkey,
    const unsigned char *input,
    size_t inputlen
);

/* ALICE 1 */
int secp256k1_threshold_call_create(
    const secp256k1_context *ctx,
    secp256k1_threshold_call_msg *callmsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_scalar *secshare,
    const secp256k1_paillier_pubkey *paillierkey,
    const unsigned char *msg32,
    const secp256k1_paillier_nonce_function pnoncefp
);

/* BOB 1 */
int secp256k1_threshold_call_received(
    const secp256k1_context *ctx,
    secp256k1_threshold_challenge_msg *challengemsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_threshold_call_msg *callmsg,
    const secp256k1_scalar *secshare,
    const unsigned char *msg32
);

/* ALICE 2 */
int secp256k1_threshold_challenge_received(
    const secp256k1_context *ctx,
    secp256k1_threshold_response_challenge_msg *respmsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_scalar *secshare,
    const secp256k1_threshold_challenge_msg *challengemsg,
    const secp256k1_threshold_call_msg *callmsg,
    const secp256k1_eczkp_parameter *zkp,
    const secp256k1_paillier_pubkey *paillierkey,
    const secp256k1_eczkp_rdn_function rdnfp
);

/* BOB 2 */
int secp256k1_threshold_response_challenge_received(
    const secp256k1_context *ctx,
    secp256k1_threshold_terminate_msg *termsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_scalar *secshare,
    const secp256k1_threshold_call_msg *callmsg,
    const secp256k1_threshold_challenge_msg *challengemsg,
    const secp256k1_threshold_response_challenge_msg *respmsg,
    const unsigned char *msg32,
    const secp256k1_eczkp_parameter *zkp,
    const secp256k1_paillier_pubkey *pairedkey,
    const secp256k1_paillier_pubkey *p2,
    const secp256k1_pubkey *pairedshare,
    const secp256k1_paillier_nonce_function noncefp,
    const secp256k1_eczkp_rdn_function rdnfp
);

 /* ALICE 3 */
int secp256k1_threshold_terminate_received(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature* sig,
    const secp256k1_threshold_call_msg *callmsg,
    const secp256k1_threshold_challenge_msg *challengemsg,
    const secp256k1_threshold_terminate_msg *termsg,
    const secp256k1_threshold_signature_params *params,
    const secp256k1_eczkp_parameter *zkp,
    const secp256k1_paillier_privkey *p,
    const secp256k1_paillier_pubkey *pairedkey,
    const secp256k1_pubkey *pub,
    const secp256k1_pubkey *pairedpub,
    const unsigned char *msg32
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_THRESHOLD_H */
