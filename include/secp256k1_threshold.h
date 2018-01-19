#ifndef SECP256K1_THRESHOLD_H
#define SECP256K1_THRESHOLD_H

#include "secp256k1.h"
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    secp256k1_scalar k;
    secp256k1_scalar z;
    secp256k1_pubkey r;
} secp256k1_threshold_signature_params;

typedef struct {
    secp256k1_paillier_encrypted_message *alpha;
    secp256k1_paillier_encrypted_message *zeta;
} secp256k1_threshold_call_msg;

typedef struct {
    secp256k1_pubkey r2;
} secp256k1_threshold_challenge_msg;

typedef struct {
    secp256k1_pubkey r;
    secp256k1_eczkp_pi *pi;
} secp256k1_threshold_response_challenge_msg;

typedef struct {
    secp256k1_paillier_encrypted_message *mu;
    secp256k1_paillier_encrypted_message *mu2;
    secp256k1_eczkp_pi2 *pi2;
} secp256k1_threshold_terminate_msg;

secp256k1_threshold_call_msg* secp256k1_threshold_call_msg_create(void);
/*void secp256k1_threshold_call_msg_destroy(secp256k1_threshold_call_msg* msg);*/

/*
ThresholdECPrivateKey ::= SEQUENCE {
    version              INTEGER,
    privateShare         OCTET STRING,
    privateEnc           HEPrivateKey,
    pairedPublicEnc      HEPublicKey,
    publicKey            OCTET STRING,
    parameters       [0] ECParameters {{ NamedCurve }} OPTIONAL
}*/ 
int secp256k1_threshold_privkey_parse(
    const secp256k1_context *ctx,
    secp256k1_scalar *secshare,
    secp256k1_paillier_privkey *paillierkey,
    secp256k1_paillier_pubkey *pairedkey,
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
int secp256k1_threshold_call_recieved(
    const secp256k1_context *ctx,
    secp256k1_threshold_challenge_msg *challengemsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_threshold_call_msg *callmsg,
    const secp256k1_scalar *secshare,
    const unsigned char *msg32
);

/* ALICE 2 */
int secp256k1_threshold_challenge_recieved(
    const secp256k1_context *ctx,
    secp256k1_threshold_response_challenge_msg *respmsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_threshold_challenge_msg *challengemsg
);

/* BOB 2 */
int secp256k1_threshold_response_challenge_recieved(
    const secp256k1_context *ctx,
    secp256k1_threshold_terminate_msg *termsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_scalar *secshare,
    const secp256k1_threshold_call_msg *callmsg,
    const secp256k1_threshold_response_challenge_msg *respmsg,
    const unsigned char *msg32,
    const secp256k1_paillier_pubkey *p1,
    const secp256k1_paillier_pubkey *p2,
    const secp256k1_paillier_nonce_function noncefp
);

 /* ALICE 3 */
int secp256k1_threshold_terminate_recieved(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature* sig,
    const secp256k1_threshold_terminate_msg *termsg,
    const secp256k1_threshold_signature_params *params,
    const secp256k1_paillier_privkey *p,
    const secp256k1_pubkey *pub,
    const unsigned char *msg32
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_THRESHOLD_H */
