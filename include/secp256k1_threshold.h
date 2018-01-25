#ifndef SECP256K1_THRESHOLD_H
#define SECP256K1_THRESHOLD_H

#include "secp256k1.h"
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Data structure that holds context information needed in multiple functions.
 *
 *  The purpose of signature params is to store information attached to a session
 *  of signature. It is possible to serialize this structure 
 *  (see secp256k1_threshold_params_serialize) to store information between 
 *  round of communication if needed.
 */
typedef struct {
    secp256k1_scalar k;
    secp256k1_scalar z;
    secp256k1_pubkey r;
} secp256k1_threshold_signature_params;

/** Data structure that holds the content of the first message in the protocol.
 *
 *  The first message used in the scheme is composed of two values encrypted
 *  with homomorphic Paillier cryptosystem. Alpha holds the inverse z1 (modulo n)  
 *  of the random value k1. Zeta holds the result of x1z1 (mod n). Both value
 *  need to be encrypted with the sender's Paillier public key. This message is
 *  used to start the signing protocol.
 */
typedef struct {
    secp256k1_paillier_encrypted_message *alpha;
    secp256k1_paillier_encrypted_message *zeta;
} secp256k1_threshold_call_msg;

/** Data structure that holds the content of the second message in the protocol.
 *
 *  The second message used in the scheme is composed of one point r2. The point
 *  is point associated with the private random value k2. This message is used
 *  to accept the signing call and challenge the initiator to give all the needed
 *  informations.
 */
typedef struct {
    secp256k1_pubkey r2;
} secp256k1_threshold_challenge_msg;

/** Data structure that holds the content of the third message in the protocol.
 *
 *  The third message used in the scheme is composed of one point r and a zero-
 *  knowledge proof pi. The point holds the result of the r2 tweaked with k1.
 *  The ZKP pi ensure that the value z1 is knowed by the prover, the plaintext
 *  of alpha and zeta are linked and are related to the partial public key holds
 *  by the prover (y1), the plaintext of alpha is z1, and the plaintext of zeta
 *  is x1z1. This message is used to respond to the challenger and send all
 *  information needed to start signing.
 */
typedef struct {
    secp256k1_pubkey r;
    secp256k1_eczkp_pi *pi;
} secp256k1_threshold_response_challenge_msg;

/** Data structure that holds the content of the forth message in the protocol.
 *
 *  The forth message used in the scheme is composed of two encrypted values and
 *  a second type of zero-knowledge proof. The first encrypted value (under the 
 *  initiator Paillier public key) holds the encrypted value s of the final 
 *  signature, the second message (encrypted under the sender Paillier public
 *  key) holds the secret value z2, the inverse of k2 mod n. The ZKP proves that
 *  the value z2 is knowed by the sender, z2 and x2z2 generate the partial public 
 *  key y2, the plaintext of the second encrypted message is z2, and the first
 *  encrypted message holds the final value of s.
 */
typedef struct {
    secp256k1_paillier_encrypted_message *mu;
    secp256k1_paillier_encrypted_message *mu2;
    secp256k1_eczkp_pi2 *pi2;
} secp256k1_threshold_terminate_msg;

/** Flags used to serialize the parameter strucutre, the short form avoid the
    serialization of the public key. */
#define SECP256K1_THRESHOLD_PARAMS_FULL 0x01
#define SECP256K1_THRESHOLD_PARAMS_SHORT 0x00

/** Clear a secp256k1 threshold parameter object.
 *
 *  In:      p: a pointer to the struct to clear.
 */
SECP256K1_API void secp256k1_threshold_params_clear(
    secp256k1_threshold_signature_params *p
) SECP256K1_ARG_NONNULL(1);

/** Initialize a secp256k1 threshold call message object.
 *
 *  In:      p: a pointer to the call message to initialize.
 */
SECP256K1_API void secp256k1_threshold_init_call_msg(
    secp256k1_threshold_call_msg *m
) SECP256K1_ARG_NONNULL(1);

/** Initialize a secp256k1 threshold challenge message object.
 *
 *  In:      p: a pointer to the challenge message to initialize.
 */
SECP256K1_API void secp256k1_threshold_init_challenge_msg(
    secp256k1_threshold_challenge_msg *m
) SECP256K1_ARG_NONNULL(1);

/** Initialize a secp256k1 threshold response challenge message object.
 *
 *  In:      p: a pointer to the response challenge message to initialize.
 */
SECP256K1_API void secp256k1_threshold_init_response_challenge_msg(
    secp256k1_threshold_response_challenge_msg *m
) SECP256K1_ARG_NONNULL(1);

/** Initialize a secp256k1 threshold terminate message object.
 *
 *  In:      p: a pointer to the terminate message to initialize.
 */
SECP256K1_API void secp256k1_threshold_init_terminate_msg(
    secp256k1_threshold_terminate_msg *m
) SECP256K1_ARG_NONNULL(1);

/** Parse a parameter string into the parameter object.
 *
 *  Returns: 1 if the parameter object was fully valid.
 *           0 if the parameter object could not be parsed or is invalid.
 *  Args: ctx:      a secp256k1 context object.
 *  Out:  p:        pointer to a parameter object. If 1 is returned, it is set to a
 *                  parsed version of input.
 *  In:   input:    pointer to a serialized parameter object.
 *        inputlen: length of the array pointed to by input.
 *
 *  This function supports parsing DER serialization of a threshold parameter
 *  sequence.
 *
 *  ThresholdParameters ::= SEQUENCE {
 *      k           OCTET STRING,
 *      z           OCTET STRING,
 *      r           OCTET STRING
 *  }
 */
SECP256K1_API int secp256k1_threshold_params_parse(
    const secp256k1_context *ctx,
    secp256k1_threshold_signature_params *p,
    const unsigned char *input,
    size_t inputlen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a parameter object into a serialized byte sequence.
 *
 *  Returns: a pointer to a serialized byte sequence.
 *  Args: ctx:         a secp256k1 context object.
 *  Out:  outputlen:   the lenght of the serialized byte sequence.
 *  In:   p:           pointer to the parameter object to serialize.
 *        flag:        SECP256K1_THRESHOLD_PARAMS_FULL if the point r is set
 *                     or SECP256K1_THRESHOLD_PARAMS_SHORT if the point is zero.
 *
 *  This function export the threshold parameter into a DER sequence.
 *
 *  ThresholdParameters ::= SEQUENCE {
 *      k           OCTET STRING,
 *      z           OCTET STRING,
 *      r           OCTET STRING
 *  }
 */
SECP256K1_API unsigned char* secp256k1_threshold_params_serialize(
    const secp256k1_context *ctx,
    size_t *outputlen,
    const secp256k1_threshold_signature_params *p,
    int flag
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a call message string into the call message object.
 *
 *  Returns: 1 if the call message object was fully valid.
 *           0 if the call message object could not be parsed or is invalid.
 *  Out:  m:        pointer to a call msg object. If 1 is returned, it is set to
 *                  a parsed version of input.
 *  In:   input:    pointer to a serialized call message object.
 *        inputlen: length of the array pointed to by input.
 *
 *  This function supports parsing DER serialization of a threshold call message
 *  sequence.
 *
 *  ThresholdCallMsg ::= SEQUENCE {
 *      alpha         HEEncryptedMessage,
 *      zeta          HEEncryptedMessage
 *  }
 */
SECP256K1_API int secp256k1_threshold_call_msg_parse(
    secp256k1_threshold_call_msg *m,
    const unsigned char *input,
    size_t inputlen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Serialize a call message object into a serialized byte sequence.
 *
 *  Returns: a pointer to a serialized byte sequence.
 *  Out:  outputlen:   the lenght of the serialized byte sequence.
 *  In:   m:           pointer to the call message object to serialize.
 *
 *  This function export the threshold call message into a DER sequence.
 *
 *  ThresholdCallMsg ::= SEQUENCE {
 *      alpha         HEEncryptedMessage,
 *      zeta          HEEncryptedMessage
 *  }
 */
SECP256K1_API unsigned char* secp256k1_threshold_call_msg_serialize(
    size_t *outputlen,
    const secp256k1_threshold_call_msg *m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Parse a challenge message string into the challenge message object.
 *
 *  Returns: 1 if the challenge message object was fully valid.
 *           0 if the challenge message object could not be parsed or is invalid.
 *  Args: ctx:      a secp256k1 context object.
 *  Out:  m:        pointer to a challenge msg object. If 1 is returned, it is
 *                  set to a parsed version of input.
 *  In:   input:    pointer to a serialized challenge message object.
 *        inputlen: length of the array pointed to by input.
 *
 *  This function supports parsing DER serialization of a threshold challenge 
 *  message sequence.
 *
 *  ThresholdChallengeMsg ::= SEQUENCE {
 *      r2             OCTET STRING
 *  }
 */
SECP256K1_API int secp256k1_threshold_challenge_msg_parse(
    const secp256k1_context *ctx,
    secp256k1_threshold_challenge_msg *m,
    const unsigned char *input,
    size_t inputlen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a challenge message object into a serialized byte sequence.
 *
 *  Returns: a pointer to a serialized byte sequence.
 *  Args: ctx:         a secp256k1 context object.
 *  Out:  outputlen:   the lenght of the serialized byte sequence.
 *  In:   m:           pointer to the challenge message object to serialize.
 *
 *  This function export the threshold challenge message into a DER sequence.
 *
 *  ThresholdChallengeMsg ::= SEQUENCE {
 *      r2             OCTET STRING
 *  }
 */
SECP256K1_API unsigned char* secp256k1_threshold_challenge_msg_serialize(
    const secp256k1_context *ctx,
    size_t *outputlen,
    const secp256k1_threshold_challenge_msg *m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a response challenge message string into the response challenge object.
 *
 *  Returns: 1 if the response challenge message object was fully valid.
 *           0 if the response challenge message object could not be parsed or 
 *             is invalid.
 *  Args: ctx:      a secp256k1 context object.
 *  Out:  m:        pointer to a response challenge msg object. If 1 is returned,
 *                  it is set to a parsed version of input.
 *  In:   input:    pointer to a serialized response challenge message object.
 *        inputlen: length of the array pointed to by input.
 *
 *  This function supports parsing DER serialization of a threshold response  
 *  challenge message sequence.
 *
 *  ThresholdResponseChallengeMsg ::= SEQUENCE {
 *      r              OCTET STRING,
 *      pi             ECZKPPi
 *  }
 */
SECP256K1_API int secp256k1_threshold_response_challenge_msg_parse(
    const secp256k1_context *ctx,
    secp256k1_threshold_response_challenge_msg *m,
    const unsigned char *input,
    size_t inputlen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a response challenge message object into a serialized byte sequence.
 *
 *  Returns: a pointer to a serialized byte sequence.
 *  Args: ctx:         a secp256k1 context object.
 *  Out:  outputlen:   the lenght of the serialized byte sequence.
 *  In:   m:           pointer to the response challenge message object to 
 *                     serialize.
 *
 *  This function export the threshold response challenge message into a DER sequence.
 *
 *  ThresholdResponseChallengeMsg ::= SEQUENCE {
 *      r              OCTET STRING,
 *      pi             ECZKPPi
 *  }
 */
SECP256K1_API unsigned char* secp256k1_threshold_response_challenge_msg_serialize(
    const secp256k1_context *ctx,
    size_t *outputlen,
    const secp256k1_threshold_response_challenge_msg *m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a terminate string into the challenge object.
 *
 *  Returns: 1 if the terminate object was fully valid.
 *           0 if the terminate object could not be parsed or is invalid.
 *  Args: ctx:      a secp256k1 context object.
 *  Out:  m:        pointer to a challenge msg object. If 1 is returned,
 *                  it is set to a parsed version of input.
 *  In:   input:    pointer to a serialized terminate object.
 *        inputlen: length of the array pointed to by input.
 *
 *  This function supports parsing DER serialization of a threshold  
 *  terminate sequence.
 *
 *  ThresholdTerminateMsg ::= SEQUENCE {
 *      mu             HEEncryptedMessage,
 *      mu2            HEEncryptedMessage,
 *      pi2            ECZKPPiPrim
 *  }
 */
SECP256K1_API int secp256k1_threshold_terminate_msg_parse(
    const secp256k1_context *ctx,
    secp256k1_threshold_terminate_msg *m,
    const unsigned char *input,
    size_t inputlen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a terminate message object into a serialized byte sequence.
 *
 *  Returns: a pointer to a serialized byte sequence.
 *  Args: ctx:         a secp256k1 context object.
 *  Out:  outputlen:   the lenght of the serialized byte sequence.
 *  In:   m:           pointer to the terminate message object to 
 *                     serialize.
 *
 *  This function export the threshold terminate message into a DER sequence.
 *
 *  ThresholdTerminateMsg ::= SEQUENCE {
 *      mu             HEEncryptedMessage,
 *      mu2            HEEncryptedMessage,
 *      pi2            ECZKPPiPrim
 *  }
 */
SECP256K1_API unsigned char* secp256k1_threshold_terminate_msg_serialize(
    const secp256k1_context *ctx,
    size_t *outputlen,
    const secp256k1_threshold_terminate_msg *m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a threshol private key string into all the data structure needed to sign.
 *
 *  Returns: 1 if the threshold private key object was fully valid.
 *           0 if the threshold private key object could not be parsed or is invalid.
 *  Args: ctx:           a secp256k1 context object.
 *  Out:  secshare:      secret share key.
 *        paillierkey:   private homomorphic encryption paillier key.
 *        pairedkey:     paired paillier public key in the scheme.
 *        zkp:           set of parameters for the zero-knowledge proofs.
 *        pairedpubkey:  paired ECDSA public key.
 *        pubkey:        full ECDSA public key which verify signatures.
 *  In:   input:         pointer to a serialized threshold private key object.
 *        inputlen:      length of the array pointed to by input.
 *
 *  This function supports parsing DER serialization of a threshold private key  
 *  sequence.
 *
 *  ThresholdECPrivateKey ::= SEQUENCE {
 *      version              INTEGER,
 *      privateShare         OCTET STRING,
 *      privateEnc           HEPrivateKey,
 *      pairedPublicEnc      HEPublicKey,
 *      zkpParameters        ZKPParameter,
 *      pairedPublicShare    OCTET STRING,
 *      publicKey            OCTET STRING
 *  }
 */ 
SECP256K1_API int secp256k1_threshold_privkey_parse(
    const secp256k1_context *ctx,
    secp256k1_scalar *secshare,
    secp256k1_paillier_privkey *paillierkey,
    secp256k1_paillier_pubkey *pairedkey,
    secp256k1_eczkp_parameter *zkp,
    secp256k1_pubkey *pairedpubkey,
    secp256k1_pubkey *pubkey,
    const unsigned char *input,
    size_t inputlen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4)
  SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7);

/** Start the protocol of signing and create the call message.
 *
 *  Returns: 1 call message created, 0 otherwise
 *  Args: ctx:           a secp256k1 context object.
 *  Out:  callmsg:       a pointer to the resulting message.
 *        params:        a pointer to the parameters, parameters z and k are set.
 *  In:   secshare:      a pointer to the secret shared key.
 *        paillierkey:   a pointer to the paillier key used to encrypt the first
 *                       values.
 *        msg32:         a pointer to the hash 32 bytes sequence to sign.
 *        noncefp:       a fonction pointer to generate the nonce k1.
 *        pnoncefp:      a fonction pointer to encrypt values with paillier.
 *
 *  This function generates the parameters k1 and k1^-1 (z1), then encrypt z1 and
 *  x1z1 and create the call message.
 */ 
SECP256K1_API int secp256k1_threshold_call_create(
    const secp256k1_context *ctx,
    secp256k1_threshold_call_msg *callmsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_scalar *secshare,
    const secp256k1_paillier_pubkey *paillierkey,
    const unsigned char *msg32,
    const secp256k1_nonce_function noncefp,
    const secp256k1_paillier_nonce_function pnoncefp
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4)
  SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Call this functioin when the call message is received to create the challenge.
 *
 *  Returns: 1 call msg parsed and challenge message created, 0 otherwise
 *  Args: ctx:           a secp256k1 context object.
 *  Out:  challengemsg:  a pointer to the resulting challenge message.
 *        params:        a pointer to the parameters, parameters z, k, and r are set.
 *  In:   callmsg:       a pointer to the received call message.
 *        secshare:      a pointer the the secret shared key.
 *        msg32:         a pointer to the hash 32 bytes sequence to sign.
 *        noncefp:       a fonction pointer to generate the nonce k2.
 *
 *  This function generates the parameters k2 and k2^-1 (z2), then compute the
 *  public value r2 of k2 and create the challenge message.
 */ 
SECP256K1_API int secp256k1_threshold_call_received(
    const secp256k1_context *ctx,
    secp256k1_threshold_challenge_msg *challengemsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_threshold_call_msg *callmsg,
    const secp256k1_scalar *secshare,
    const unsigned char *msg32,
    const secp256k1_nonce_function noncefp
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4)
  SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Call this functioin when the challenge message is received to create the response.
 *
 *  Returns: 1 challenge msg parsed and response challenge message created, 0 otherwise
 *  Args: ctx:           a secp256k1 context object.
 *  Out:  respmsg:       a pointer to the resulting response challenge message.
 *        params:        a pointer to the parameters, parameters r is set.
 *  In:   secshare:      a pointer the the secret shared key.
 *        challengemsg:  a pointer to the received challenge message.
 *        zkp:           a pointer to zero-knowledge proofs parameters.
 *        paillierkey:   a pointer to the paillier key used to encrypt the first
 *                       values.
 *        rdnfp:         a fonction pointer to generate the zkp.
 *
 *  This function compute the public point r of the signature and create the 
 *  first ZKP.
 */ 
SECP256K1_API int secp256k1_threshold_challenge_received(
    const secp256k1_context *ctx,
    secp256k1_threshold_response_challenge_msg *respmsg,
    secp256k1_threshold_signature_params *params,
    const secp256k1_scalar *secshare,
    const secp256k1_threshold_challenge_msg *challengemsg,
    const secp256k1_threshold_call_msg *callmsg,
    const secp256k1_eczkp_parameter *zkp,
    const secp256k1_paillier_pubkey *paillierkey,
    const secp256k1_eczkp_rdn_function rdnfp
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4)
  SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/** Call this functioin when the response challenge message is received to create
 *  the terminate message.
 *
 *  Returns: 1 response challenge msg parsed and terminate msg created, 0 otherwise
 *  Args: ctx:           a secp256k1 context object.
 *  Out:  termsg:        a pointer to the resulting terminate message.
 *        params:        a pointer to the parameters, parameters r is set.
 *  In:   secshare:      a pointer the the secret shared key.
 *        callmsg:       a pointer to the received call message.
 *        challengemsg:  a pointer to the generated challenge message.
 *        respmsg:       a pointer to the received response challenge message.
 *        msg32:         a pointer to the hash 32 bytes sequence to sign.
 *        zkp:           a pointer to zero-knowledge proofs parameters.
 *        pairedkey:     a pointer to the paillier key used to encrypt the first
 *                       values.
 *        p2:            a pointer to the paillier key used to encrypt z2.
 *        pairedshare:   a pointer to the public paired share.
 *        noncefp:       a fonction pointer to encrypt values with paillier.
 *        rdnfp:         a fonction pointer to generate the zkp.
 *
 *  This function verify the first zero-knowledge proof, compute the encrypted 
 *  signature s over the cipher mu with alpha and zeta holds in the call message,
 *  and create the second zero-knowledge proof.
 */ 
SECP256K1_API int secp256k1_threshold_response_challenge_received(
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
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4)
  SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8)
  SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(11) SECP256K1_ARG_NONNULL(12);

/** Call this functioin when the terminate message is received to retreive the signature.
 *
 *  Returns: 1 terminate msg parsed and signature created and validated, 0 otherwise
 *  Args: ctx:           a secp256k1 context object.
 *  Out:  sig:           a pointer to the final signature.
 *  In:   callmsg:       a pointer to the generated call message.
 *        challengemsg:  a pointer to the received challenge message.
 *        termsg:        a pointer to the received terminate message.
 *        params:        a pointer to the signature parameters.
 *        zkp:           a pointer to zero-knowledge proofs parameters.
 *        p:             a pointer to the paillier private key used to encrypt 
 *                       the first values.
 *        pairedkey:     a pointer to the paired paillier key used to encrypt z2.
 *        pub:           a pointer to the public key that validates signature.
 *        pairedpub:     a pointer to the public paired share.
 *
 *  This function verify the second zero-knowledge proof, decrypt the ciphertext 
 *  mu and recover the final signature.
 */ 
SECP256K1_API int secp256k1_threshold_terminate_received(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature *sig,
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
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4)
  SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8)
  SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(11);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_THRESHOLD_H */
