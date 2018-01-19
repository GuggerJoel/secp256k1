/**********************************************************************
 * Copyright (c) 2017 Joel Gugger                                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_THRESHOLD_MAIN_H
#define SECP256K1_MODULE_THRESHOLD_MAIN_H

#include "include/secp256k1_threshold.h"
#include "src/modules/threshold/der_impl.h"


secp256k1_threshold_call_msg* secp256k1_threshold_call_msg_create(void) {
    secp256k1_threshold_call_msg *msg = malloc(sizeof(*msg));
    msg->alpha = secp256k1_paillier_message_create();
    msg->zeta = secp256k1_paillier_message_create();
    return msg;
}

/*secp256k1_threshold_challenge_msg *challenge_msg = secp256k1_threshold_challenge_msg_create(void) {
    secp256k1_threshold_challenge_msg *msg = malloc(sizeof(*msg));
    return msg;
}*/

int secp256k1_threshold_privkey_parse(const secp256k1_context *ctx, secp256k1_scalar *secshare, secp256k1_paillier_privkey *paillierkey, secp256k1_paillier_pubkey *pairedkey, secp256k1_pubkey *pubkey, const unsigned char *input, size_t inputlen) {
    unsigned char data[65];
    unsigned long start, offset, lenght, inlen;
    mpz_t version;
    int overflow = 0;
    start = offset = lenght = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        mpz_init(version);
        /* Version MUST be set to 1 */
        if (secp256k1_der_parse_int(input, inputlen, &start, version, &offset) 
            && mpz_cmp_ui(version, 1) == 0) {
            mpz_clear(version);
            /*
            ThresholdECPrivateKey ::= SEQUENCE {
                version              INTEGER,
                privateShare         OCTET STRING,
                privateEnc           HEPrivateKey,
                pairedPublicEnc      HEPublicKey,
                publicKey            OCTET STRING,
                parameters       [0] ECParameters {{ NamedCurve }} OPTIONAL
            }*/ 
            if (!secp256k1_der_parse_octet_string(input, inputlen, 32, &start, data, &offset)) {
                return 0;
            }
            secp256k1_scalar_set_b32(secshare, data, &overflow);

            secp256k1_der_parse_struct_len(&input[start], &inlen);
            if (!secp256k1_paillier_privkey_parse(paillierkey, NULL, &input[start], inlen)) {
                return 0;
            }
            start += inlen;
            secp256k1_der_parse_struct_len(&input[start], &inlen);
            if (!secp256k1_paillier_pubkey_parse(pairedkey, &input[start], inlen)) {
                return 0;
            }
            start += inlen;
            if (!secp256k1_der_parse_octet_string(input, inputlen, 65, &start, data, &offset)
                || !secp256k1_ec_pubkey_parse(ctx, pubkey, data, 65)) {
                return 0;
            }

            return 1;

        } else { mpz_clear(version); }
    }
    return 0;
}

int secp256k1_threshold_call_create(const secp256k1_context *ctx, secp256k1_threshold_call_msg *callmsg, secp256k1_threshold_signature_params *params, const secp256k1_scalar *secshare, const secp256k1_paillier_pubkey *paillierkey, const unsigned char *msg32, const secp256k1_paillier_nonce_function pnoncefp) {
    secp256k1_scalar privinv;
    secp256k1_nonce_function noncefp;
    int ret = 0;
    int overflow = 0;
    unsigned char nonce32[32];
    unsigned char sec32[32];
    unsigned int count = 0;

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(callmsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(secshare != NULL);
    ARG_CHECK(paillierkey != NULL);
    ARG_CHECK(msg32 != NULL);
    noncefp = secp256k1_nonce_function_default;
    secp256k1_scalar_get_b32(sec32, secshare);
    while (1) {
        ret = noncefp(nonce32, msg32, sec32, NULL, NULL, count);
        if (!ret) {
            break;
        }
        secp256k1_scalar_set_b32(&params->k, nonce32, &overflow);
        if (!overflow && !secp256k1_scalar_is_zero(&params->k)) {
            secp256k1_scalar_inverse(&params->z, &params->k); /* z1 */
            secp256k1_scalar_mul(&privinv, &params->z, secshare); /* x1z1 */
            callmsg->alpha = secp256k1_paillier_message_create();
            callmsg->zeta = secp256k1_paillier_message_create();
            if (secp256k1_paillier_encrypt_scalar(callmsg->alpha, &params->z, paillierkey, pnoncefp) 
                && secp256k1_paillier_encrypt_scalar(callmsg->zeta, &privinv, paillierkey, pnoncefp)) {
                break;
            }
        }
        count++;
    }
    memset(nonce32, 0, 32);
    memset(sec32, 0, 32);
    secp256k1_scalar_clear(&privinv);
    return ret;
}

int secp256k1_threshold_call_recieved(const secp256k1_context *ctx, secp256k1_threshold_challenge_msg *challengemsg, secp256k1_threshold_signature_params *params, const secp256k1_threshold_call_msg *callmsg, const secp256k1_scalar *secshare, const unsigned char *msg32) {
    secp256k1_nonce_function noncefp;
    int ret = 0;
    int overflow = 0;
    unsigned int count = 0;
    unsigned char k32[32];
    unsigned char sec32[32];

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(challengemsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(callmsg != NULL);
    ARG_CHECK(secshare != NULL);
    ARG_CHECK(msg32 != NULL);
    noncefp = secp256k1_nonce_function_default;
    secp256k1_scalar_get_b32(sec32, secshare);
    while (1) {
        ret = noncefp(k32, msg32, sec32, NULL, NULL, count);
        if (!ret) {
            break;
        }
        secp256k1_scalar_set_b32(&params->k, k32, &overflow);
        if (!overflow && !secp256k1_scalar_is_zero(&params->k)) {
            if (secp256k1_ec_pubkey_create(ctx, &params->r, k32)) {
                memcpy(&challengemsg->r2, &params->r, (size_t)64);
                break;
            }
        }
        count++;
    }
    memset(k32, 0, 32);
    memset(sec32, 0, 32);
    return ret;
}

int secp256k1_threshold_challenge_recieved(const secp256k1_context *ctx, secp256k1_threshold_response_challenge_msg *respmsg, secp256k1_threshold_signature_params *params, const secp256k1_threshold_challenge_msg *challengemsg) {
    int ret = 0;
    unsigned char k32[32];

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(respmsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(challengemsg != NULL);
    secp256k1_scalar_get_b32(k32, &params->k);
    memcpy(&respmsg->r, &challengemsg->r2, (size_t)64);
    ret = secp256k1_ec_pubkey_tweak_mul(ctx, &respmsg->r, k32);
    if (ret) {
        memcpy(&params->r, &respmsg->r, (size_t)64);
    }
    memset(k32, 0, 32);
    return ret;
}

int secp256k1_threshold_response_challenge_recieved(const secp256k1_context *ctx, secp256k1_threshold_terminate_msg *termsg, secp256k1_threshold_signature_params *params, const secp256k1_scalar *secshare, const secp256k1_threshold_call_msg *callmsg, const secp256k1_threshold_response_challenge_msg *respmsg, const unsigned char *msg32, const secp256k1_paillier_pubkey *p1, const secp256k1_paillier_pubkey *p2, const secp256k1_paillier_nonce_function noncefp) {
    unsigned char b[32];
    unsigned char n32[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    secp256k1_scalar privinv, msg, sigr;
    secp256k1_ge r;
    mpz_t m1, m2, m3, m4, m5, c, n5, n, nc, message, z, rsig, inv;
    secp256k1_paillier_encrypted_message *enc = secp256k1_paillier_message_create();
    int ret = 0;
    int overflow = 0;

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(termsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(callmsg != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(p1 != NULL);
    ARG_CHECK(p2 != NULL);
    ARG_CHECK(noncefp != NULL);
    mpz_inits(m1, m2, m3, m4, m5, c, n5, n, nc, message, z, rsig, inv, NULL);
    secp256k1_scalar_inverse(&params->z, &params->k); /* z2 */
    secp256k1_scalar_mul(&privinv, &params->z, secshare); /* x2z2 */
    mpz_import(n, 32, 1, sizeof(n32[0]), 1, 0, n32);
    
    secp256k1_scalar_set_b32(&msg, msg32, &overflow);
    if (!overflow && !secp256k1_scalar_is_zero(&msg)) {
        secp256k1_pubkey_load(ctx, &r, &respmsg->r);
        secp256k1_fe_normalize(&r.x);
        secp256k1_fe_normalize(&r.y);
        secp256k1_fe_get_b32(b, &r.x);
        secp256k1_scalar_set_b32(&sigr, b, &overflow);
        /* These two conditions should be checked before calling */
        VERIFY_CHECK(!secp256k1_scalar_is_zero(&sigr));
        VERIFY_CHECK(overflow == 0);

        mpz_import(rsig, 32, 1, sizeof(b[0]), 1, 0, b);
        secp256k1_scalar_get_b32(b, &params->z);
        mpz_import(z, 32, 1, sizeof(b[0]), 1, 0, b);
        secp256k1_scalar_get_b32(b, &privinv);
        mpz_import(inv, 32, 1, sizeof(b[0]), 1, 0, b);
        secp256k1_scalar_get_b32(b, &msg);
        mpz_import(message, 32, 1, sizeof(msg32[0]), 1, 0, msg32);
        mpz_mul(m1, message, z); /* m'z2 */
        mpz_mul(m2, rsig, inv); /* r'x2z2 */
        mpz_pow_ui(n5, n, 5);
        noncefp(c, n5);
        mpz_mul(nc, c, n);
        termsg->mu = secp256k1_paillier_message_create();
        secp256k1_paillier_mult(m3, callmsg->alpha->message, m1, p1);
        secp256k1_paillier_mult(m4, callmsg->zeta->message, m2, p1);
        secp256k1_paillier_add(m5, m3, m4, p1);

        ret = secp256k1_paillier_encrypt_mpz(enc, &nc, p1, noncefp);
        if (ret) {
            secp256k1_paillier_add(termsg->mu->message, m5, enc->message, p1);

            termsg->mu2 = secp256k1_paillier_message_create();
            ret = secp256k1_paillier_encrypt_scalar(termsg->mu2, &params->z, p2, noncefp);
        }
    }
    mpz_clears(m1, m2, m3, m4, m5, c, n5, n, nc, message, z, rsig, inv, NULL);
    return ret;
}

int secp256k1_threshold_terminate_recieved(const secp256k1_context *ctx, secp256k1_ecdsa_signature* sig, const secp256k1_threshold_terminate_msg *termsg, const secp256k1_threshold_signature_params *params, const secp256k1_paillier_privkey *p, const secp256k1_pubkey *pub, const unsigned char *msg32) {
    unsigned char n32[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    unsigned char b[32];
    void *ser;
    size_t size;
    secp256k1_scalar r, s, mes;
    int ret = 0;
    int overflow = 0;
    secp256k1_ge sigr, pge;
    mpz_t m, n, sigs;

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(termsg != NULL);
    ARG_CHECK(params != NULL);
    ARG_CHECK(p != NULL);
    ARG_CHECK(pub != NULL);
    ARG_CHECK(msg32 != NULL);
    secp256k1_scalar_set_b32(&mes, msg32, &overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &pge, pub);
    if (ret) {
        secp256k1_pubkey_load(ctx, &sigr, &params->r);
        secp256k1_fe_normalize(&sigr.x);
        secp256k1_fe_normalize(&sigr.y);
        secp256k1_fe_get_b32(b, &sigr.x);
        secp256k1_scalar_set_b32(&r, b, &overflow);
        VERIFY_CHECK(!secp256k1_scalar_is_zero(&r));
        VERIFY_CHECK(overflow == 0);
        mpz_inits(m, n, sigs, NULL);
        secp256k1_paillier_decrypt(m, termsg->mu->message, p);
        mpz_import(n, 32, 1, sizeof(n32[0]), 1, 0, n32);
        mpz_mod(sigs, m, n);
        ser = mpz_export(NULL, &size, 1, sizeof(unsigned char), 1, 0, sigs);
        secp256k1_scalar_set_b32(&s, ser, &overflow);
        if (!overflow 
            && !secp256k1_scalar_is_zero(&s)
            && secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &r, &s, &pge, &mes)) {
            secp256k1_ecdsa_signature_save(sig, &r, &s);
        } else {
            memset(sig, 0, sizeof(*sig));
        }
    }
    mpz_clears(m, n, sigs, NULL);
    return ret;
}

#endif /* SECP256K1_MODULE_THRESHOLD_MAIN_H */
