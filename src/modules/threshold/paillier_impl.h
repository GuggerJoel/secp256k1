/**********************************************************************
 * Copyright (c) 2017 Joel Gugger                                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_PAILLIER_MAIN_H
#define SECP256K1_MODULE_PAILLIER_MAIN_H

#include "src/modules/threshold/paillier.h"
#include "src/modules/threshold/der_impl.h"

secp256k1_paillier_privkey* secp256k1_paillier_privkey_create(void) {
    secp256k1_paillier_privkey *key = malloc(sizeof(*key));
    mpz_init(key->modulus);
    mpz_init(key->prime1);
    mpz_init(key->prime2);
    mpz_init(key->generator);
    mpz_init(key->bigModulus);
    mpz_init(key->privateExponent);
    mpz_init(key->coefficient);
    return key;
}

secp256k1_paillier_encrypted_message* secp256k1_paillier_message_create(void) {
    secp256k1_paillier_encrypted_message *message = malloc(sizeof(*message));
    mpz_init(message->message);
    mpz_init(message->nonce);
    return message;
}

void secp256k1_paillier_message_destroy(secp256k1_paillier_encrypted_message *m) {
    mpz_clears(m->message, m->nonce, NULL);
    free(m);
}

secp256k1_paillier_pubkey* secp256k1_paillier_pubkey_create(void) {
    secp256k1_paillier_pubkey *pub = malloc(sizeof(*pub));
    mpz_init(pub->modulus);
    mpz_init(pub->generator);
    mpz_init(pub->bigModulus);
    return pub;
}

secp256k1_paillier_pubkey* secp256k1_paillier_pubkey_get(const secp256k1_paillier_privkey *privkey) {
    secp256k1_paillier_pubkey *pub = secp256k1_paillier_pubkey_create();
    mpz_set(pub->modulus, privkey->modulus);
    mpz_set(pub->generator, privkey->generator);
    mpz_set(pub->bigModulus, privkey->bigModulus);
    return pub;
}

void secp256k1_paillier_privkey_reset(secp256k1_paillier_privkey *privkey) {
    mpz_set_ui(privkey->modulus, 0);
    mpz_set_ui(privkey->prime1, 0);
    mpz_set_ui(privkey->prime2, 0);
    mpz_set_ui(privkey->generator, 0);
    mpz_set_ui(privkey->bigModulus, 0);
    mpz_set_ui(privkey->privateExponent, 0);
    mpz_set_ui(privkey->coefficient, 0);
}

void secp256k1_paillier_pubkey_reset(secp256k1_paillier_pubkey *pubkey) {
    mpz_set_ui(pubkey->modulus, 0);
    mpz_set_ui(pubkey->generator, 0);
    mpz_set_ui(pubkey->bigModulus, 0);
}

void secp256k1_paillier_privkey_destroy(secp256k1_paillier_privkey *privkey) {
    mpz_clears(privkey->modulus, privkey->prime1, privkey->prime2, privkey->generator,
        privkey->bigModulus, privkey->privateExponent, privkey->coefficient, NULL);
    free(privkey);
}

void secp256k1_paillier_pubkey_destroy(secp256k1_paillier_pubkey *pubkey) {
    mpz_clears(pubkey->modulus, pubkey->generator, pubkey->bigModulus, NULL);
    free(pubkey);
}

int secp256k1_paillier_privkey_parse(secp256k1_paillier_privkey *privkey, secp256k1_paillier_pubkey *pubkey, const unsigned char *input, size_t inputlen) {
    unsigned long start, offset, lenght;
    mpz_t version, modulus, coefficient;
    start = offset = lenght = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        mpz_init(version);
        /* Version MUST be set to 1 */
        if (secp256k1_der_parse_int(input, inputlen, &start, version, &offset)
            && mpz_cmp_ui(version, 1) == 0) {
            mpz_clear(version);
            if (secp256k1_der_parse_int(input, inputlen, &start, privkey->modulus, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, privkey->prime1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, privkey->prime2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, privkey->generator, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, privkey->privateExponent, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, privkey->coefficient, &offset)) {
                mpz_inits(coefficient, modulus, NULL);
                mpz_pow_ui(privkey->bigModulus, privkey->modulus, 2);
                mpz_mul(modulus, privkey->prime1, privkey->prime2);
                mpz_invert(coefficient, privkey->privateExponent, privkey->modulus);
                if (mpz_cmp(privkey->coefficient, coefficient) == 0
                    && mpz_cmp(privkey->modulus, modulus) == 0) {
                    mpz_clears(coefficient, modulus, NULL);
                    if (pubkey) {
                        mpz_set(pubkey->modulus, privkey->modulus);
                        mpz_set(pubkey->generator, privkey->generator);
                        mpz_set(pubkey->bigModulus, privkey->bigModulus);
                    }
                    return 1;
                }
                mpz_clears(coefficient, modulus, NULL);
            }
        } else { mpz_clear(version); }
    }
    secp256k1_paillier_privkey_reset(privkey);
    if (pubkey) {
        secp256k1_paillier_pubkey_reset(pubkey);
    }
    return 0;
}

int secp256k1_paillier_pubkey_parse(secp256k1_paillier_pubkey *pubkey, const unsigned char *input, size_t inputlen) {
    unsigned long start, offset, lenght;
    mpz_t version;
    start = offset = lenght = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        mpz_init(version);
        /* Version MUST be set to 1 */
        if (secp256k1_der_parse_int(input, inputlen, &start, version, &offset)
            && mpz_cmp_ui(version, 1) == 0) {
            mpz_clear(version);
            if (secp256k1_der_parse_int(input, inputlen, &start, pubkey->modulus, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, pubkey->generator, &offset)) {
                mpz_pow_ui(pubkey->bigModulus, pubkey->modulus, 2);
                return 1;
            }
        } else { mpz_clear(version); }
    }
    secp256k1_paillier_pubkey_reset(pubkey);
    return 0;
}

int secp256k1_paillier_message_parse(secp256k1_paillier_encrypted_message *message, const unsigned char *input, size_t inputlen) {
    unsigned long start, offset, lenght;
    start = offset = lenght = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        if (secp256k1_der_parse_int(input, inputlen, &start, message->message, &offset)) {
            mpz_set_ui(message->nonce, 0);
            return 1;
        }
    }
    mpz_set_ui(message->message, 0);
    mpz_set_ui(message->nonce, 0);
    return 0;
}

unsigned char* secp256k1_paillier_message_serialize(size_t *outputlen, const secp256k1_paillier_encrypted_message *message){
    unsigned char *outputdata = NULL, *data = NULL, *len = NULL; size_t dlenght = 0, llenght = 0;
    data = secp256k1_der_serialize_int(&dlenght, message->message);
    len = secp256k1_der_serialize_len(&llenght, dlenght);
    *outputlen = 1 + dlenght + llenght;
    outputdata = malloc(*outputlen * sizeof(unsigned char));
    outputdata[0] = 0x30;
    memcpy(&outputdata[1], len, llenght);
    memcpy(&outputdata[1 + llenght], data, dlenght);
    return outputdata;
}

int secp256k1_paillier_encrypt_scalar(secp256k1_paillier_encrypted_message *res, const secp256k1_scalar *scalar, const secp256k1_paillier_pubkey *pubkey, const secp256k1_paillier_nonce_function noncefp) {
    unsigned char data[32];
    secp256k1_scalar_get_b32(data, scalar);
    return secp256k1_paillier_encrypt(res, data, (size_t)32, pubkey, noncefp);
}

static void secp256k1_paillier_encrypt_mpz_r(secp256k1_paillier_encrypted_message *res, const mpz_t m, const secp256k1_paillier_pubkey *pubkey, const mpz_t r) {
    mpz_t l1, l2, l3;
    mpz_set(res->nonce, r);
    mpz_inits(l1, l2, l3, NULL);
    mpz_powm(l1, pubkey->generator, m, pubkey->bigModulus);
    mpz_powm(l2, res->nonce, pubkey->modulus, pubkey->bigModulus);
    mpz_mul(l3, l1, l2);
    mpz_mod(res->message, l3, pubkey->bigModulus);
    mpz_clears(l1, l2, l3, NULL);
}

void secp256k1_paillier_encrypt_r(secp256k1_paillier_encrypted_message *res, const unsigned char *data, const size_t lenght, const secp256k1_paillier_pubkey *pubkey, const mpz_t r) {
    mpz_t m;
    mpz_init(m);
    mpz_import(m, lenght, 1, sizeof(data[0]), 1, 0, data);
    secp256k1_paillier_encrypt_mpz_r(res, m, pubkey, r);
    mpz_clear(m);
}

int secp256k1_paillier_encrypt(secp256k1_paillier_encrypted_message *res, const unsigned char *data, const size_t lenght, const secp256k1_paillier_pubkey *pubkey, const secp256k1_paillier_nonce_function noncefp) {
    mpz_t m;
    int ret;
    mpz_init(m);
    mpz_import(m, lenght, 1, sizeof(data[0]), 1, 0, data);
    ret = secp256k1_paillier_encrypt_mpz(res, m, pubkey, noncefp);
    mpz_clear(m);
    return ret;
}

int secp256k1_paillier_encrypt_mpz(secp256k1_paillier_encrypted_message *res, const mpz_t m, const secp256k1_paillier_pubkey *pubkey, const secp256k1_paillier_nonce_function noncefp) {
    int ret;
    mpz_t nonce;
    mpz_init(nonce);
    ret = noncefp(nonce, pubkey->modulus);
    if (ret) {
        secp256k1_paillier_encrypt_mpz_r(res, m, pubkey, nonce);
    }
    mpz_clear(nonce);
    return ret;
}

void secp256k1_paillier_decrypt(mpz_t res, const secp256k1_paillier_encrypted_message *c, const secp256k1_paillier_privkey *privkey) {
    mpz_t l1, l2;
    mpz_inits(l1, l2, NULL);
    mpz_powm(l1, c->message, privkey->privateExponent, privkey->bigModulus);
    mpz_sub_ui(l2, l1, 1);
    mpz_cdiv_q(l1, l2, privkey->modulus);
    mpz_mul(l2, l1, privkey->coefficient);
    mpz_mod(res, l2, privkey->modulus);
    mpz_clears(l1, l2, NULL);
}

void secp256k1_paillier_mult(secp256k1_paillier_encrypted_message *res, const secp256k1_paillier_encrypted_message *c, const mpz_t s, const secp256k1_paillier_pubkey *pubkey) {
    mpz_powm(res->message, c->message, s, pubkey->bigModulus);
    mpz_set(res->nonce, c->nonce);
}

void secp256k1_paillier_add(secp256k1_paillier_encrypted_message *res, const secp256k1_paillier_encrypted_message *op1, const secp256k1_paillier_encrypted_message *op2, const secp256k1_paillier_pubkey *pubkey) {
    mpz_t l1;
    mpz_init(l1);
    mpz_mul(l1, op1->message, op2->message);
    mpz_mod(res->message, l1, pubkey->bigModulus);
    mpz_clear(l1);
}

void secp256k1_paillier_add_scalar(secp256k1_paillier_encrypted_message *res, const secp256k1_paillier_encrypted_message *op1, const mpz_t op2, const secp256k1_paillier_pubkey *pubkey) {
    mpz_t l1, l2;
    mpz_inits(l1, l2, NULL);
    mpz_powm(l1, pubkey->generator, op2, pubkey->bigModulus);
    mpz_mul(l2, op1->message, l1);
    mpz_mod(res->message, l2, pubkey->bigModulus);
    mpz_clears(l1, l2, NULL);
}

#endif /* SECP256K1_MODULE_PAILLIER_MAIN_H */
