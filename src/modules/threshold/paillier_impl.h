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
            /**
            HEPublicKey ::= SEQUENCE {
                version           INTEGER,
                modulus           INTEGER,  -- p * q
                generator         INTEGER   -- n + 1
            }
            */
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
        /**
        HEEncryptedMessage ::= SEQUENCE {
            message           INTEGER
        }
        */
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
    /**
    HEEncryptedMessage ::= SEQUENCE {
        message           INTEGER
    }
    */
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

int secp256k1_paillier_encrypt(secp256k1_paillier_encrypted_message *res, const unsigned char *data, const size_t lenght, const secp256k1_paillier_pubkey *pubkey, const secp256k1_paillier_nonce_function noncefp) {
    mpz_t message;
    int ret = 0;
    mpz_init(message);
    mpz_import(message, lenght, 1, sizeof(data[0]), 1, 0, data);
    ret = secp256k1_paillier_encrypt_mpz(res, &message, pubkey, noncefp);
    mpz_clear(message);
    return ret;
}

int secp256k1_paillier_encrypt_mpz(secp256k1_paillier_encrypted_message *res, const mpz_t *m, const secp256k1_paillier_pubkey *pubkey, const secp256k1_paillier_nonce_function noncefp) {
    mpz_t l1, l2, l3;
    int ret = noncefp(res->nonce, pubkey->modulus);
    if (ret) {
        mpz_inits(l1, l2, l3, NULL);
        mpz_powm(l1, pubkey->generator, *m, pubkey->bigModulus);
        mpz_powm(l2, res->nonce, pubkey->modulus, pubkey->bigModulus);
        mpz_mul(l3, l1, l2);
        mpz_mod(res->message, l3, pubkey->bigModulus);
        mpz_clears(l1, l2, l3, NULL);
    }
    return ret;
}

void secp256k1_paillier_decrypt(mpz_t message, mpz_t cipher, const secp256k1_paillier_privkey *privkey) {
    mpz_t l1, l2; mpz_inits(l1, l2, NULL);
    mpz_powm(l1, cipher, privkey->privateExponent, privkey->bigModulus);
    mpz_sub_ui(l2, l1, 1);
    mpz_cdiv_q(l1, l2, privkey->modulus);
    mpz_mul(l2, l1, privkey->coefficient);
    mpz_mod(message, l2, privkey->modulus);
    mpz_clears(l1, l2, NULL);
}

void secp256k1_paillier_mult(mpz_t res, mpz_t cipher, mpz_t scalar, const secp256k1_paillier_pubkey *pubkey) {
    mpz_powm(res, cipher, scalar, pubkey->bigModulus);
}

void secp256k1_paillier_add(mpz_t res, mpz_t op1, mpz_t op2, const secp256k1_paillier_pubkey *pubkey) {
    mpz_t l1; mpz_init(l1);
    mpz_mul(l1, op1, op2);
    mpz_mod(res, l1, pubkey->bigModulus);
}

#endif /* SECP256K1_MODULE_PAILLIER_MAIN_H */
