/**********************************************************************
 * Copyright (c) 2017 Joel Gugger                                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECZKP_MAIN_H
#define SECP256K1_MODULE_ECZKP_MAIN_H

#include "include/secp256k1_eczkp.h"
#include "src/modules/threshold/der_impl.h"


secp256k1_eczkp_parameter* secp256k1_eczkp_parameter_create(void) {
    secp256k1_eczkp_parameter *ecparam = malloc(sizeof(*ecparam));
    mpz_init(ecparam->modulus);
    mpz_init(ecparam->h1);
    mpz_init(ecparam->h2);
    return ecparam;
}

void secp256k1_eczkp_parameter_destroy(secp256k1_eczkp_parameter *eczkp) {
    mpz_clears(eczkp->modulus, eczkp->h1, eczkp->h2, NULL);
    free(eczkp);
}

secp256k1_eczkp_pi* secp256k1_eczkp_pi_create(void) {
    secp256k1_eczkp_pi *eczkp_pi = malloc(sizeof(*eczkp_pi));
    mpz_init(eczkp_pi->version);
    mpz_init(eczkp_pi->z1);
    mpz_init(eczkp_pi->z2);
    mpz_init(eczkp_pi->e);
    mpz_init(eczkp_pi->s1);
    mpz_init(eczkp_pi->s2);
    mpz_init(eczkp_pi->s3);
    mpz_init(eczkp_pi->t1);
    mpz_init(eczkp_pi->t2);
    mpz_init(eczkp_pi->t3);
    mpz_init(eczkp_pi->t4);
    return eczkp_pi;
}

void secp256k1_eczkp_pi_destroy(secp256k1_eczkp_pi *eczkp_pi) {
    mpz_clears(eczkp_pi->version, eczkp_pi->z1, eczkp_pi->z2, eczkp_pi->e, eczkp_pi->s1, 
    eczkp_pi->s2, eczkp_pi->s3, eczkp_pi->t1, eczkp_pi->t2, eczkp_pi->t3, 
    eczkp_pi->t4, NULL);
    free(eczkp_pi);
}

secp256k1_eczkp_pi2* secp256k1_eczkp_pi2_create(void) {
    secp256k1_eczkp_pi2 *eczkp_pi2 = malloc(sizeof(*eczkp_pi2));
    mpz_init(eczkp_pi2->version);
    mpz_init(eczkp_pi2->z1);
    mpz_init(eczkp_pi2->z2);
    mpz_init(eczkp_pi2->z3);
    mpz_init(eczkp_pi2->e);
    mpz_init(eczkp_pi2->s1);
    mpz_init(eczkp_pi2->s2);
    mpz_init(eczkp_pi2->s3);
    mpz_init(eczkp_pi2->s4);
    mpz_init(eczkp_pi2->t1);
    mpz_init(eczkp_pi2->t2);
    mpz_init(eczkp_pi2->t3);
    mpz_init(eczkp_pi2->t4);
    mpz_init(eczkp_pi2->t5);
    mpz_init(eczkp_pi2->t6);
    mpz_init(eczkp_pi2->t7);
    return eczkp_pi2;
}

void secp256k1_eczkp_pi2_destroy(secp256k1_eczkp_pi2 *eczkp_pi2) {
    mpz_clears(eczkp_pi2->version, eczkp_pi2->z1, eczkp_pi2->z2, eczkp_pi2->z3, 
    eczkp_pi2->e, eczkp_pi2->s1, eczkp_pi2->s2, eczkp_pi2->s3, eczkp_pi2->s4, 
    eczkp_pi2->t1, eczkp_pi2->t2, eczkp_pi2->t3, eczkp_pi2->t4, eczkp_pi2->t5, 
    eczkp_pi2->t6, eczkp_pi2->t7, NULL);
    free(eczkp_pi2);
}

int secp256k1_eczkp_parameter_parse(secp256k1_eczkp_parameter *eczkp, const unsigned char *input, size_t inputlen) {
    unsigned long start, offset, lenght;
    start = offset = lenght = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        /**
        ZKPParameter ::= SEQUENCE {
            modulus            INTEGER,
            h1                 INTEGER,
            h2                 INTEGER
        }
        */
        if (secp256k1_der_parse_int(input, inputlen, &start, eczkp->modulus, &offset)
            && secp256k1_der_parse_int(input, inputlen, &start, eczkp->h1, &offset)
            && secp256k1_der_parse_int(input, inputlen, &start, eczkp->h2, &offset)) {
            return 1;
        }
    }
    mpz_set_ui(eczkp->modulus, 0);
    mpz_set_ui(eczkp->h1, 0);
    mpz_set_ui(eczkp->h2, 0);
    return 0;
}

int secp256k1_eczkp_pi_parse(const secp256k1_context *ctx, secp256k1_eczkp_pi *eczkp_pi, const unsigned char *input, size_t inputlen) {
    unsigned char buf65[65];
    int ret = 0;
    unsigned long start, offset, lenght;
    start = offset = lenght = 0;
   if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        /* Version MUST be set to 1 */
        if (secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->version, &offset) 
            && mpz_cmp_ui(eczkp_pi->version, 1) == 0) {
            if (secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->z1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->z2, &offset)
                && secp256k1_der_parse_octet_string(input, inputlen, 65, &start, buf65, &lenght, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->e, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->s1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->s2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->s3, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->t1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->t2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->t3, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->t4, &offset)) {
                ret = secp256k1_ec_pubkey_parse(ctx, &eczkp_pi->y, buf65, lenght);
                if (!ret) {
                    /* Erase data in the pubkey */
                    memset(&eczkp_pi->y.data, 0, 64);
                }
                return ret;
            }
        }
    }
    return 0;
}

int secp256k1_eczkp_pi2_parse(const secp256k1_context *ctx, secp256k1_eczkp_pi2 *eczkp_pi2, const unsigned char *input, size_t inputlen) {
    unsigned char buf65[65];
    int ret = 0;
    unsigned long start, offset, lenght;
    start = offset = lenght = 0;
    if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        /* Version MUST be set to 1 */
        if (secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->version, &offset) 
            && mpz_cmp_ui(eczkp_pi2->version, 1) == 0) {
            if (secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->z1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->z2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->z3, &offset)
                && secp256k1_der_parse_octet_string(input, inputlen, 65, &start, buf65, &lenght, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->e, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->s1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->s2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->s3, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->s4, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->t1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->t2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->t3, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->t4, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->t5, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->t6, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->t7, &offset)) {
                ret = secp256k1_ec_pubkey_parse(ctx, &eczkp_pi2->y, buf65, lenght);
                if (!ret) {
                    /* Erase data in the pubkey */
                    memset(&eczkp_pi2->y.data, 0, 64);
                }
                return ret;
            }
        }
    }
    return 0;
}

int secp256k1_eczkp_pi_generate(const secp256k1_context *ctx, secp256k1_eczkp_pi *pi, const secp256k1_eczkp_parameter *zkp, const secp256k1_paillier_encrypted_message *m1, const secp256k1_paillier_encrypted_message *m2, const secp256k1_scalar *sx1, const secp256k1_scalar *sx2, const secp256k1_pubkey *c, const secp256k1_pubkey *w1, const secp256k1_pubkey *w2, const secp256k1_paillier_pubkey *pubkey, const secp256k1_eczkp_rdn_function rdnfp) {
    unsigned char ser65[65], b32[32], n32[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    unsigned char serG[65] = {
        0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
        0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
        0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
        0xB8
    };
    void *res;
    const secp256k1_pubkey* pub3[2];
    size_t countp;

    mpz_t alpha, beta, gamma, phi1, delta, mu, nu, phi2, phi3, epsilon, u2, u3, v3, v4;
    mpz_t s1, s2, s3, t1, t2, t3, t4, n, n3, n3tild, nntild, tmp1, tmp2, tmp3, x1, x2;
    secp256k1_pubkey u1, v1, v2, pub1, pub2;
    secp256k1_scalar sc1, sc2;
    secp256k1_sha256 hash;

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(pi != NULL);
    ARG_CHECK(zkp != NULL);
    ARG_CHECK(m1 != NULL);
    ARG_CHECK(m2 != NULL);
    ARG_CHECK(sx1 != NULL);
    ARG_CHECK(sx2 != NULL);
    ARG_CHECK(c != NULL);
    ARG_CHECK(w1 != NULL);
    ARG_CHECK(w2 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(rdnfp != NULL);

    secp256k1_sha256_initialize(&hash);
    mpz_inits(alpha, beta, gamma, phi1, delta, mu, nu, phi2, phi3, epsilon, u2, u3,
        v3, v4, s1, s2, s3, t1, t2, t3, t4, n, n3, n3tild, nntild, tmp1, tmp2, tmp3, 
        x1, x2, NULL);
    mpz_set_ui(pi->version, 1);
    /* Imports */
    mpz_import(n, 32, 1, sizeof(n32[0]), 1, 0, n32);
    mpz_pow_ui(n3, n, 3);
    mpz_mul(n3tild, n3, zkp->modulus);
    mpz_mul(nntild, n, zkp->modulus);
    secp256k1_scalar_get_b32(b32, sx1);
    mpz_import(x1, 32, 1, sizeof(b32[0]), 1, 0, b32);
    secp256k1_scalar_get_b32(b32, sx2);
    mpz_import(x2, 32, 1, sizeof(b32[0]), 1, 0, b32);
    /* Random values */
    rdnfp(alpha, n3, SECP256K1_THRESHOLD_RND_STD);
    rdnfp(beta, pubkey->modulus, SECP256K1_THRESHOLD_RND_INV);
    rdnfp(gamma, n3tild, SECP256K1_THRESHOLD_RND_STD);
    rdnfp(phi1, nntild, SECP256K1_THRESHOLD_RND_STD);
    rdnfp(delta, n3, SECP256K1_THRESHOLD_RND_STD);
    rdnfp(mu, pubkey->modulus, SECP256K1_THRESHOLD_RND_INV);
    rdnfp(nu, n3tild, SECP256K1_THRESHOLD_RND_STD);
    rdnfp(phi2, nntild, SECP256K1_THRESHOLD_RND_STD);
    rdnfp(phi3, n, SECP256K1_THRESHOLD_RND_STD);
    rdnfp(epsilon, n, SECP256K1_THRESHOLD_RND_STD);
    /* z1 */
    mpz_powm(tmp1, zkp->h1, x1, zkp->modulus);
    mpz_powm(tmp2, zkp->h2, phi1, zkp->modulus);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(pi->z1, tmp3, zkp->modulus);
    /* u1 */
    memcpy(&u1, c, sizeof(secp256k1_pubkey));
    mpz_set(tmp2, alpha);
    mpz_mod(tmp1, tmp2, n);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, tmp1);
    VERIFY_CHECK(countp <= 32);
    VERIFY_CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &u1, res) == 1);
    /* u2 */
    memcpy(&pub2, w2, sizeof(secp256k1_pubkey));
    VERIFY_CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pub2, res) == 1);
    mpz_powm(tmp1, pubkey->generator, alpha, pubkey->bigModulus);
    mpz_powm(tmp2, beta, pubkey->modulus, pubkey->bigModulus);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(u2, tmp3, pubkey->bigModulus);
    /* u3 */
    mpz_powm(tmp1, zkp->h1, alpha, zkp->modulus);
    mpz_powm(tmp2, zkp->h2, gamma, zkp->modulus);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(u3, tmp3, zkp->modulus);
    /* z2 */
    mpz_powm(tmp1, zkp->h1, x2, zkp->modulus);
    mpz_powm(tmp2, zkp->h2, phi2, zkp->modulus);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(pi->z2, tmp3, zkp->modulus);
    /* y */
    mpz_add(tmp1, x2, phi3);
    mpz_mod(tmp2, tmp1, n);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, tmp2);
    VERIFY_CHECK(countp <= 32);    
    VERIFY_CHECK(secp256k1_ec_pubkey_create(ctx, &pi->y, res) == 1);
    /* v1 */
    mpz_add(tmp1, delta, epsilon);
    mpz_mod(tmp2, tmp1, n);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, tmp2);
    VERIFY_CHECK(countp <= 32);
    VERIFY_CHECK(secp256k1_ec_pubkey_create(ctx, &v1, res) == 1);
    /* v2 */
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, epsilon);
    VERIFY_CHECK(countp <= 32);
    VERIFY_CHECK(secp256k1_ec_pubkey_create(ctx, &pub1, res) == 1);
    pub3[0] = &pub1;
    pub3[1] = &pub2;
    VERIFY_CHECK(secp256k1_ec_pubkey_combine(ctx, &v2, pub3, 2) == 1);
    /* v3 */
    mpz_powm(tmp1, pubkey->generator, delta, pubkey->bigModulus);
    mpz_powm(tmp2, mu, pubkey->modulus, pubkey->bigModulus);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(v3, tmp3, pubkey->bigModulus);
    /* v4 */
    mpz_powm(tmp1, zkp->h1, delta, zkp->modulus);
    mpz_powm(tmp2, zkp->h2, nu, zkp->modulus);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(v4, tmp3, zkp->modulus);
    /* Serialize and hash */
    countp = 65;
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, c, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, w1, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    secp256k1_sha256_write(&hash, serG, countp);
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, w2, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, m1->message);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, m2->message);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, pi->z1);
    secp256k1_sha256_write(&hash, res, countp);
    countp = 65;
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, &u1, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, u2);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, u3);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, pi->z2);
    secp256k1_sha256_write(&hash, res, countp);
    countp = 65;
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, &pi->y, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, &v1, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, &v2, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, v3);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, v4);
    secp256k1_sha256_write(&hash, res, countp);
    
    secp256k1_sha256_finalize(&hash, b32);
    mpz_import(pi->e, 32, 1, sizeof(b32[0]), 1, 0, b32);

    mpz_mul(tmp1, pi->e, x1);
    mpz_add(pi->s1, tmp1, alpha);
    mpz_powm(tmp1, m1->nonce, pi->e, pubkey->modulus);
    mpz_mul(tmp2, tmp1, beta);
    mpz_mod(pi->s2, tmp2, pubkey->modulus);
    mpz_mul(tmp1, pi->e, phi1);
    mpz_add(pi->s3, tmp1, gamma);
    mpz_mul(tmp1, pi->e, x2);
    mpz_add(pi->t1, tmp1, delta);
    mpz_mul(tmp1, pi->e, phi3);
    mpz_add(tmp2, tmp1, epsilon);
    mpz_mod(pi->t2, tmp2, n);
    mpz_powm(tmp1, m2->nonce, pi->e, pubkey->bigModulus);
    mpz_mul(tmp2, tmp1, mu);
    mpz_mod(pi->t3, tmp2, pubkey->bigModulus);
    mpz_mul(tmp1, pi->e, phi2);
    mpz_add(pi->t4, tmp1, nu);

    mpz_clears(alpha, beta, gamma, phi1, delta, mu, nu, phi2, phi3, epsilon, u2, u3,
        v3, v4, s1, s2, s3, t1, t2, t3, t4, n, n3, n3tild, nntild, tmp1, tmp2, tmp3,
        x1, x2, NULL);
    memset(b32, 0, 32);
    memset(ser65, 0, 65);
    secp256k1_scalar_clear(&sc1);
    secp256k1_scalar_clear(&sc2);
    return 1;
}

int secp256k1_eczkp_pi_verify(const secp256k1_context *ctx, secp256k1_eczkp_pi *pi, const secp256k1_eczkp_parameter *zkp, const secp256k1_paillier_encrypted_message *m1, const secp256k1_paillier_encrypted_message *m2, const secp256k1_pubkey *c, const secp256k1_pubkey *w1, const secp256k1_pubkey *w2, const secp256k1_paillier_pubkey *pubkey) {
    unsigned char ser65[65], me32[32], n32[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    unsigned char serG[65] = {
        0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
        0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
        0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
        0xB8
    };
    void *res = NULL;
    int ret = 0;
    int overflow = 0;
    const secp256k1_pubkey* pubs[3];
    size_t countp = 0;
    secp256k1_pubkey u1prim, v1prim, v2prim, pub1, pub2, pub3;
    mpz_t tmp1, tmp2, tmp3, tmp4, n, me, u2prim, u3prim, v3prim, v4prim, eprim;
    secp256k1_sha256 hash;

    ARG_CHECK(ctx != NULL);
    ARG_CHECK(pi != NULL);
    ARG_CHECK(zkp != NULL);
    ARG_CHECK(m1 != NULL);
    ARG_CHECK(m2 != NULL);
    ARG_CHECK(c != NULL);
    ARG_CHECK(w1 != NULL);
    ARG_CHECK(w2 != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_sha256_initialize(&hash);
    mpz_inits(tmp1, tmp2, tmp3, tmp4, n, me, u2prim, u3prim, v3prim, v4prim, eprim, NULL);
    mpz_import(n, 32, 1, sizeof(n32[0]), 1, 0, n32);

    mpz_neg(tmp1, pi->e);
    mpz_mod(me, tmp1, n);
    /* u1prim */
    mpz_mod(tmp1, pi->s1, n);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, tmp1);
    VERIFY_CHECK(countp <= 32);
    memcpy(&pub1, c, sizeof(secp256k1_pubkey));
    VERIFY_CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pub1, res) == 1);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, me);
    VERIFY_CHECK(countp <= 32);
    memcpy(&pub2, w1, sizeof(secp256k1_pubkey));
    VERIFY_CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pub2, res) == 1);
    pubs[0] = &pub1;
    pubs[1] = &pub2;
    VERIFY_CHECK(secp256k1_ec_pubkey_combine(ctx, &u1prim, pubs, 2) == 1);
    /* u2prim */
    VERIFY_CHECK(mpz_invert(tmp2, m1->message, pubkey->bigModulus) == 1);
    mpz_powm(tmp1, tmp2, pi->e, pubkey->bigModulus);
    mpz_powm(tmp2, pubkey->generator, pi->s1, pubkey->bigModulus);
    mpz_powm(tmp3, pi->s2, pubkey->modulus, pubkey->bigModulus);
    mpz_mul(tmp4, tmp1, tmp2);
    mpz_mul(tmp1, tmp4, tmp3);
    mpz_mod(u2prim, tmp1, pubkey->bigModulus);
    /* u3prim */
    VERIFY_CHECK(mpz_invert(tmp2, pi->z1, zkp->modulus) == 1);
    mpz_powm(tmp1, tmp2, pi->e, zkp->modulus);
    mpz_powm(tmp2, zkp->h1, pi->s1, zkp->modulus);
    mpz_powm(tmp3, zkp->h2, pi->s3, zkp->modulus);
    mpz_mul(tmp4, tmp1, tmp2);
    mpz_mul(tmp1, tmp4, tmp3);
    mpz_mod(u3prim, tmp1, zkp->modulus);
    /* v1prim */
    mpz_add(tmp1, pi->t1, pi->t2);
    mpz_mod(tmp2, tmp1, n);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, tmp2);
    VERIFY_CHECK(countp <= 32);
    VERIFY_CHECK(secp256k1_ec_pubkey_create(ctx, &pub1, res) == 1);
    memcpy(&pub2, &pi->y, sizeof(secp256k1_pubkey));
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, me);
    VERIFY_CHECK(countp <= 32);
    VERIFY_CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pub2, res) == 1);
    VERIFY_CHECK(secp256k1_ec_pubkey_combine(ctx, &v1prim, pubs, 2) == 1);
    /* v2prim */
    mpz_mod(tmp1, pi->s1, n);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, tmp1);
    VERIFY_CHECK(countp <= 32);
    memcpy(&pub1, w2, sizeof(secp256k1_pubkey));
    VERIFY_CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pub1, res) == 1);
    mpz_mod(tmp1, pi->t2, n);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, tmp1);
    VERIFY_CHECK(countp <= 32);
    VERIFY_CHECK(secp256k1_ec_pubkey_create(ctx, &pub3, res) == 1);
    pubs[2] = &pub3;
    VERIFY_CHECK(secp256k1_ec_pubkey_combine(ctx, &v2prim, pubs, 3) == 1);
    /* v3prim */
    VERIFY_CHECK(mpz_invert(tmp2, m2->message, pubkey->bigModulus) == 1);
    mpz_powm(tmp1, tmp2, pi->e, pubkey->bigModulus);
    mpz_powm(tmp2, pubkey->generator, pi->t1, pubkey->bigModulus);
    mpz_powm(tmp3, pi->t3, pubkey->modulus, pubkey->bigModulus);
    mpz_mul(tmp4, tmp1, tmp2);
    mpz_mul(tmp1, tmp4, tmp3);
    mpz_mod(v3prim, tmp1, pubkey->bigModulus);
    /* v4prim */
    VERIFY_CHECK(mpz_invert(tmp2, pi->z2, zkp->modulus) == 1);
    mpz_powm(tmp1, tmp2, pi->e, zkp->modulus);
    mpz_powm(tmp2, zkp->h1, pi->t1, zkp->modulus);
    mpz_powm(tmp3, zkp->h2, pi->t4, zkp->modulus);
    mpz_mul(tmp4, tmp1, tmp2);
    mpz_mul(tmp1, tmp4, tmp3);
    mpz_mod(v4prim, tmp1, zkp->modulus);
    /* Serialize and hash */
    countp = 65;
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, c, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, w1, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    secp256k1_sha256_write(&hash, serG, countp);
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, w2, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, m1->message);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, m2->message);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, pi->z1);
    secp256k1_sha256_write(&hash, res, countp);
    countp = 65;
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, &u1prim, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, u2prim);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, u3prim);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, pi->z2);
    secp256k1_sha256_write(&hash, res, countp);
    countp = 65;
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, &pi->y, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, &v1prim, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    secp256k1_ec_pubkey_serialize(ctx, ser65, &countp, &v2prim, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_sha256_write(&hash, ser65, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, v3prim);
    secp256k1_sha256_write(&hash, res, countp);
    res = mpz_export(NULL, &countp, 1, sizeof(unsigned char), 1, 0, v4prim);
    secp256k1_sha256_write(&hash, res, countp);

    secp256k1_sha256_finalize(&hash, me32);
    mpz_import(eprim, 32, 1, sizeof(me32[0]), 1, 0, me32);

    ret = mpz_cmp(pi->e, eprim) == 0;

    /*printf("\n%s : ", "e");
    mpz_out_str(stdout, 16, pi->e);
    printf("\n");
    printf("\n%s : ", "e'");
    mpz_out_str(stdout, 16, eprim);
    printf("\n");

    if (mpz_cmp(pi->e, eprim) == 0) {
        printf("%s\n", "ok");
    } else {
        printf("%s\n", "not ok");
    }*/

    mpz_clears(tmp1, tmp2, tmp3, tmp4, n, me, u2prim, u3prim, v3prim, v4prim, eprim, NULL);
    memset(me32, 0, 32);
    memset(ser65, 0, 65);
    return ret;
}

#endif /* SECP256K1_MODULE_ECZKP_MAIN_H */
