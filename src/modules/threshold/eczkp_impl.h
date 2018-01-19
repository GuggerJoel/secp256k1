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

int secp256k1_eczkp_pi_parse(secp256k1_eczkp_pi *eczkp_pi, const unsigned char *input, size_t inputlen) {
    unsigned long start, offset, lenght;
    start = offset = lenght = 0;
   if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        /* Version MUST be set to 1 */
        if (secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->version, &offset) 
            && mpz_cmp_ui(eczkp_pi->version, 1) == 0) {
            if (secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->z1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->z2, &offset)
                && secp256k1_der_parse_octet_string(input, inputlen, 65, &start, eczkp_pi->y, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->e, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->s1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->s2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->s3, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->t1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->t2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->t3, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi->t4, &offset)) {
                return 1;
            }
        }
    }
    return 0;
}

int secp256k1_eczkp_pi2_parse(secp256k1_eczkp_pi2 *eczkp_pi2, const unsigned char *input, size_t inputlen) {
    unsigned long start, offset, lenght;
    start = offset = lenght = 0;
   if (secp256k1_der_parse_struct(input, inputlen, &start, &lenght, &offset)) {
        /* Version MUST be set to 1 */
        if (secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->version, &offset) 
            && mpz_cmp_ui(eczkp_pi2->version, 1) == 0) {
            if (secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->z1, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->z2, &offset)
                && secp256k1_der_parse_int(input, inputlen, &start, eczkp_pi2->z3, &offset)
                && secp256k1_der_parse_octet_string(input, inputlen, 65, &start, eczkp_pi2->y, &offset)
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
                return 1;
            }
        }
    }
    return 0;
}

#endif /* SECP256K1_MODULE_ECZKP_MAIN_H */
