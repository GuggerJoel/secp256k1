/**********************************************************************
 * Copyright (c) 2018 Joel Gugger                                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "include/secp256k1.h"
#include "src/modules/threshold/paillier.h"
#include "src/modules/threshold/paillier_impl.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_paillier_pubkey* pub;
    secp256k1_paillier_encrypted_message* enc;
    mpz_t nonce;
    unsigned char msg[32];
} bench_paillier_enc_data;

typedef struct {
    secp256k1_paillier_privkey* priv;
    secp256k1_paillier_pubkey* pub;
    secp256k1_paillier_encrypted_message* msg;
    mpz_t res;
} bench_paillier_dec_data;

typedef struct {
    secp256k1_paillier_pubkey* pub;
    secp256k1_paillier_encrypted_message* res;
    secp256k1_paillier_encrypted_message* msg1;
    secp256k1_paillier_encrypted_message* msg2;
} bench_paillier_add_data;

typedef struct {
    secp256k1_paillier_pubkey* pub;
    secp256k1_paillier_encrypted_message* res;
    secp256k1_paillier_encrypted_message* msg1;
    mpz_t msg2;
} bench_paillier_scal_data;

static int paillier_nonce_function(mpz_t nonce, const mpz_t max) {
    char rnd[128];
    int counter, fd;
    mpz_t gcd, seed; gmp_randstate_t r_state;
    counter = 0; fd = 0;
    mpz_inits(gcd, seed, NULL); gmp_randinit_mt(r_state);
    /* A cryptographically secure random number generator is required */
    /* to generate a key. This method will work on most Unix-like */
    /* operating systems, but not on Windows operating systems. */
    if ( (fd = open ("/dev/urandom", O_RDONLY)) == -1) {
        return -1;
    }
    if (read(fd, rnd, 128) != 128 ) {
        if (close(fd)) {
            return 0;
        }
        return -1;
    }
    /*rnd[0] |= 0x80;*/
    mpz_import(seed, 128, 1, 1, 1, 0, rnd);
    gmp_randseed(r_state, seed);
    do {
        mpz_urandomm(nonce, r_state, max);
        mpz_gcd(gcd, nonce, max);
        if (counter > 10) {
            printf("%s\n", "Nonce failed");
            return 0;
        }
        counter += 1;
    } while (mpz_cmp_ui(gcd, 1) != 0);
    gmp_randclear(r_state);
    mpz_clear(gcd);
    return 1;
}

static unsigned char raw_pubkey[1041] = {
    0x30, 0x82, 0x04, 0x0d, 0x02, 0x01, 0x01, 0x02, 0x82, 0x02, 0x01, 0x00, 0x81, 0x1e, 0xb0, 0x58,
    0x15, 0xf2, 0xc8, 0xe4, 0xe1, 0x6f, 0xad, 0xec, 0x9f, 0x91, 0x5d, 0x89, 0xfc, 0xba, 0x59, 0x78,
    0x46, 0x2c, 0x73, 0x5d, 0x57, 0x35, 0x89, 0x9e, 0x29, 0x20, 0x69, 0x5f, 0x56, 0xac, 0x5e, 0x99,
    0x7c, 0x8e, 0x83, 0x06, 0xa9, 0x9f, 0xbe, 0x26, 0x19, 0x90, 0xcc, 0x71, 0xfc, 0x19, 0x83, 0x8b,
    0x28, 0x7f, 0xc1, 0x1b, 0x83, 0x4a, 0x1a, 0x1f, 0x16, 0x47, 0x3f, 0xda, 0x1e, 0x44, 0xfc, 0xfe,
    0x9f, 0x70, 0xec, 0xdd, 0xbb, 0x33, 0x6f, 0x86, 0xdb, 0xe3, 0xa1, 0x08, 0x63, 0x74, 0xf9, 0xd0,
    0xc6, 0xf2, 0x59, 0x01, 0x9a, 0x46, 0xf2, 0x11, 0xb9, 0x72, 0xe0, 0x0f, 0x10, 0x01, 0xd9, 0xea,
    0x11, 0x2d, 0x90, 0x65, 0x12, 0xfd, 0x96, 0x29, 0x6f, 0x0c, 0x83, 0x7d, 0xae, 0xc2, 0x3c, 0x90,
    0x2c, 0xe7, 0xd7, 0x31, 0x6c, 0x31, 0xc0, 0x73, 0x1a, 0xc8, 0x11, 0x59, 0x32, 0xdd, 0x19, 0x7f,
    0xbd, 0x59, 0x11, 0xdf, 0x20, 0x8c, 0x4e, 0x78, 0xe6, 0xd6, 0x92, 0xda, 0xc2, 0x42, 0x9e, 0x78,
    0x7e, 0xb8, 0x74, 0x89, 0xc8, 0xfc, 0xee, 0xf8, 0xa6, 0x20, 0x55, 0xc9, 0xf6, 0x34, 0xb9, 0x04,
    0x2e, 0x38, 0x04, 0xba, 0x27, 0x66, 0xaa, 0xbe, 0xda, 0x1a, 0x7d, 0xb0, 0x87, 0xf1, 0x62, 0x31,
    0x57, 0x6b, 0x16, 0xfe, 0x10, 0x5d, 0xdc, 0xb8, 0xbd, 0x7f, 0x10, 0x33, 0x4f, 0xb7, 0x4d, 0x9f,
    0xe9, 0xf1, 0x17, 0x37, 0x11, 0x58, 0xa4, 0xae, 0xac, 0x7f, 0x46, 0x54, 0x4e, 0x72, 0x46, 0xed,
    0xe8, 0x75, 0x68, 0xcb, 0x4d, 0x2d, 0x1e, 0x6a, 0xcd, 0x81, 0x09, 0x32, 0x02, 0x7e, 0x34, 0xfa,
    0x5d, 0xe8, 0xd5, 0x79, 0xb5, 0xe1, 0x6b, 0x70, 0x27, 0x99, 0x4e, 0xd7, 0x4c, 0x6a, 0xf6, 0x97,
    0x15, 0x75, 0xdf, 0x81, 0xc1, 0x6e, 0x8e, 0xe5, 0x8d, 0x75, 0xb6, 0x30, 0x69, 0x18, 0xba, 0x2e,
    0xe6, 0x55, 0x17, 0x55, 0x9f, 0x24, 0xbb, 0x8c, 0x99, 0x50, 0x53, 0xc7, 0x70, 0x37, 0xd8, 0x4c,
    0xba, 0x92, 0xae, 0x11, 0x7a, 0x39, 0x07, 0x73, 0xe0, 0xcf, 0x99, 0x42, 0xde, 0xe8, 0xae, 0x43,
    0xd8, 0xdc, 0xfe, 0x0c, 0x5c, 0x51, 0x10, 0x96, 0x77, 0x00, 0xad, 0x9c, 0xf4, 0x86, 0x08, 0xed,
    0x91, 0xc0, 0x6f, 0x87, 0xff, 0x4f, 0x43, 0xb6, 0x18, 0xa5, 0xb2, 0x2b, 0x45, 0x9a, 0x11, 0x08,
    0x89, 0x1f, 0x8f, 0x28, 0x75, 0x63, 0x3f, 0x8d, 0xca, 0x21, 0x70, 0xb8, 0x1f, 0x13, 0xda, 0x84,
    0xc2, 0x82, 0xf3, 0x79, 0x32, 0x73, 0x4c, 0x41, 0x3b, 0x45, 0xb9, 0x04, 0xe8, 0x36, 0x62, 0x40,
    0x2d, 0x6c, 0x8a, 0xeb, 0x93, 0xa5, 0xfe, 0xf4, 0xe8, 0x94, 0xfb, 0xf5, 0x50, 0x55, 0x4b, 0x42,
    0xd2, 0xb4, 0xdc, 0xc7, 0x14, 0xb2, 0x73, 0x5a, 0xbf, 0x05, 0xb0, 0xf6, 0x8a, 0x73, 0xda, 0x6f,
    0x0e, 0x00, 0xb7, 0x3f, 0xc2, 0x59, 0x8c, 0x83, 0x81, 0x78, 0x9a, 0xce, 0x2a, 0x99, 0x7b, 0xec,
    0x01, 0x46, 0x8c, 0x8e, 0xe6, 0x6b, 0x07, 0xff, 0xf3, 0x5c, 0x4e, 0x9b, 0xd3, 0x8b, 0x01, 0x1f,
    0x28, 0x1f, 0xcc, 0xb4, 0xba, 0xf5, 0x03, 0x2b, 0x45, 0xb5, 0xcc, 0x2d, 0xb4, 0x01, 0x49, 0x93,
    0x97, 0x1c, 0xc4, 0xa0, 0xe7, 0xf7, 0xd0, 0x95, 0x32, 0x2a, 0xa6, 0x87, 0xe5, 0x6e, 0xd8, 0x3c,
    0xb1, 0x92, 0x7a, 0xcd, 0xf2, 0x56, 0x96, 0x84, 0xf3, 0x8b, 0x69, 0x9f, 0x0b, 0x83, 0x92, 0x2f,
    0x8c, 0x5b, 0x4d, 0x8c, 0x28, 0x21, 0x85, 0x4b, 0x13, 0x6e, 0xf0, 0x84, 0xb7, 0x83, 0xe3, 0x4d,
    0x06, 0x80, 0x4e, 0x1a, 0x13, 0xe9, 0x84, 0xce, 0xe1, 0xbf, 0x0d, 0xda, 0x34, 0x68, 0x07, 0xdf,
    0xb3, 0x05, 0xfa, 0x40, 0x3a, 0xc9, 0xff, 0xab, 0xeb, 0xe4, 0x24, 0x85, 0x02, 0x82, 0x02, 0x01,
    0x00, 0x81, 0x1e, 0xb0, 0x58, 0x15, 0xf2, 0xc8, 0xe4, 0xe1, 0x6f, 0xad, 0xec, 0x9f, 0x91, 0x5d,
    0x89, 0xfc, 0xba, 0x59, 0x78, 0x46, 0x2c, 0x73, 0x5d, 0x57, 0x35, 0x89, 0x9e, 0x29, 0x20, 0x69,
    0x5f, 0x56, 0xac, 0x5e, 0x99, 0x7c, 0x8e, 0x83, 0x06, 0xa9, 0x9f, 0xbe, 0x26, 0x19, 0x90, 0xcc,
    0x71, 0xfc, 0x19, 0x83, 0x8b, 0x28, 0x7f, 0xc1, 0x1b, 0x83, 0x4a, 0x1a, 0x1f, 0x16, 0x47, 0x3f,
    0xda, 0x1e, 0x44, 0xfc, 0xfe, 0x9f, 0x70, 0xec, 0xdd, 0xbb, 0x33, 0x6f, 0x86, 0xdb, 0xe3, 0xa1,
    0x08, 0x63, 0x74, 0xf9, 0xd0, 0xc6, 0xf2, 0x59, 0x01, 0x9a, 0x46, 0xf2, 0x11, 0xb9, 0x72, 0xe0,
    0x0f, 0x10, 0x01, 0xd9, 0xea, 0x11, 0x2d, 0x90, 0x65, 0x12, 0xfd, 0x96, 0x29, 0x6f, 0x0c, 0x83,
    0x7d, 0xae, 0xc2, 0x3c, 0x90, 0x2c, 0xe7, 0xd7, 0x31, 0x6c, 0x31, 0xc0, 0x73, 0x1a, 0xc8, 0x11,
    0x59, 0x32, 0xdd, 0x19, 0x7f, 0xbd, 0x59, 0x11, 0xdf, 0x20, 0x8c, 0x4e, 0x78, 0xe6, 0xd6, 0x92,
    0xda, 0xc2, 0x42, 0x9e, 0x78, 0x7e, 0xb8, 0x74, 0x89, 0xc8, 0xfc, 0xee, 0xf8, 0xa6, 0x20, 0x55,
    0xc9, 0xf6, 0x34, 0xb9, 0x04, 0x2e, 0x38, 0x04, 0xba, 0x27, 0x66, 0xaa, 0xbe, 0xda, 0x1a, 0x7d,
    0xb0, 0x87, 0xf1, 0x62, 0x31, 0x57, 0x6b, 0x16, 0xfe, 0x10, 0x5d, 0xdc, 0xb8, 0xbd, 0x7f, 0x10,
    0x33, 0x4f, 0xb7, 0x4d, 0x9f, 0xe9, 0xf1, 0x17, 0x37, 0x11, 0x58, 0xa4, 0xae, 0xac, 0x7f, 0x46,
    0x54, 0x4e, 0x72, 0x46, 0xed, 0xe8, 0x75, 0x68, 0xcb, 0x4d, 0x2d, 0x1e, 0x6a, 0xcd, 0x81, 0x09,
    0x32, 0x02, 0x7e, 0x34, 0xfa, 0x5d, 0xe8, 0xd5, 0x79, 0xb5, 0xe1, 0x6b, 0x70, 0x27, 0x99, 0x4e,
    0xd7, 0x4c, 0x6a, 0xf6, 0x97, 0x15, 0x75, 0xdf, 0x81, 0xc1, 0x6e, 0x8e, 0xe5, 0x8d, 0x75, 0xb6,
    0x30, 0x69, 0x18, 0xba, 0x2e, 0xe6, 0x55, 0x17, 0x55, 0x9f, 0x24, 0xbb, 0x8c, 0x99, 0x50, 0x53,
    0xc7, 0x70, 0x37, 0xd8, 0x4c, 0xba, 0x92, 0xae, 0x11, 0x7a, 0x39, 0x07, 0x73, 0xe0, 0xcf, 0x99,
    0x42, 0xde, 0xe8, 0xae, 0x43, 0xd8, 0xdc, 0xfe, 0x0c, 0x5c, 0x51, 0x10, 0x96, 0x77, 0x00, 0xad,
    0x9c, 0xf4, 0x86, 0x08, 0xed, 0x91, 0xc0, 0x6f, 0x87, 0xff, 0x4f, 0x43, 0xb6, 0x18, 0xa5, 0xb2,
    0x2b, 0x45, 0x9a, 0x11, 0x08, 0x89, 0x1f, 0x8f, 0x28, 0x75, 0x63, 0x3f, 0x8d, 0xca, 0x21, 0x70,
    0xb8, 0x1f, 0x13, 0xda, 0x84, 0xc2, 0x82, 0xf3, 0x79, 0x32, 0x73, 0x4c, 0x41, 0x3b, 0x45, 0xb9,
    0x04, 0xe8, 0x36, 0x62, 0x40, 0x2d, 0x6c, 0x8a, 0xeb, 0x93, 0xa5, 0xfe, 0xf4, 0xe8, 0x94, 0xfb,
    0xf5, 0x50, 0x55, 0x4b, 0x42, 0xd2, 0xb4, 0xdc, 0xc7, 0x14, 0xb2, 0x73, 0x5a, 0xbf, 0x05, 0xb0,
    0xf6, 0x8a, 0x73, 0xda, 0x6f, 0x0e, 0x00, 0xb7, 0x3f, 0xc2, 0x59, 0x8c, 0x83, 0x81, 0x78, 0x9a,
    0xce, 0x2a, 0x99, 0x7b, 0xec, 0x01, 0x46, 0x8c, 0x8e, 0xe6, 0x6b, 0x07, 0xff, 0xf3, 0x5c, 0x4e,
    0x9b, 0xd3, 0x8b, 0x01, 0x1f, 0x28, 0x1f, 0xcc, 0xb4, 0xba, 0xf5, 0x03, 0x2b, 0x45, 0xb5, 0xcc,
    0x2d, 0xb4, 0x01, 0x49, 0x93, 0x97, 0x1c, 0xc4, 0xa0, 0xe7, 0xf7, 0xd0, 0x95, 0x32, 0x2a, 0xa6,
    0x87, 0xe5, 0x6e, 0xd8, 0x3c, 0xb1, 0x92, 0x7a, 0xcd, 0xf2, 0x56, 0x96, 0x84, 0xf3, 0x8b, 0x69,
    0x9f, 0x0b, 0x83, 0x92, 0x2f, 0x8c, 0x5b, 0x4d, 0x8c, 0x28, 0x21, 0x85, 0x4b, 0x13, 0x6e, 0xf0,
    0x84, 0xb7, 0x83, 0xe3, 0x4d, 0x06, 0x80, 0x4e, 0x1a, 0x13, 0xe9, 0x84, 0xce, 0xe1, 0xbf, 0x0d,
    0xda, 0x34, 0x68, 0x07, 0xdf, 0xb3, 0x05, 0xfa, 0x40, 0x3a, 0xc9, 0xff, 0xab, 0xeb, 0xe4, 0x24,
    0x86
};

static unsigned char raw_privkey[2596] = {
    0x30, 0x82, 0x0a, 0x20, 0x02, 0x01, 0x01, 0x02, 0x82, 0x02, 0x01, 0x00, 0x85, 0xb4, 0x9b, 0xa6,
    0x8f, 0x2a, 0xe7, 0x1b, 0x5f, 0xbd, 0x13, 0x5a, 0x82, 0x80, 0x81, 0x18, 0xef, 0xd0, 0x24, 0x56,
    0x47, 0x2d, 0xa9, 0xce, 0x2c, 0xc0, 0x5a, 0x11, 0x2b, 0xa3, 0xf8, 0xfc, 0xff, 0x78, 0xc6, 0x54,
    0x00, 0x01, 0x40, 0x4c, 0xb4, 0x05, 0x9f, 0xa3, 0xe3, 0x2d, 0x1c, 0xbe, 0xd0, 0xe3, 0xa3, 0x72,
    0x9d, 0xfb, 0x3b, 0xa1, 0x87, 0xe3, 0xf3, 0x99, 0x7f, 0x59, 0x75, 0xb4, 0xb4, 0x48, 0x91, 0xe6,
    0xf0, 0x59, 0x66, 0xf9, 0x42, 0x87, 0x16, 0xd8, 0x68, 0x07, 0x0d, 0xb8, 0x19, 0x14, 0x3f, 0x42,
    0x1a, 0x9d, 0xd9, 0x58, 0xee, 0xc4, 0x04, 0x4a, 0x75, 0x1c, 0xe0, 0x3f, 0xcd, 0xfc, 0x3f, 0xf2,
    0xfd, 0x61, 0xdb, 0x1d, 0x19, 0x68, 0x92, 0x68, 0x23, 0x8a, 0xd7, 0x1a, 0xcb, 0xac, 0x99, 0x41,
    0xc1, 0xd3, 0xd9, 0xd1, 0x5d, 0xe1, 0x55, 0xb3, 0x80, 0x2d, 0xd2, 0x7c, 0xc2, 0x26, 0xb8, 0x6c,
    0xb2, 0x8d, 0x76, 0x16, 0x89, 0x4f, 0x3f, 0xd6, 0xbf, 0xc1, 0x06, 0x97, 0x6d, 0x89, 0xe9, 0xb9,
    0xb9, 0x82, 0x83, 0xc1, 0xdf, 0xb0, 0x7c, 0x4e, 0x8a, 0xe3, 0xe6, 0x6c, 0x50, 0x63, 0x59, 0xe5,
    0x89, 0x3c, 0x3b, 0xbb, 0x9e, 0xd4, 0xdd, 0xb1, 0xfa, 0x51, 0xcf, 0x56, 0x83, 0x47, 0xc9, 0x99,
    0x71, 0x6e, 0xea, 0x60, 0x7a, 0x52, 0x67, 0x1e, 0x44, 0x07, 0xae, 0xb7, 0x34, 0x51, 0xad, 0x59,
    0x23, 0x4a, 0x07, 0xd5, 0xd3, 0xc2, 0xec, 0x26, 0xd9, 0xd8, 0x15, 0x11, 0xc5, 0x4b, 0x45, 0xfd,
    0x25, 0xe8, 0x66, 0x6d, 0xfe, 0xf6, 0x1a, 0x09, 0x74, 0xc9, 0x59, 0xf5, 0x7a, 0x55, 0x85, 0x3f,
    0x1d, 0x4b, 0x8f, 0xe0, 0x17, 0x49, 0x2a, 0x68, 0x75, 0x8d, 0x8d, 0x31, 0xdc, 0xe9, 0x2d, 0x15,
    0xe9, 0x1d, 0x53, 0x18, 0xb8, 0x69, 0x71, 0x89, 0xee, 0x2c, 0x1f, 0x3d, 0x26, 0x36, 0x4f, 0x61,
    0x36, 0x7c, 0x77, 0x12, 0xdf, 0x37, 0xdd, 0x15, 0x63, 0x03, 0x85, 0x61, 0x4a, 0x48, 0x37, 0xfc,
    0x18, 0x0c, 0x08, 0x5d, 0xed, 0x24, 0x45, 0x7f, 0xb5, 0x88, 0x6a, 0x40, 0xc1, 0xcc, 0x19, 0xb0,
    0x86, 0xac, 0xc5, 0xfc, 0xf9, 0x41, 0xa6, 0x88, 0x8e, 0xd4, 0xd7, 0x7c, 0x57, 0x94, 0x79, 0xbf,
    0xd7, 0x2a, 0x94, 0x41, 0x85, 0x64, 0xfb, 0x28, 0x16, 0x7a, 0x18, 0x73, 0x1f, 0x57, 0x43, 0x8f,
    0x77, 0xf1, 0x8e, 0x97, 0x26, 0x45, 0xd3, 0xb3, 0x9c, 0x2a, 0x76, 0x2a, 0x57, 0x78, 0xca, 0x9c,
    0x4d, 0xca, 0xe8, 0xf6, 0xa3, 0x9e, 0xa2, 0x97, 0xf0, 0x00, 0xd9, 0x28, 0xf4, 0xc9, 0x94, 0x1d,
    0xf6, 0xf9, 0x09, 0xa9, 0xb3, 0x70, 0xfe, 0xca, 0xd5, 0x3e, 0x5d, 0x7e, 0x6b, 0xcb, 0xef, 0xe5,
    0xc9, 0x51, 0x71, 0xd8, 0x69, 0x5d, 0x5f, 0x01, 0x64, 0x87, 0x9b, 0xf7, 0x98, 0x8c, 0xff, 0x6b,
    0x8e, 0x72, 0x1f, 0x9d, 0x76, 0x17, 0x7d, 0xd2, 0x58, 0x75, 0x05, 0xa9, 0xb0, 0x61, 0x6e, 0xa7,
    0x83, 0x28, 0x0a, 0x4a, 0x11, 0xa9, 0x19, 0x6c, 0x2c, 0xc5, 0x6a, 0x08, 0xc4, 0x7d, 0x1e, 0xf3,
    0x73, 0x9b, 0x10, 0x8e, 0x57, 0xc6, 0xdb, 0xb5, 0x2f, 0x8b, 0x6d, 0x5c, 0xa4, 0x88, 0x05, 0x82,
    0xab, 0xe5, 0x69, 0xd0, 0xc3, 0x3b, 0xb7, 0x26, 0xaa, 0x39, 0xa8, 0x5a, 0x04, 0x9a, 0xe8, 0x6f,
    0x45, 0xd1, 0x0a, 0xba, 0x3c, 0x2b, 0xab, 0xfe, 0xf9, 0x8e, 0x5d, 0x05, 0x6b, 0xc0, 0x6d, 0x46,
    0x77, 0xeb, 0xc1, 0xa3, 0x8f, 0x3b, 0x26, 0xfc, 0xe5, 0x5a, 0x6a, 0xee, 0x36, 0x1c, 0x2c, 0xf9,
    0x60, 0xbd, 0x7f, 0x7c, 0xf6, 0xf7, 0x93, 0xbd, 0x5b, 0xe7, 0x59, 0x40, 0xa5, 0x7d, 0x0b, 0xad,
    0xd9, 0x30, 0xcd, 0x08, 0xd2, 0xe1, 0xaf, 0x4c, 0x03, 0x9f, 0x11, 0x25, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xca, 0xb1, 0xda, 0xb7, 0x31, 0x79, 0x32, 0x98, 0x37, 0x59, 0xf2, 0x6d, 0x31, 0x54, 0x5d,
    0x5c, 0x79, 0x61, 0x60, 0x6e, 0xf8, 0xb4, 0x20, 0x6c, 0xbc, 0x74, 0x24, 0x52, 0x36, 0xcf, 0xb1,
    0xd4, 0x2c, 0x41, 0x57, 0x2f, 0x71, 0x27, 0x7e, 0x50, 0xd8, 0x5e, 0x7d, 0x65, 0x41, 0xd4, 0x41,
    0xa5, 0x43, 0x77, 0xe5, 0x98, 0x15, 0xa3, 0xb6, 0x0b, 0x05, 0xb4, 0x18, 0x3e, 0x8d, 0x2a, 0x12,
    0x40, 0x8b, 0xc6, 0x04, 0xd0, 0xb6, 0xbf, 0x21, 0x60, 0x96, 0xf5, 0x9c, 0x84, 0x29, 0xd2, 0xfb,
    0xad, 0xc7, 0x56, 0x17, 0xef, 0xe3, 0x1e, 0x02, 0x8a, 0xb8, 0x5e, 0xe2, 0x7f, 0x2b, 0x4c, 0x4a,
    0x18, 0x4b, 0xd0, 0xe9, 0x42, 0xfc, 0x47, 0x68, 0xe7, 0x54, 0x53, 0x43, 0xcb, 0x88, 0x45, 0xaa,
    0x92, 0x3b, 0x2a, 0x35, 0x87, 0x94, 0xb0, 0xbb, 0x0f, 0x30, 0x81, 0xc9, 0x52, 0x1d, 0x42, 0x14,
    0xc0, 0x88, 0xb2, 0xdb, 0xba, 0x99, 0x8b, 0xb2, 0x58, 0x8e, 0xec, 0xfc, 0x07, 0xca, 0x23, 0xdc,
    0x29, 0x49, 0x49, 0xdc, 0x82, 0x99, 0x48, 0x54, 0x8d, 0x84, 0xa4, 0x12, 0x0d, 0xd7, 0xdb, 0x7c,
    0x37, 0x0f, 0xe4, 0x16, 0x6e, 0x23, 0xaa, 0x45, 0x6f, 0x6c, 0x66, 0x9d, 0x37, 0x02, 0x29, 0x21,
    0x7b, 0x32, 0xad, 0xe8, 0x5b, 0xd4, 0xc2, 0x55, 0xb2, 0x1d, 0x24, 0x4c, 0x25, 0xe5, 0xd8, 0xce,
    0x12, 0x61, 0x6a, 0xab, 0xde, 0x3e, 0x28, 0xe7, 0x90, 0x50, 0x6d, 0x87, 0x81, 0xc0, 0x24, 0x77,
    0x4a, 0x74, 0x5b, 0x70, 0xb8, 0x34, 0xa2, 0xf8, 0xe3, 0x3b, 0x41, 0x96, 0x00, 0x8a, 0x75, 0xac,
    0x73, 0x97, 0xf0, 0xff, 0x31, 0x76, 0x6e, 0x89, 0x7d, 0x4b, 0xb5, 0xaf, 0x66, 0xcf, 0x16, 0x34,
    0x3f, 0xca, 0xaf, 0x62, 0x79, 0x53, 0x9e, 0xd0, 0xfc, 0xb3, 0x79, 0x25, 0xa4, 0x37, 0xb6, 0xab,
    0x5b, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa8, 0xde, 0x25, 0xbe, 0xaa, 0xc9, 0x83, 0x1a, 0x80, 0x2a,
    0x0a, 0x31, 0x97, 0x4c, 0xc7, 0xb3, 0x81, 0x57, 0x77, 0x6f, 0x9c, 0x62, 0x88, 0x72, 0x8a, 0xf2,
    0xf3, 0xd4, 0x6d, 0x80, 0x4f, 0x97, 0xfc, 0xf8, 0x7b, 0x2b, 0x2b, 0x67, 0x63, 0x1e, 0xff, 0x87,
    0xfa, 0xd6, 0x0a, 0xce, 0x1a, 0x13, 0xc3, 0x55, 0xd5, 0xf5, 0xc9, 0x53, 0xb7, 0x98, 0x98, 0x02,
    0x29, 0x42, 0xdf, 0xba, 0xea, 0xda, 0x76, 0x06, 0x0f, 0x46, 0xe0, 0x1c, 0x0f, 0xb3, 0x08, 0xc7,
    0x46, 0xa8, 0x62, 0x6d, 0x8e, 0x2a, 0x5e, 0xf4, 0xbe, 0x47, 0x6b, 0xa9, 0x5c, 0x3e, 0x58, 0x50,
    0xe6, 0x13, 0x4e, 0x63, 0x8c, 0x16, 0xf1, 0x4b, 0x16, 0x80, 0x70, 0xfa, 0xb4, 0x80, 0xe3, 0xe6,
    0xad, 0x48, 0xaa, 0x56, 0xf8, 0x72, 0xd2, 0xc0, 0xd5, 0x92, 0xa7, 0xb3, 0x7c, 0xdc, 0xba, 0x2d,
    0xe0, 0x4a, 0x84, 0xd3, 0x54, 0x08, 0x3f, 0x85, 0x81, 0x82, 0x1b, 0xda, 0x00, 0xd0, 0x16, 0x4e,
    0x5c, 0xa1, 0x5b, 0xb9, 0x06, 0x7b, 0x02, 0x24, 0x2b, 0x7b, 0x38, 0xc8, 0xa4, 0xd8, 0x0f, 0x79,
    0x8b, 0xd5, 0xe8, 0xac, 0xa8, 0x4c, 0xfd, 0x68, 0x28, 0x17, 0x8d, 0x1f, 0x9c, 0x51, 0x96, 0x4e,
    0x49, 0x38, 0x1d, 0xaf, 0xa3, 0xf7, 0x81, 0x4a, 0x77, 0xa1, 0x9d, 0x94, 0x4a, 0x57, 0x69, 0x3d,
    0x79, 0x12, 0x0b, 0x8b, 0x91, 0xa3, 0xe4, 0x0e, 0xb0, 0x09, 0xf3, 0xa3, 0x90, 0xa5, 0xb7, 0x1a,
    0xa9, 0x4d, 0x54, 0x09, 0xbc, 0x88, 0xe6, 0xa9, 0x6d, 0x05, 0x3c, 0x07, 0xbc, 0x0a, 0xde, 0x43,
    0x3e, 0xf3, 0xc2, 0x99, 0x42, 0x79, 0xa8, 0xab, 0x38, 0x45, 0x22, 0xb7, 0xec, 0x23, 0x96, 0x7c,
    0x12, 0x44, 0x8a, 0xa4, 0xb0, 0x99, 0xa7, 0xe3, 0x2b, 0xb5, 0xe4, 0x22, 0x86, 0x37, 0xef, 0x3b,
    0xbc, 0x45, 0x17, 0x40, 0x5d, 0x7f, 0x02, 0x82, 0x02, 0x01, 0x00, 0x85, 0xb4, 0x9b, 0xa6, 0x8f,
    0x2a, 0xe7, 0x1b, 0x5f, 0xbd, 0x13, 0x5a, 0x82, 0x80, 0x81, 0x18, 0xef, 0xd0, 0x24, 0x56, 0x47,
    0x2d, 0xa9, 0xce, 0x2c, 0xc0, 0x5a, 0x11, 0x2b, 0xa3, 0xf8, 0xfc, 0xff, 0x78, 0xc6, 0x54, 0x00,
    0x01, 0x40, 0x4c, 0xb4, 0x05, 0x9f, 0xa3, 0xe3, 0x2d, 0x1c, 0xbe, 0xd0, 0xe3, 0xa3, 0x72, 0x9d,
    0xfb, 0x3b, 0xa1, 0x87, 0xe3, 0xf3, 0x99, 0x7f, 0x59, 0x75, 0xb4, 0xb4, 0x48, 0x91, 0xe6, 0xf0,
    0x59, 0x66, 0xf9, 0x42, 0x87, 0x16, 0xd8, 0x68, 0x07, 0x0d, 0xb8, 0x19, 0x14, 0x3f, 0x42, 0x1a,
    0x9d, 0xd9, 0x58, 0xee, 0xc4, 0x04, 0x4a, 0x75, 0x1c, 0xe0, 0x3f, 0xcd, 0xfc, 0x3f, 0xf2, 0xfd,
    0x61, 0xdb, 0x1d, 0x19, 0x68, 0x92, 0x68, 0x23, 0x8a, 0xd7, 0x1a, 0xcb, 0xac, 0x99, 0x41, 0xc1,
    0xd3, 0xd9, 0xd1, 0x5d, 0xe1, 0x55, 0xb3, 0x80, 0x2d, 0xd2, 0x7c, 0xc2, 0x26, 0xb8, 0x6c, 0xb2,
    0x8d, 0x76, 0x16, 0x89, 0x4f, 0x3f, 0xd6, 0xbf, 0xc1, 0x06, 0x97, 0x6d, 0x89, 0xe9, 0xb9, 0xb9,
    0x82, 0x83, 0xc1, 0xdf, 0xb0, 0x7c, 0x4e, 0x8a, 0xe3, 0xe6, 0x6c, 0x50, 0x63, 0x59, 0xe5, 0x89,
    0x3c, 0x3b, 0xbb, 0x9e, 0xd4, 0xdd, 0xb1, 0xfa, 0x51, 0xcf, 0x56, 0x83, 0x47, 0xc9, 0x99, 0x71,
    0x6e, 0xea, 0x60, 0x7a, 0x52, 0x67, 0x1e, 0x44, 0x07, 0xae, 0xb7, 0x34, 0x51, 0xad, 0x59, 0x23,
    0x4a, 0x07, 0xd5, 0xd3, 0xc2, 0xec, 0x26, 0xd9, 0xd8, 0x15, 0x11, 0xc5, 0x4b, 0x45, 0xfd, 0x25,
    0xe8, 0x66, 0x6d, 0xfe, 0xf6, 0x1a, 0x09, 0x74, 0xc9, 0x59, 0xf5, 0x7a, 0x55, 0x85, 0x3f, 0x1d,
    0x4b, 0x8f, 0xe0, 0x17, 0x49, 0x2a, 0x68, 0x75, 0x8d, 0x8d, 0x31, 0xdc, 0xe9, 0x2d, 0x15, 0xe9,
    0x1d, 0x53, 0x18, 0xb8, 0x69, 0x71, 0x89, 0xee, 0x2c, 0x1f, 0x3d, 0x26, 0x36, 0x4f, 0x61, 0x36,
    0x7c, 0x77, 0x12, 0xdf, 0x37, 0xdd, 0x15, 0x63, 0x03, 0x85, 0x61, 0x4a, 0x48, 0x37, 0xfc, 0x18,
    0x0c, 0x08, 0x5d, 0xed, 0x24, 0x45, 0x7f, 0xb5, 0x88, 0x6a, 0x40, 0xc1, 0xcc, 0x19, 0xb0, 0x86,
    0xac, 0xc5, 0xfc, 0xf9, 0x41, 0xa6, 0x88, 0x8e, 0xd4, 0xd7, 0x7c, 0x57, 0x94, 0x79, 0xbf, 0xd7,
    0x2a, 0x94, 0x41, 0x85, 0x64, 0xfb, 0x28, 0x16, 0x7a, 0x18, 0x73, 0x1f, 0x57, 0x43, 0x8f, 0x77,
    0xf1, 0x8e, 0x97, 0x26, 0x45, 0xd3, 0xb3, 0x9c, 0x2a, 0x76, 0x2a, 0x57, 0x78, 0xca, 0x9c, 0x4d,
    0xca, 0xe8, 0xf6, 0xa3, 0x9e, 0xa2, 0x97, 0xf0, 0x00, 0xd9, 0x28, 0xf4, 0xc9, 0x94, 0x1d, 0xf6,
    0xf9, 0x09, 0xa9, 0xb3, 0x70, 0xfe, 0xca, 0xd5, 0x3e, 0x5d, 0x7e, 0x6b, 0xcb, 0xef, 0xe5, 0xc9,
    0x51, 0x71, 0xd8, 0x69, 0x5d, 0x5f, 0x01, 0x64, 0x87, 0x9b, 0xf7, 0x98, 0x8c, 0xff, 0x6b, 0x8e,
    0x72, 0x1f, 0x9d, 0x76, 0x17, 0x7d, 0xd2, 0x58, 0x75, 0x05, 0xa9, 0xb0, 0x61, 0x6e, 0xa7, 0x83,
    0x28, 0x0a, 0x4a, 0x11, 0xa9, 0x19, 0x6c, 0x2c, 0xc5, 0x6a, 0x08, 0xc4, 0x7d, 0x1e, 0xf3, 0x73,
    0x9b, 0x10, 0x8e, 0x57, 0xc6, 0xdb, 0xb5, 0x2f, 0x8b, 0x6d, 0x5c, 0xa4, 0x88, 0x05, 0x82, 0xab,
    0xe5, 0x69, 0xd0, 0xc3, 0x3b, 0xb7, 0x26, 0xaa, 0x39, 0xa8, 0x5a, 0x04, 0x9a, 0xe8, 0x6f, 0x45,
    0xd1, 0x0a, 0xba, 0x3c, 0x2b, 0xab, 0xfe, 0xf9, 0x8e, 0x5d, 0x05, 0x6b, 0xc0, 0x6d, 0x46, 0x77,
    0xeb, 0xc1, 0xa3, 0x8f, 0x3b, 0x26, 0xfc, 0xe5, 0x5a, 0x6a, 0xee, 0x36, 0x1c, 0x2c, 0xf9, 0x60,
    0xbd, 0x7f, 0x7c, 0xf6, 0xf7, 0x93, 0xbd, 0x5b, 0xe7, 0x59, 0x40, 0xa5, 0x7d, 0x0b, 0xad, 0xd9,
    0x30, 0xcd, 0x08, 0xd2, 0xe1, 0xaf, 0x4c, 0x03, 0x9f, 0x11, 0x26, 0x02, 0x82, 0x02, 0x01, 0x00,
    0x85, 0xb4, 0x9b, 0xa6, 0x8f, 0x2a, 0xe7, 0x1b, 0x5f, 0xbd, 0x13, 0x5a, 0x82, 0x80, 0x81, 0x18,
    0xef, 0xd0, 0x24, 0x56, 0x47, 0x2d, 0xa9, 0xce, 0x2c, 0xc0, 0x5a, 0x11, 0x2b, 0xa3, 0xf8, 0xfc,
    0xff, 0x78, 0xc6, 0x54, 0x00, 0x01, 0x40, 0x4c, 0xb4, 0x05, 0x9f, 0xa3, 0xe3, 0x2d, 0x1c, 0xbe,
    0xd0, 0xe3, 0xa3, 0x72, 0x9d, 0xfb, 0x3b, 0xa1, 0x87, 0xe3, 0xf3, 0x99, 0x7f, 0x59, 0x75, 0xb4,
    0xb4, 0x48, 0x91, 0xe6, 0xf0, 0x59, 0x66, 0xf9, 0x42, 0x87, 0x16, 0xd8, 0x68, 0x07, 0x0d, 0xb8,
    0x19, 0x14, 0x3f, 0x42, 0x1a, 0x9d, 0xd9, 0x58, 0xee, 0xc4, 0x04, 0x4a, 0x75, 0x1c, 0xe0, 0x3f,
    0xcd, 0xfc, 0x3f, 0xf2, 0xfd, 0x61, 0xdb, 0x1d, 0x19, 0x68, 0x92, 0x68, 0x23, 0x8a, 0xd7, 0x1a,
    0xcb, 0xac, 0x99, 0x41, 0xc1, 0xd3, 0xd9, 0xd1, 0x5d, 0xe1, 0x55, 0xb3, 0x80, 0x2d, 0xd2, 0x7c,
    0xc2, 0x26, 0xb8, 0x6c, 0xb2, 0x8d, 0x76, 0x16, 0x89, 0x4f, 0x3f, 0xd6, 0xbf, 0xc1, 0x06, 0x97,
    0x6d, 0x89, 0xe9, 0xb9, 0xb9, 0x82, 0x83, 0xc1, 0xdf, 0xb0, 0x7c, 0x4e, 0x8a, 0xe3, 0xe6, 0x6c,
    0x50, 0x63, 0x59, 0xe5, 0x89, 0x3c, 0x3b, 0xbb, 0x9e, 0xd4, 0xdd, 0xb1, 0xfa, 0x51, 0xcf, 0x56,
    0x83, 0x47, 0xc9, 0x99, 0x71, 0x6e, 0xea, 0x60, 0x7a, 0x52, 0x67, 0x1e, 0x44, 0x07, 0xae, 0xb7,
    0x34, 0x51, 0xad, 0x59, 0x23, 0x4a, 0x07, 0xd5, 0xd3, 0xc2, 0xec, 0x26, 0xd9, 0xd8, 0x15, 0x11,
    0xc5, 0x4b, 0x45, 0xfd, 0x25, 0xe8, 0x66, 0x6d, 0xfe, 0xf6, 0x1a, 0x09, 0x74, 0xc9, 0x59, 0xf5,
    0x7a, 0x55, 0x85, 0x3f, 0x1d, 0x4b, 0x8f, 0xe0, 0x17, 0x49, 0x2a, 0x68, 0x75, 0x8d, 0x8d, 0x31,
    0xdc, 0xe9, 0x2d, 0x15, 0xe9, 0x1d, 0x53, 0x18, 0xb8, 0x69, 0x71, 0x89, 0xee, 0x2c, 0x1f, 0x3b,
    0xb2, 0xa6, 0x4e, 0xeb, 0x5a, 0x39, 0xc1, 0x60, 0x27, 0xb3, 0xe0, 0x76, 0x9a, 0x62, 0x60, 0x51,
    0x4f, 0x8f, 0x60, 0x1d, 0x82, 0xf5, 0x5f, 0x7e, 0xa5, 0xbd, 0x2d, 0x59, 0x11, 0x38, 0x68, 0xd4,
    0x98, 0x92, 0x47, 0x55, 0xea, 0x1d, 0xe4, 0x8d, 0x21, 0x5b, 0x2e, 0x4d, 0x42, 0x32, 0x7b, 0xc3,
    0x50, 0xc6, 0xbe, 0x31, 0xf8, 0x33, 0x26, 0x9d, 0xe7, 0xae, 0xb9, 0xa6, 0xa9, 0x95, 0x1b, 0x58,
    0x1d, 0x8b, 0x2f, 0x77, 0xe1, 0x16, 0x5d, 0x83, 0x86, 0x88, 0xf0, 0x87, 0x0f, 0xe9, 0xec, 0x52,
    0x31, 0x2d, 0xf4, 0x64, 0xff, 0x03, 0x8a, 0x2d, 0x92, 0xee, 0xda, 0x05, 0x76, 0x51, 0x02, 0xf9,
    0xb7, 0xad, 0x94, 0x5a, 0x89, 0xb6, 0xec, 0x41, 0x7b, 0x37, 0x0d, 0xb6, 0xa2, 0xa1, 0xba, 0x79,
    0x5d, 0xe0, 0xe4, 0xcb, 0x8c, 0xed, 0x39, 0xec, 0x7e, 0xad, 0xb5, 0x64, 0xc2, 0x72, 0x33, 0x2e,
    0xd0, 0x54, 0xa2, 0x2e, 0xd9, 0x0c, 0x6c, 0x74, 0xd0, 0xdc, 0x25, 0x29, 0x32, 0x98, 0x23, 0x05,
    0x64, 0xf3, 0x66, 0xa9, 0xb1, 0x17, 0x10, 0xe4, 0x7d, 0x8b, 0x7b, 0x88, 0x6c, 0x3d, 0x45, 0x84,
    0xb7, 0x30, 0xe0, 0x6d, 0xc2, 0xd1, 0x2e, 0xcd, 0x55, 0x11, 0xf5, 0x46, 0x0f, 0xb2, 0xa7, 0xe9,
    0xf0, 0x8f, 0xa5, 0x85, 0x39, 0x8e, 0xc9, 0xc7, 0x3c, 0xd9, 0xf1, 0xee, 0xb8, 0xd5, 0x48, 0xa3,
    0xbf, 0x21, 0x8c, 0x87, 0x14, 0x04, 0x92, 0x84, 0x34, 0xa3, 0x7b, 0x2f, 0xe5, 0x60, 0x29, 0x32,
    0x10, 0xbb, 0x8f, 0x89, 0x07, 0x41, 0x0c, 0xb5, 0x75, 0xb6, 0x52, 0x08, 0x98, 0x4b, 0x7c, 0x00,
    0xf5, 0x7f, 0xf5, 0x82, 0xc7, 0x97, 0x09, 0xdc, 0x14, 0xc5, 0xd2, 0x12, 0x02, 0x2c, 0x74, 0x67,
    0x32, 0xea, 0x7d, 0x7e, 0xa1, 0x6f, 0x75, 0xd4, 0x30, 0x2c, 0xcd, 0x62, 0xb4, 0xa8, 0x08, 0x4c,
    0x02, 0x82, 0x02, 0x00, 0x5d, 0x2d, 0x0c, 0x5d, 0xff, 0xb0, 0x23, 0xaa, 0x04, 0xbd, 0xb6, 0x2e,
    0xf6, 0x44, 0xba, 0xbc, 0x76, 0x33, 0xc3, 0x23, 0x4c, 0x63, 0x73, 0x2d, 0x40, 0x3f, 0x3f, 0x19,
    0xdd, 0x5b, 0x4c, 0x77, 0x0e, 0x5f, 0x5e, 0x38, 0x83, 0x40, 0x04, 0x14, 0x7f, 0x9d, 0x4a, 0x77,
    0x9f, 0x9f, 0x78, 0xc1, 0xd5, 0x9c, 0x30, 0xf5, 0xcf, 0x03, 0x6c, 0x22, 0xc2, 0xcd, 0xe7, 0x3f,
    0x6a, 0xac, 0xcc, 0xcc, 0xa3, 0xb1, 0x03, 0x81, 0x96, 0xd6, 0x5d, 0x54, 0xf7, 0xf6, 0x82, 0x31,
    0xcb, 0x08, 0xd9, 0x35, 0xa0, 0x07, 0x1b, 0xb7, 0x5e, 0xa6, 0x5e, 0x0f, 0x87, 0x6a, 0xa8, 0x50,
    0xe9, 0x05, 0x11, 0x72, 0x8e, 0x59, 0xd0, 0xb0, 0xa8, 0x4d, 0x38, 0xbf, 0xd7, 0x36, 0xb5, 0xb3,
    0x04, 0x21, 0x61, 0x6f, 0xdd, 0x7d, 0xb6, 0x0f, 0xb6, 0x45, 0x96, 0xec, 0x33, 0x92, 0x2f, 0x56,
    0xfa, 0x30, 0x73, 0xd2, 0x1d, 0x8e, 0x8e, 0xe1, 0x33, 0xee, 0xfc, 0xe1, 0xcc, 0x2a, 0x80, 0x56,
    0xc8, 0xb2, 0x20, 0x08, 0x8b, 0x8a, 0x55, 0x0d, 0x23, 0xfe, 0x06, 0x91, 0x22, 0xab, 0x6d, 0xec,
    0xae, 0xd6, 0x34, 0x72, 0x37, 0xc2, 0x77, 0xc3, 0xeb, 0xcc, 0xfb, 0xfe, 0x06, 0xd1, 0xc8, 0x24,
    0x80, 0x38, 0x11, 0xcb, 0x2d, 0x99, 0x18, 0x21, 0xdb, 0x47, 0x58, 0xd6, 0x9f, 0xd5, 0xa6, 0x27,
    0x0d, 0x76, 0xff, 0xa2, 0x8a, 0x71, 0x8e, 0xa3, 0xe2, 0x8d, 0x4c, 0x57, 0x5e, 0xa2, 0xa2, 0x44,
    0x65, 0x4f, 0xea, 0x80, 0x5f, 0x03, 0xd6, 0x74, 0xcd, 0xc4, 0xb1, 0x78, 0x82, 0x68, 0x06, 0x47,
    0xe1, 0x7c, 0x42, 0xa0, 0x4c, 0x94, 0xb6, 0x3a, 0x19, 0xde, 0x0a, 0x21, 0x49, 0x06, 0x05, 0xcf,
    0x60, 0xb0, 0x2f, 0x36, 0x1f, 0xef, 0x60, 0xaa, 0xe7, 0x63, 0xef, 0x9e, 0x95, 0x58, 0x60, 0xd3,
    0x8a, 0x1b, 0x1d, 0x36, 0x73, 0xc3, 0x34, 0xb2, 0x7f, 0xd4, 0xc9, 0xf4, 0x8e, 0x49, 0xbc, 0xbc,
    0x43, 0x23, 0xf6, 0xa8, 0x2a, 0x0a, 0xc8, 0x38, 0xa9, 0x3c, 0x98, 0x75, 0x5e, 0xd3, 0x80, 0xa0,
    0xb5, 0xdf, 0x65, 0xf1, 0xd3, 0xe4, 0xed, 0xc5, 0x27, 0x51, 0xc0, 0x9b, 0xc5, 0x89, 0xb1, 0xd6,
    0xb0, 0x96, 0x91, 0x90, 0xb1, 0xb8, 0x67, 0x53, 0x6b, 0xc5, 0x2c, 0x3e, 0x73, 0xd3, 0x2d, 0x08,
    0xea, 0x39, 0xeb, 0x67, 0x9f, 0x8a, 0xd8, 0x12, 0x2f, 0x8c, 0x55, 0x6d, 0x3a, 0xeb, 0xca, 0x51,
    0xcb, 0xb7, 0x9d, 0xe6, 0x30, 0x43, 0x68, 0x84, 0xfa, 0x8f, 0x56, 0x61, 0x7f, 0xc1, 0xf3, 0x37,
    0xab, 0x70, 0xdf, 0x37, 0xc2, 0x38, 0x4c, 0x27, 0xbd, 0xf9, 0xd1, 0x7c, 0xee, 0xcc, 0xc5, 0xda,
    0xad, 0xbe, 0x4d, 0xa8, 0x5a, 0xf1, 0xb3, 0xaa, 0x12, 0x20, 0x41, 0x48, 0x0e, 0x29, 0x59, 0x76,
    0xd0, 0x42, 0x2a, 0xc7, 0x0c, 0x83, 0x98, 0xad, 0xea, 0xb0, 0xa8, 0xc3, 0x08, 0xef, 0x6b, 0xf7,
    0xda, 0x06, 0xbf, 0x11, 0x76, 0xbc, 0x6d, 0x57, 0xb3, 0x0d, 0x0f, 0xbd, 0x3a, 0x96, 0x80, 0x45,
    0x8b, 0x98, 0xaf, 0xd2, 0x03, 0xea, 0x40, 0x3d, 0x84, 0x97, 0x84, 0x17, 0x27, 0xec, 0x52, 0x92,
    0x73, 0xcd, 0x84, 0x81, 0x9b, 0x85, 0x14, 0x5a, 0x91, 0x88, 0xee, 0xb5, 0x7e, 0xcd, 0xcd, 0x77,
    0x0c, 0xc9, 0xf0, 0x8b, 0xe3, 0x6c, 0x75, 0xfd, 0xd8, 0x1b, 0x52, 0x5f, 0x0c, 0x95, 0xe0, 0xaf,
    0xab, 0x0b, 0x63, 0x5c, 0x16, 0x39, 0x39, 0x84, 0x8a, 0xb8, 0xb9, 0x56, 0x0a, 0xbc, 0x97, 0x4b,
    0x97, 0x40, 0xb0, 0xe4, 0xfb, 0xe7, 0x10, 0xb0, 0x10, 0x31, 0x07, 0x4b, 0x73, 0x60, 0x68, 0x5d,
    0x53, 0x00, 0x77, 0x2b, 0xa8, 0x94, 0x88, 0x9b, 0xb3, 0x06, 0x23, 0x7c, 0x6d, 0x07, 0x9b, 0x9c,
    0xad, 0x78, 0x21, 0xa9
};

static unsigned char raw_encrypted_message[1032] = {
    0x30, 0x82, 0x04, 0x04, 0x02, 0x82, 0x04, 0x00, 0x38, 0x7e, 0xa8, 0x0f, 0xd2, 0xd7, 0xa1, 0x82,
    0x35, 0xe9, 0x73, 0xeb, 0x8f, 0x81, 0x3e, 0x53, 0x8e, 0x07, 0x2c, 0x09, 0xea, 0x91, 0x11, 0x8c,
    0x08, 0x38, 0x91, 0x50, 0x56, 0xb6, 0x39, 0x82, 0x74, 0x60, 0xfc, 0xb6, 0xd1, 0xaa, 0x1a, 0x53,
    0x6d, 0x73, 0xdd, 0xe6, 0x17, 0xb3, 0x90, 0xd6, 0x37, 0x04, 0x13, 0xef, 0xf0, 0xdf, 0xbf, 0xa0,
    0x18, 0x41, 0xcd, 0x1d, 0x30, 0x41, 0x28, 0xaa, 0x53, 0x79, 0x32, 0x1a, 0x66, 0x50, 0xa4, 0xec,
    0xb5, 0xc0, 0xae, 0x71, 0x71, 0xa1, 0xe7, 0x6d, 0x10, 0x8f, 0x72, 0xd2, 0x8e, 0x73, 0xfd, 0xfa,
    0xcf, 0x85, 0x9f, 0x74, 0xa0, 0x52, 0xd7, 0x0b, 0xf9, 0x25, 0x41, 0x94, 0x59, 0x0e, 0x10, 0x3b,
    0x60, 0x82, 0x21, 0xf4, 0xf3, 0x44, 0x85, 0x20, 0xed, 0x37, 0x5f, 0xe3, 0x16, 0x57, 0x57, 0xf5,
    0x32, 0x70, 0x9d, 0x73, 0x4c, 0x89, 0xce, 0x32, 0x01, 0x2c, 0xcb, 0x8f, 0x9f, 0xe2, 0x48, 0x0e,
    0xe9, 0xa5, 0xd6, 0x46, 0xb3, 0x5c, 0x88, 0x12, 0xfb, 0xdc, 0x0a, 0x20, 0x49, 0x44, 0xf3, 0x47,
    0x60, 0x1e, 0x7e, 0xee, 0xf9, 0x5a, 0xef, 0x36, 0xac, 0xbe, 0xb2, 0xd6, 0x3b, 0xad, 0x2a, 0x49,
    0x94, 0x13, 0x5d, 0x37, 0x9e, 0xc3, 0xd9, 0x44, 0xdc, 0x49, 0x13, 0xc0, 0x7e, 0xef, 0x1b, 0x32,
    0x28, 0x54, 0x39, 0x04, 0x1f, 0x85, 0xdb, 0x66, 0xdb, 0x94, 0xe0, 0x2a, 0x5d, 0x37, 0x7c, 0xf2,
    0x40, 0x91, 0xd2, 0x8b, 0xa6, 0x9c, 0xc2, 0xb7, 0x7a, 0xb1, 0xa5, 0x66, 0x2d, 0x12, 0xff, 0x3a,
    0x4a, 0xf6, 0x6f, 0x99, 0x9c, 0x65, 0x2a, 0x6d, 0xcb, 0x91, 0x76, 0x73, 0xac, 0x02, 0x31, 0x00,
    0x4c, 0x19, 0x1e, 0x63, 0x1e, 0x6b, 0xc1, 0x1c, 0x26, 0x47, 0xed, 0x53, 0x7c, 0x65, 0xa3, 0x18,
    0x02, 0xd2, 0xa4, 0x03, 0xba, 0xdd, 0xb2, 0x59, 0x0c, 0xa2, 0xad, 0x6e, 0x70, 0xad, 0x4a, 0xb1,
    0x43, 0xe7, 0x9c, 0x49, 0x70, 0x8e, 0xc4, 0xcf, 0x97, 0x41, 0x29, 0x3d, 0x12, 0xff, 0x29, 0x0e,
    0x9f, 0xc4, 0x2e, 0x04, 0x37, 0x02, 0xa1, 0x75, 0x8b, 0x4f, 0xe6, 0x74, 0xbc, 0x8c, 0x1d, 0x89,
    0x3c, 0xfb, 0xb7, 0x25, 0xff, 0x8e, 0x9a, 0xb3, 0x23, 0x93, 0x27, 0x8b, 0x18, 0xcb, 0x54, 0x18,
    0xc0, 0xb2, 0xe2, 0x77, 0xd1, 0xe7, 0x97, 0xc9, 0x3d, 0xa9, 0xff, 0x38, 0x61, 0x07, 0xff, 0x76,
    0x6b, 0x2d, 0x06, 0x3c, 0xae, 0xcf, 0xf9, 0xb0, 0x72, 0x6d, 0x6b, 0xd3, 0x76, 0x99, 0xfd, 0xdd,
    0x85, 0x29, 0x2d, 0x1e, 0x7d, 0x73, 0xed, 0x9f, 0xfc, 0x65, 0x92, 0x94, 0xa4, 0x13, 0x57, 0x2f,
    0x20, 0x26, 0x4d, 0xe7, 0xcb, 0xb0, 0xe4, 0x2f, 0xf3, 0x20, 0xe1, 0x3a, 0x4d, 0x5e, 0x80, 0x42,
    0x3b, 0x3f, 0xb0, 0xf2, 0xb7, 0x5a, 0x8f, 0x49, 0x8f, 0x5c, 0x9e, 0xfa, 0x27, 0x2c, 0x8d, 0x9f,
    0x28, 0x16, 0xbe, 0xa6, 0x61, 0xfe, 0xd7, 0xf8, 0xf2, 0x01, 0xf4, 0x9a, 0xd3, 0xc1, 0xab, 0x3a,
    0x71, 0x4d, 0x51, 0x20, 0xe1, 0xd8, 0x9b, 0x5f, 0xdf, 0xda, 0x5e, 0x8a, 0xf0, 0x00, 0x98, 0xdf,
    0x16, 0x24, 0x45, 0x72, 0x9f, 0x14, 0x90, 0x4e, 0x72, 0x3b, 0xf9, 0xac, 0x09, 0xda, 0x74, 0xee,
    0x89, 0x41, 0x57, 0x30, 0x16, 0x22, 0x4e, 0x4e, 0xd5, 0x5b, 0x3e, 0x65, 0x33, 0x02, 0x24, 0x22,
    0x56, 0x95, 0x68, 0x78, 0xa3, 0x21, 0xae, 0xe3, 0x1b, 0x2e, 0x24, 0x53, 0x8b, 0x9b, 0x1a, 0x44,
    0xdb, 0x82, 0xf3, 0xeb, 0x75, 0xe2, 0x8c, 0x47, 0x67, 0x5d, 0x74, 0x63, 0xdf, 0x3f, 0xdf, 0x6d,
    0x99, 0x47, 0x1b, 0xf3, 0x50, 0xe1, 0x89, 0x13, 0x24, 0x98, 0x8a, 0x0e, 0xeb, 0x61, 0x9c, 0xda,
    0xbe, 0xc0, 0x63, 0xa2, 0x4c, 0x08, 0xd1, 0x31, 0x69, 0x02, 0x1e, 0x54, 0x9b, 0x27, 0x9e, 0xef,
    0xa3, 0x3b, 0x7d, 0xca, 0xe6, 0x69, 0x01, 0x85, 0xb0, 0xd0, 0xa3, 0x2c, 0xb1, 0x62, 0x5a, 0x57,
    0xa8, 0x1e, 0x0e, 0x50, 0xe7, 0x69, 0x32, 0x8c, 0x36, 0x81, 0xd5, 0xa4, 0x75, 0xc3, 0xbc, 0x1e,
    0x73, 0xd0, 0x01, 0xa9, 0x3e, 0x22, 0xf9, 0x20, 0x76, 0x5c, 0x76, 0xc2, 0xc4, 0x44, 0xd1, 0x3f,
    0x6a, 0x17, 0x7e, 0x82, 0xe5, 0x98, 0x3e, 0x74, 0x05, 0x90, 0x2a, 0xab, 0xe5, 0x6e, 0xc9, 0x4e,
    0x76, 0x60, 0x28, 0x07, 0xf7, 0xa1, 0x1e, 0xb4, 0x26, 0x03, 0x26, 0xad, 0x9f, 0x7f, 0xa9, 0x25,
    0x6a, 0xce, 0xcc, 0xf6, 0x7b, 0x29, 0xe1, 0x43, 0x78, 0x01, 0x05, 0x64, 0x7e, 0x32, 0x7e, 0xdf,
    0x78, 0x4c, 0x1a, 0x08, 0x82, 0x3d, 0xea, 0xca, 0x8e, 0xbb, 0xaa, 0x0c, 0x51, 0xa2, 0xaf, 0x5b,
    0xc7, 0x2e, 0x8a, 0xb2, 0x23, 0x70, 0xbf, 0xfc, 0xf0, 0xe7, 0x6e, 0xf4, 0x29, 0x0a, 0x9b, 0x66,
    0x8f, 0x59, 0x22, 0x38, 0xc3, 0x11, 0x0c, 0x53, 0x08, 0xf4, 0x50, 0xdc, 0x41, 0xd6, 0xaf, 0xdf,
    0x26, 0x19, 0x32, 0x94, 0xfd, 0xbc, 0x6c, 0x48, 0xbe, 0xac, 0x4a, 0x99, 0xaa, 0x4f, 0x1e, 0x37,
    0xc0, 0x90, 0xfa, 0x45, 0x86, 0x08, 0x57, 0x82, 0xc7, 0x1f, 0x8b, 0xb3, 0x1b, 0x01, 0xb4, 0xff,
    0x14, 0x74, 0xfc, 0xe4, 0x82, 0x2a, 0xdc, 0x16, 0xe7, 0xd3, 0x3c, 0x49, 0xf3, 0x46, 0x40, 0xad,
    0x00, 0x58, 0x95, 0x63, 0x95, 0x05, 0xcb, 0xcd, 0xbf, 0x95, 0xd9, 0x89, 0xc5, 0x8b, 0x44, 0x10,
    0x4b, 0x64, 0xde, 0xf9, 0x5e, 0x0c, 0xca, 0xd6, 0x24, 0xd5, 0x48, 0xcb, 0xe5, 0x89, 0x3c, 0x6d,
    0xac, 0x80, 0x3d, 0xf3, 0x29, 0xcf, 0xdc, 0x77, 0x27, 0x6d, 0x9f, 0x38, 0xae, 0x43, 0x72, 0xce,
    0x84, 0x97, 0x01, 0x6b, 0xa3, 0x1c, 0xb6, 0x11, 0x60, 0xfa, 0x26, 0xdb, 0xbe, 0xb6, 0x2f, 0xd1,
    0xaa, 0x1a, 0xf8, 0x16, 0x77, 0x09, 0x9a, 0x95, 0x5d, 0x74, 0x47, 0x15, 0x07, 0x71, 0x69, 0x3b,
    0x58, 0x91, 0x78, 0xa9, 0xbc, 0x97, 0x94, 0x4a, 0x05, 0x36, 0x91, 0x33, 0x50, 0x6c, 0xbe, 0xf0,
    0xd4, 0x2a, 0xf7, 0x58, 0xa2, 0xa5, 0x9e, 0x0c, 0x42, 0xa4, 0x3c, 0x07, 0x32, 0xdf, 0xa9, 0x67,
    0xdd, 0x42, 0x2d, 0x4a, 0xb3, 0xb8, 0x5d, 0x29, 0x29, 0x03, 0xad, 0xba, 0xc7, 0xa0, 0xc0, 0x14,
    0x93, 0xf4, 0xd5, 0xe0, 0x6c, 0x14, 0x03, 0x2e, 0x87, 0x63, 0xaa, 0xe5, 0x20, 0x42, 0xb8, 0x0a,
    0x30, 0x65, 0xee, 0x2a, 0x8b, 0xe8, 0x73, 0xe3, 0x07, 0x22, 0x67, 0x10, 0x11, 0x4a, 0x52, 0xc1,
    0xd3, 0xc8, 0xbf, 0x07, 0x1d, 0xc0, 0x5f, 0x00, 0xaf, 0x45, 0xcf, 0x6c, 0x14, 0xe1, 0x1a, 0x1d,
    0x3b, 0x97, 0x83, 0x28, 0x9f, 0x84, 0x3c, 0xb3, 0x02, 0x9f, 0x40, 0xb3, 0x46, 0x1a, 0x78, 0x3d,
    0x6b, 0x0d, 0xb0, 0x73, 0x12, 0x2e, 0x76, 0xe2, 0x40, 0xd5, 0x14, 0x82, 0xbc, 0x89, 0x60, 0x4a,
    0x35, 0x4a, 0x9d, 0xf2, 0x0a, 0x15, 0x33, 0xd0, 0xf3, 0x1d, 0x23, 0x22, 0x71, 0x9d, 0x88, 0x12,
    0x73, 0x9c, 0x70, 0xe5, 0x7c, 0xb0, 0x68, 0xab, 0xeb, 0x33, 0xd7, 0x25, 0xb0, 0x57, 0xae, 0xe0,
    0x44, 0x71, 0xf3, 0xe2, 0xcf, 0xa2, 0xc8, 0xde, 0xbb, 0x55, 0xdc, 0xdc, 0xf6, 0xfd, 0xcd, 0x80,
    0xf3, 0x96, 0x97, 0x72, 0x42, 0x94, 0x20, 0x8f, 0x92, 0xf4, 0xdd, 0x82, 0xcb, 0xfe, 0x12, 0xdd,
    0xa1, 0x3d, 0x4d, 0x49, 0x72, 0x8b, 0x0f, 0x23, 0xd4, 0x44, 0x1b, 0xa2, 0xe5, 0xa3, 0x90, 0x9a,
    0xdc, 0xc6, 0x0f, 0xfb, 0xed, 0x15, 0x50, 0x88, 0x9c, 0xd4, 0xfa, 0x03, 0x96, 0x33, 0x8d, 0xcb,
    0x83, 0xf0, 0x25, 0xa8, 0x8d, 0xe8, 0x2e, 0x18
};

static void bench_paillier_enc_setup(void* arg) {
    int i;
    bench_paillier_enc_data *data = (bench_paillier_enc_data*)arg;

    for (i = 0; i < 32; i++) {
        data->msg[i] = i + 1;
    }

    data->pub = secp256k1_paillier_pubkey_create();
    data->enc = secp256k1_paillier_message_create();
    CHECK(secp256k1_paillier_pubkey_parse(data->pub, raw_pubkey, 1041) == 1);

    mpz_init(data->nonce);
    paillier_nonce_function(data->nonce, data->pub->modulus);
}

static void bench_paillier_dec_setup(void* arg) {
    bench_paillier_dec_data *data = (bench_paillier_dec_data*)arg;

    data->priv = secp256k1_paillier_privkey_create();
    data->pub = secp256k1_paillier_pubkey_create();
    data->msg = secp256k1_paillier_message_create();
    mpz_init(data->res);
    CHECK(secp256k1_paillier_privkey_parse(data->priv, data->pub, raw_privkey, 2596) == 1);
    CHECK(secp256k1_paillier_message_parse(data->msg, raw_encrypted_message, 1032) == 1);
}

static void bench_paillier_add_setup(void* arg) {
    bench_paillier_add_data *data = (bench_paillier_add_data*)arg;

    data->pub = secp256k1_paillier_pubkey_create();
    data->msg1 = secp256k1_paillier_message_create();
    data->msg2 = secp256k1_paillier_message_create();
    data->res = secp256k1_paillier_message_create();
    CHECK(secp256k1_paillier_pubkey_parse(data->pub, raw_pubkey, 1041) == 1);
    CHECK(secp256k1_paillier_message_parse(data->msg1, raw_encrypted_message, 1032) == 1);
    CHECK(secp256k1_paillier_message_parse(data->msg2, raw_encrypted_message, 1032) == 1);
}

static void bench_paillier_scal_setup(void* arg) {
    bench_paillier_scal_data *data = (bench_paillier_scal_data*)arg;

    data->pub = secp256k1_paillier_pubkey_create();
    data->msg1 = secp256k1_paillier_message_create();
    data->res = secp256k1_paillier_message_create();
    mpz_init(data->msg2);
    CHECK(secp256k1_paillier_pubkey_parse(data->pub, raw_pubkey, 1041) == 1);
    CHECK(secp256k1_paillier_message_parse(data->msg1, raw_encrypted_message, 1032) == 1);
    mpz_set_ui(data->msg2, 10);
}

static void bench_paillier_enc_teardown(void* arg) {
    bench_paillier_enc_data *data = (bench_paillier_enc_data*)arg;

    secp256k1_paillier_pubkey_destroy(data->pub);
    secp256k1_paillier_message_destroy(data->enc);
    mpz_clear(data->nonce);
}

static void bench_paillier_dec_teardown(void* arg) {
    bench_paillier_dec_data *data = (bench_paillier_dec_data*)arg;

    secp256k1_paillier_privkey_destroy(data->priv);
    secp256k1_paillier_pubkey_destroy(data->pub);
    secp256k1_paillier_message_destroy(data->msg);
    mpz_clear(data->res);
}

static void bench_paillier_add_teardown(void* arg) {
    bench_paillier_add_data *data = (bench_paillier_add_data*)arg;

    secp256k1_paillier_pubkey_destroy(data->pub);
    secp256k1_paillier_message_destroy(data->msg1);
    secp256k1_paillier_message_destroy(data->msg2);
    secp256k1_paillier_message_destroy(data->res);
}

static void bench_paillier_scal_teardown(void* arg) {
    bench_paillier_scal_data *data = (bench_paillier_scal_data*)arg;

    secp256k1_paillier_pubkey_destroy(data->pub);
    secp256k1_paillier_message_destroy(data->msg1);
    secp256k1_paillier_message_destroy(data->res);
    mpz_clear(data->msg2);
}

static void bench_paillier_enc(void* arg) {
    int i;
    bench_paillier_enc_data *data = (bench_paillier_enc_data*)arg;

    for (i = 0; i < 100; i++) {
        int j;
        size_t out;
        unsigned char* ser;
        secp256k1_paillier_encrypt_r(data->enc, data->msg, 32, data->pub, data->nonce);
        ser = secp256k1_paillier_message_serialize(&out, data->enc);
        mpz_add_ui(data->nonce, data->nonce, 1);
        for (j = 0; j < 32 && j < (int)out; j++) {
            data->msg[j] = ser[j];
        }
    }
}

static void bench_paillier_dec(void* arg) {
    int i;
    bench_paillier_dec_data *data = (bench_paillier_dec_data*)arg;

    for (i = 0; i < 100; i++) {
        secp256k1_paillier_decrypt(data->res, data->msg, data->priv);
    }
}

static void bench_paillier_add(void* arg) {
    int i;
    bench_paillier_add_data *data = (bench_paillier_add_data*)arg;

    for (i = 0; i < 20000; i++) {
        secp256k1_paillier_add(data->res, data->msg1, data->msg2, data->pub);
        mpz_set(data->msg1->message, data->msg2->message);
        mpz_set(data->msg2->message, data->res->message);
    }
}

static void bench_paillier_add_scal(void* arg) {
    int i;
    bench_paillier_scal_data *data = (bench_paillier_scal_data*)arg;

    for (i = 0; i < 20000; i++) {
        secp256k1_paillier_add_scalar(data->res, data->msg1, data->msg2, data->pub);
        mpz_add_ui(data->msg2, data->msg2, 10);
    }
}

static void bench_paillier_mul(void* arg) {
    int i;
    bench_paillier_scal_data *data = (bench_paillier_scal_data*)arg;

    for (i = 0; i < 20000; i++) {
        secp256k1_paillier_mult(data->res, data->msg1, data->msg2, data->pub);
        mpz_add_ui(data->msg2, data->msg2, 10);
    }
}

int main(void) {
    bench_paillier_enc_data enc_data;
    bench_paillier_dec_data dec_data;
    bench_paillier_add_data add_data;
    bench_paillier_scal_data add_scal_data;

    run_benchmark("paillier_enc", bench_paillier_enc, bench_paillier_enc_setup, bench_paillier_enc_teardown, &enc_data, 10, 100);
    run_benchmark("paillier_dec", bench_paillier_dec, bench_paillier_dec_setup, bench_paillier_dec_teardown, &dec_data, 10, 100);
    run_benchmark("paillier_add", bench_paillier_add, bench_paillier_add_setup, bench_paillier_add_teardown, &add_data, 10, 20000);
    run_benchmark("paillier_add_scal", bench_paillier_add_scal, bench_paillier_scal_setup, bench_paillier_scal_teardown, &add_scal_data, 10, 20000);
    run_benchmark("paillier_mul", bench_paillier_mul, bench_paillier_scal_setup, bench_paillier_scal_teardown, &add_scal_data, 10, 20000);

    return 0;
}
