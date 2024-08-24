/*
* Software Name : RFEDP
* Version: 1.1
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at 
*     http://www.apache.org/licenses/LICENSE-2.0 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Author: Ferran Alborch Escobar <ferran.alborch@gmail.com>
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>
#include <mcl/bn_c384_256.h>
#include "RFE/ripfe_FH.h"
#include "config.h"

int ripfe_FH_precomp_init(ripfe_FH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y) {
    S->epsilon = EPSILON;
    S->Q = Q;
    S->l = l;

    int err = ipfe_FH_precomp_init(&S->s, l + 1, bound_X, bound_Y);

    return err;    
}

void ripfe_FH_free(ripfe_FH *S) {
    ipfe_FH_free(&S->s);
    return;
}

void ripfe_FH_sec_key_init(ripfe_FH_sec_key *MSK, ripfe_FH *S) {
    ipfe_FH_sec_key_init(&MSK->msk_ipfe, &S->s);
    return; 
}

void ripfe_FH_sec_key_free(ripfe_FH_sec_key *MSK) {
    ipfe_FH_sec_key_free(&MSK->msk_ipfe);
	return;
}

void ripfe_FH_fe_key_init(ripfe_FH_fe_key *FE_key, ripfe_FH *S) {
    ipfe_FH_fe_key_init(&FE_key->fe_key, &S->s);
    return;
}

void ripfe_FH_fe_key_free(ripfe_FH_fe_key *FE_key) {
    ipfe_FH_fe_key_free(&FE_key->fe_key);
    return;
}

void ripfe_FH_ciphertext_init(ripfe_FH_ciphertext *c, ripfe_FH *S) {
    ipfe_FH_ciphertext_init(&c->ct_ipfe, &S->s);
    c->l = S->l;
    return;
}

void ripfe_FH_ciphertext_free(ripfe_FH_ciphertext *c) {
    ipfe_FH_ciphertext_free(&c->ct_ipfe);
    return;
}

int ripfe_FH_generate_master_keys(ripfe_FH_sec_key *MSK, double timesSetUp[]) {
    // Run ipfh_FH_generate_master_keys
    return ipfe_FH_generate_master_keys(&MSK->msk_ipfe, timesSetUp);
}

int ripfe_FH_encrypt(ripfe_FH_ciphertext *c, ripfe_FH *S, mpz_t *x, ripfe_FH_sec_key *MSK, double timesEnc[]) {
    // Verify x is in bound
    clock_t begin = clock();
	int check = 0;
    for(size_t i = 0; i < S->l; ++i) {
        if(mpz_cmp(x[i], S->s.bound_X) > 0) {
            check = 1;
        }
        if(check != 0) break;
    }
    if(check != 0) return 1;
    clock_t end = clock();
    timesEnc[2] = timesEnc[2] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Compute input for ipfe_FH_encrypt_unbounded
    begin = clock();
    mclBnFr *x_ipfe;
    x_ipfe = (mclBnFr *) malloc(S->s.l * sizeof(mclBnFr));
    for(size_t i = 0; i < c->l; ++i) mpz_to_mclBnFr(&x_ipfe[i], &x[i], 1);
	mpz_t one;
	mpz_init(one);
	mpz_set_ui(one, 1);
	mpz_to_mclBnFr(&x_ipfe[c->l], &one, 1);
    end = clock();
    timesEnc[3] = timesEnc[3] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Encrypt through ipfe_FH_unbounded
    int verify = ipfe_FH_encrypt_unbounded(&c->ct_ipfe, &S->s, x_ipfe, &MSK->msk_ipfe, timesEnc);

    // Clear auxiliary values
    free(x_ipfe);
	mpz_clear(one);

    return verify;
}

int ripfe_FH_derive_fe_key(ripfe_FH_fe_key *FE_key, ripfe_FH *S, ripfe_FH_sec_key *MSK, mpz_t *y, mpz_t e_verification, double timesKeyGen[]) {
    // Verify y is in bound
    clock_t begin = clock();
    int check = 0;
    for(size_t i = 0; i < S->l; ++i) {
		if(mpz_cmp(y[i], S->s.bound_Y) > 0) {
			check = 1;
		}
		if(check != 0) break;
    }
    if(check != 0) return 1;
    clock_t end = clock();
    timesKeyGen[2] = timesKeyGen[2] + (double)(end - begin) / CLOCKS_PER_SEC;
    
    // Generate e
    begin = clock();
    mclBnFr e;
    mpz_t e_mpz;
    mpz_init(e_mpz);
    sample_geometric_IP(e_mpz, S->epsilon, S->s.bound_Y, S->Q);
    mpz_set(e_verification, e_mpz);
    mpz_to_mclBnFr(&e, &e_mpz, 1);

    // Compute vector input for ipfe_FH_derive_fe_key
    begin = clock();
    mclBnFr *y_ipfe;
    y_ipfe = (mclBnFr *) malloc(S->s.l * sizeof(mclBnFr));
    for(size_t i = 0; i < S->l; ++i) mpz_to_mclBnFr(&y_ipfe[i], &y[i], 1);
	y_ipfe[S->l] = e;
    end = clock();
    timesKeyGen[3] = timesKeyGen[3] + (double)(end - begin) / CLOCKS_PER_SEC;


    // Use ipfe_FH_fe_derive_key_unbounded
    ipfe_FH_derive_fe_key_unbounded(&FE_key->fe_key, &S->s, &MSK->msk_ipfe, y_ipfe, timesKeyGen);

    // Clear auxiliary values
    mpz_clear(e_mpz);
    free(y_ipfe);
    return check;
}

int ripfe_FH_decrypt(mpz_t *result, mpz_t *y, ripfe_FH *S, ripfe_FH_ciphertext *c, ripfe_FH_fe_key *FE_key, double timesDec[]) {
	// Compute bound
	clock_t begin = clock();
	mpz_t alpha, aux, bound;
    mpz_inits(alpha, aux, bound, NULL);
	mpz_mul_ui(alpha, S->s.bound_Y, S->Q);
    mpz_mul_ui(alpha, alpha, 1024);
    for(size_t i = 0; i < S->l; ++i) {
        mpz_mul(aux, S->s.bound_X, y[i]);
        mpz_add(bound, bound, aux);
    }
    mpz_add(bound, bound, alpha);
	clock_t end = clock();
	timesDec[2] = timesDec[2] + ((double )(end - begin) / CLOCKS_PER_SEC);

    // Decrypt using ipfe_FH
    int output = ipfe_FH_decrypt(result, &S->s, &c->ct_ipfe, &FE_key->fe_key, bound, timesDec);

    // Clear auxiliary values
    mpz_clears(bound, alpha, aux, NULL);
    return output;
}