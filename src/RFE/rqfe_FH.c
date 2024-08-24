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
#include "RFE/rqfe_FH.h"
#include "config.h"

int rqfe_FH_precomp_init(rqfe_FH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y) {
    S->epsilon = EPSILON;
    S->Q = Q;
    S->l = l;

    int err = ipfe_FH_precomp_init(&S->s, 2 * l, bound_X, bound_Y);

    return err;    
}

void rqfe_FH_free(rqfe_FH *S) {
    ipfe_FH_free(&S->s);
    return;
}

void rqfe_FH_sec_key_init(rqfe_FH_sec_key *MSK, rqfe_FH *S) {
    ipfe_FH_sec_key_init(&MSK->msk_ipfe, &S->s);

    MSK->u = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
    MSK->w = (mclBnFr *) malloc((2 * S->l) * sizeof(mclBnFr));
    MSK->l = S->l;
    return; 
}

void rqfe_FH_sec_key_free(rqfe_FH_sec_key *MSK) {
    ipfe_FH_sec_key_free(&MSK->msk_ipfe);

    free(MSK->u);
    free(MSK->w);
}

void rqfe_FH_fe_key_init(rqfe_FH_fe_key *FE_key, rqfe_FH *S) {
    ipfe_FH_fe_key_init(&FE_key->fe_key, &S->s);
    return;
}

void rqfe_FH_fe_key_free(rqfe_FH_fe_key *FE_key) {
    ipfe_FH_fe_key_free(&FE_key->fe_key);
    return;
}

void rqfe_FH_ciphertext_init(rqfe_FH_ciphertext *c, rqfe_FH *S) {
    c->ct = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
    ipfe_FH_ciphertext_init(&c->ct_ipfe, &S->s);
    c->l = S->l;
    return;
}

void rqfe_FH_ciphertext_free(rqfe_FH_ciphertext *c) {
    free(c->ct);
    ipfe_FH_ciphertext_free(&c->ct_ipfe);
    return;
}

int rqfe_FH_generate_master_keys(rqfe_FH_sec_key *MSK, double timesSetUp[]) {
    // Sample c
    clock_t begin = clock();
    mclBnFr_setByCSPRNG(&MSK->c);
    clock_t end = clock();
    timesSetUp[1] = timesSetUp[1] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Sample u
    begin = clock();
    for(size_t i = 0; i < MSK->l; ++i) mclBnFr_setByCSPRNG(&MSK->u[i]); 
    end = clock();
    timesSetUp[2] = timesSetUp[2] + (double)(end - begin) / CLOCKS_PER_SEC;       

    // Sample w
    begin = clock();
    for(size_t i = 0; i < 2 * MSK->l; ++i) mclBnFr_setByCSPRNG(&MSK->w[i]);
    end = clock();
    timesSetUp[2] = timesSetUp[2] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Run ipfh_FH_generate_master_keys
    return ipfe_FH_generate_master_keys(&MSK->msk_ipfe, timesSetUp);
}

int rqfe_FH_encrypt(rqfe_FH_ciphertext *c, rqfe_FH *S, mpz_t *x, rqfe_FH_sec_key *MSK, double timesEnc[]) {
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


    // Swap the plaintext from mpz_t to mclBnFr
	mclBnFr *xFr;
	xFr = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
	mpz_to_mclBnFr(xFr, x, S->l);

    // Compute ct
    begin = clock();
    mclBnFr aux_Fr;
    for(size_t i = 0; i < S->l; ++i) {
        //mclBnFr_clear(&c->ct[i]);
        mclBnFr_mul(&aux_Fr, &MSK->c, &MSK->u[i]);
        mclBnFr_add(&c->ct[i], &aux_Fr, &xFr[i]);
    }
    end = clock();
    timesEnc[3] = timesEnc[3] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Compute input for ipfe_FH_encrypt_unbounded
    begin = clock();
    mclBnFr *x_ipfe;
    x_ipfe = (mclBnFr *) malloc(S->s.l * sizeof(mclBnFr));
    for(size_t i = 0; i < S->l; ++i) {
        mclBnFr_mul(&aux_Fr, &MSK->c, &c->ct[i]);
        mclBnFr_add(&x_ipfe[i], &aux_Fr, &MSK->w[i]);
    
        mclBnFr_mul(&aux_Fr, &MSK->c, &xFr[i]);
        mclBnFr_add(&x_ipfe[S->l + i], &aux_Fr, &MSK->w[S->l + i]);
    }
    end = clock();
    timesEnc[4] = timesEnc[4] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Encrypt through ipfe_FH_unbounded
    int verify = ipfe_FH_encrypt_unbounded(&c->ct_ipfe, &S->s, x_ipfe, &MSK->msk_ipfe, timesEnc);


    // Clear auxiliary values
    free(xFr);
    free(x_ipfe);

    return verify;
}

int rqfe_FH_derive_fe_key(rqfe_FH_fe_key *FE_key, rqfe_FH *S, rqfe_FH_sec_key *MSK, mpz_t **F, mpz_t e_verification, double timesKeyGen[]) {
    // Verify F is in bound and swap to mclBnFr
    clock_t begin = clock();
    int check = 0;
    mclBnFr **FFr;
    FFr = (mclBnFr **) malloc(S->l * sizeof(mclBnFr*));
    for(size_t i = 0; i < S->l; ++i) {
        FFr[i] = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
        for(size_t j = 0; j < S->l; ++j) {
            if(mpz_cmp(F[i][j], S->s.bound_Y) > 0) {
                check = 1;
            }
            if(check != 0) break;
            mpz_to_mclBnFr(&FFr[i][j], &F[i][j], 1);
        }
    }
    if(check != 0) return 1;
    clock_t end = clock();
    timesKeyGen[2] = timesKeyGen[2] + (double)(end - begin) / CLOCKS_PER_SEC;
    
    // Generate e
    begin = clock();
    mclBnFr e;
    mpz_t e_mpz;
    mpz_init(e_mpz);
    sample_geometric_Q(e_mpz, S->epsilon, S->s.bound_X, S->s.bound_Y, S->Q, S->l);
    mpz_set(e_verification, e_mpz);
    mpz_to_mclBnFr(&e, &e_mpz, 1);

    // Generate u_F
    mclBnFr u_F;
    mclBnFr_setByCSPRNG(&u_F);

    // Compute t_prime
    mclBnFr_add(&FE_key->t_prime, &e, &u_F);
    end = clock();
    timesKeyGen[3] = timesKeyGen[3] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Compute vector input for ipfe_FH_derive_fe_key
    begin = clock();
    mclBnFr *y_ipfe;
    y_ipfe = (mclBnFr *) malloc(S->s.l * sizeof(mclBnFr));
    mclBnFr aux;
    for(size_t i = 0; i < S->l; ++i) {
        mclBnFr_clear(&y_ipfe[i]);
        for(size_t j = 0; j < S->l; ++j) {
            mclBnFr_mul(&aux, &MSK->u[j], &FFr[j][i]);
            mclBnFr_add(&y_ipfe[i], &y_ipfe[i], &aux);
        }
    }
    for(size_t i = 0; i < S->l; ++i) {
        mclBnFr_clear(&y_ipfe[S->l + i]);
        for(size_t j = 0; j < S->l; ++j) {
            mclBnFr_mul(&aux, &MSK->u[j], &FFr[i][j]);
            mclBnFr_add(&y_ipfe[S->l + i], &y_ipfe[S->l + i], &aux);
        }
    }
    end = clock();
    timesKeyGen[4] = timesKeyGen[4] + (double)(end - begin) / CLOCKS_PER_SEC;


    // Use ipfe_FH_fe_derive_key_unbounded
    ipfe_FH_derive_fe_key_unbounded(&FE_key->fe_key, &S->s, &MSK->msk_ipfe, y_ipfe, timesKeyGen);

    // Compute zk
    begin = clock();
    FE_key->zk = u_F;
    mclBnFr_neg(&FE_key->zk, &FE_key->zk);
    for(size_t i = 0; i < S->s.l; ++i) {
        mclBnFr_mul(&aux, &MSK->w[i], &y_ipfe[i]);
        mclBnFr_add(&FE_key->zk, &FE_key->zk, &aux);
    }
    end = clock();
    timesKeyGen[5] = timesKeyGen[5] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Clear auxiliary values
    mpz_clear(e_mpz);
    for(size_t i = 0; i < S->l; ++i) free(FFr[i]);
    free(FFr);
    free(y_ipfe);
    return check;
}

int rqfe_FH_decrypt(mpz_t *result, rqfe_FH *S, rqfe_FH_ciphertext *c, rqfe_FH_fe_key *FE_key, mpz_t **F, double timesDec[]) {
    // Verify F is in bound and swap to mclBnFr
    clock_t begin = clock();
    int check = 0;
    mclBnFr **FFr;
    FFr = (mclBnFr **) malloc(S->l * sizeof(mclBnFr*));
    for(size_t i = 0; i < S->l; ++i) {
        FFr[i] = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
        for(size_t j = 0; j < S->l; ++j) {
            if(mpz_cmp(F[i][j], S->s.bound_Y) > 0) {
                check = 1;
            }
            if(check != 0) break;
            mpz_to_mclBnFr(&FFr[i][j], &F[i][j], 1);
        }
    }
    if(check != 0) return 1;
    clock_t end = clock();
    timesDec[4] = timesDec[4] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Compute [d]_T
    mclBnGT d;
    ipfe_FH_decrypt_exp(&d, &S->s, &c->ct_ipfe, &FE_key->fe_key, timesDec);

    // Compute ct * F * ct + t_prime + zk
    begin = clock();
    mclBnFr sum, prod;
    mclBnFr_add(&sum, &FE_key->t_prime, &FE_key->zk);
    for(size_t i = 0; i < S->l; ++i) {
        for(size_t j = 0; j < S->l; ++j) {
            mclBnFr_mul(&prod, &c->ct[i], &c->ct[j]);
            mclBnFr_mul(&prod, &prod, &FFr[i][j]);
            mclBnFr_add(&sum, &sum, &prod);
        }
    }
    end = clock();
    timesDec[1] = timesDec[1] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Compute [v]_T 
    begin = clock();
    mclBnGT v;
    mclBnGT_pow(&v, &S->s.pg.gT, &sum);
    mclBnGT_div(&v, &v, &d);
    end = clock();
    timesDec[2] = timesDec[2] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Compute discrete log
    begin = clock();
    mpz_t bound, alpha;
    mpz_inits(bound, alpha, NULL);
    mpz_mul(alpha, S->s.bound_X, S->s.bound_Y);
    int epsilon_inv = int(1 / EPSILON);
    //printf("\n1/epsilon = %d\n", epsilon_inv);
    mpz_mul_ui(alpha, alpha, 2 * S->Q * S->l * epsilon_inv * 101);
    mpz_mul(bound, S->s.bound_X, S->s.bound_X);
    mpz_mul(bound, bound, S->s.bound_Y);
    // gmp_printf("\nbound = %Zd\nalpha = %Zd\n", bound, alpha);
    size_t new_l = S->l * S->l;
    mpz_mul_ui(bound, bound, new_l);
    mpz_add(bound, bound, alpha);
    // gmp_printf("bound = %Zd\n", bound);
    mclBnFr result_Fr;
    int output = baby_giant_mcl(&result_Fr, v, S->s.pg.gT, bound);
    mclBnFr_to_mpz(result, &result_Fr, 1);
    end = clock();
    timesDec[3] = timesDec[3] + (double)(end - begin) / CLOCKS_PER_SEC;

    // Clear auxiliary values
    mpz_clears(bound, alpha, NULL);
    for(size_t i = 0; i < S->l; ++i) free(FFr[i]);
    free(FFr);
    return output;
}