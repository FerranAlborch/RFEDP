/*
* Software Name : RIPFEDP
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

#include <stdbool.h>
#include <gmp.h>
#include <time.h>
#include <cstdint>
#include "utils/dlog.hpp"
#include "RFE/ripfe_DDH.h"
#include "utils/modulo.h"
#include "config.h"




bool ripfe_DDH_precomp_init(ripfe_DDH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y) {
    S->epsilon = EPSILON;
    S->Q = Q;

    bool err = ipfe_DDH_precomp_init(&S->s, l, bound_X, bound_Y);

    return err;
}


void ripfe_DDH_free(ripfe_DDH *S) {
    ipfe_DDH_free(&S->s);
    return;
}


void ripfe_DDH_sec_key_init(ripfe_DDH_sec_key *MSK) {
    ipfe_DDH_sec_key_init(&MSK->msk);

    mpz_init2(MSK->seed_u, SEED_SIZE * sizeof(uint64_t));
    return;
}


void ripfe_DDH_sec_key_free(ripfe_DDH_sec_key *MSK) {
    ipfe_DDH_sec_key_free(&MSK->msk);

    mpz_clear(MSK->seed_u);
    return;
}


void ripfe_DDH_fe_key_init(ripfe_DDH_fe_key *FE_key) {
    ipfe_DDH_fe_key_init(&FE_key->fe_key);

    mpz_inits(FE_key->d, FE_key->zk, NULL);
    return;
}


void ripfe_DDH_fe_key_free(ripfe_DDH_fe_key *FE_key) {
    ipfe_DDH_fe_key_free(&FE_key->fe_key);
    
    mpz_clears(FE_key->d, FE_key->zk, NULL);
    return;
}


void ripfe_DDH_generate_master_keys(ripfe_DDH_sec_key *MSK, ripfe_DDH *S, double timesSetUp[]) {
    // Sample seed_u
    generate_seed(MSK->seed_u, SEED_SIZE);


    // Generate msk for the non-randomized scheme
    ipfe_DDH_generate_master_keys(&MSK->msk, &S->s, timesSetUp);

    return;
}


bool ripfe_DDH_encrypt(ipfe_DDH_ciphertext *c, ripfe_DDH *S, mpz_t *x, ripfe_DDH_sec_key *MSK, double timesEnc[]) {
    // Verify ciphertext is in bound
    bool check = true;
    size_t Sl = S->s.l;
    for(size_t i = 0; i < Sl; ++i) {
        if(mpz_cmp(x[i], S->s.bound_X) > 0) {
            check = false;
        }
        if(!check) break;
    }
    if(!check) return false;

    // Generate u
    gmp_randstate_t state_u;
    gmp_randinit_default(state_u);
    gmp_randseed(state_u, MSK->seed_u);
    // mpz_t *u = (mpz_t *) malloc(Sl * sizeof(mpz_t));
    // for(size_t i = 0; i < Sl; ++i) {
    //     mpz_init(u[i]);
    //     mpz_urandomm(u[i], state_u, S->s.phi_p);
    //     mpz_add_ui(u[i], u[i], 1);
    // }
    // gmp_randclear(state_u);

    // Compute d
    mpz_t *d;
    d = (mpz_t *) malloc(Sl * sizeof(mpz_t));
    for(size_t i = 0; i < Sl; ++i) mpz_init(d[i]);
    for(size_t i = 0; i < Sl; ++i) {
        mpz_t u;
        mpz_init(u);
        mpz_urandomm(u, state_u, S->s.phi_p);
        mpz_add_ui(u, u, 1);
        mpz_add_mod(d[i], x[i], u, S->s.p);
        // mpz_add(d[i], x[i], u[i]);
        // mpz_mod(d[i], d[i], S->s.p);
    }
    gmp_randclear(state_u);
    // for(size_t i = 0; i < Sl; ++i) mpz_clear(u[i]);
    // free(u);

    bool err = ipfe_DDH_encrypt(c, &S->s, d, &MSK->msk, timesEnc);

    for(size_t i = 0; i < Sl; ++i) mpz_clear(d[i]);
    free(d);

    return err;
}


bool ripfe_DDH_derive_fe_key(ripfe_DDH_fe_key *FE_key, ripfe_DDH *S, ripfe_DDH_sec_key *MSK, mpz_t *y, mpz_t e_verification, double timesKeyGen[]) {
    
    // Get the non-randomized functional decryption key
    bool err = ipfe_DDH_derive_fe_key(&FE_key->fe_key, &S->s, &MSK->msk, y, timesKeyGen);

    // Generate e and u_y
    mpz_t e, u_y;
    mpz_inits(e, u_y, NULL);

    clock_t begin = clock();
    sample_geometric_IP(e, S->epsilon, S->s.bound_Y, S->Q);
    mpz_set(e_verification, e);

    // Sample the secure seed
    mpz_t seed;
    mpz_init2(seed, SEED_SIZE * sizeof(uint64_t));
    generate_seed(seed, SEED_SIZE);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed(state, seed);
    mpz_clear(seed);

    mpz_urandomm(u_y, state, S->s.p);
    mpz_add_mod(FE_key->d, u_y, e, S->s.p);
    //mpz_add(FE_key->d, u_y, e);
    //mpz_mod(FE_key->d, FE_key->d, S->s.p);
    gmp_randclear(state);
    clock_t end = clock();
    timesKeyGen[0] = timesKeyGen[0] + ((double)(end - begin) / CLOCKS_PER_SEC);

    begin = clock();
    // Generate u
    gmp_randstate_t state_u;
    gmp_randinit_default(state_u);
    gmp_randseed(state_u, MSK->seed_u);
    mpz_t *u = (mpz_t *) malloc(S->s.l * sizeof(mpz_t));
    for(size_t i = 0; i < S->s.l; ++i) {
        mpz_init(u[i]);
        mpz_urandomm(u[i], state_u, S->s.phi_p);
        mpz_add_ui(u[i], u[i], 1);
    }
    gmp_randclear(state_u);

    mpz_t aux;
    mpz_init(aux);
    for(size_t i = 0; i < S->s.l; ++i) {
        mpz_mul(aux, u[i], y[i]);
        //mpz_mod(aux, aux, S->s.p);
        mpz_add(FE_key->zk, FE_key->zk, aux);
        //mpz_mod(FE_key->zk, FE_key->zk, S->s.p);
    }
    mpz_clear(aux);
    //cfe_vec_dot(FE_key->zk, &MSK->u, y);
    mpz_add(FE_key->zk, FE_key->zk, u_y);
    end = clock();
    timesKeyGen[1] = timesKeyGen[1] + ((double)(end - begin) / CLOCKS_PER_SEC);
    //mpz_mod(FE_key->zk, FE_key->zk, S->s.p);

    for(size_t i = 0; i < S->s.l; ++i) mpz_clear(u[i]);
    free(u);
    mpz_clears(e, u_y, NULL);

    return err;
}


bool ripfe_DDH_decrypt(mpz_t result, ripfe_DDH *S, ipfe_DDH_ciphertext *ciphertext, ripfe_DDH_fe_key *FE_key, mpz_t *y, double timesDec[]) {
    mpz_t bound, t, res;
    mpz_inits(bound, t, res, NULL);

    bool err = ipfe_DDH_decrypt_exp(res, &S->s, ciphertext, &FE_key->fe_key, y, timesDec);
    if(!err) {
        printf("Error is in ipfe_decrypt\n");
        return err;
    } 


    clock_t begin = clock();
    mpz_sub(t, FE_key->d, FE_key->zk);
    mpz_mod(t, t, S->s.phi_p);
    FComb_multiMult(t, &S->s.F[0], &t, 1);

    mpz_mul(res, res, t);
    mpz_mod(res, res, S->s.p);
    clock_t end = clock();
    timesDec[3] = timesDec[3] + ((double)(end - begin) / CLOCKS_PER_SEC);

    mpz_t alpha, aux;
    mpz_inits(alpha, aux, NULL);

    begin = clock();
    mpz_mul_ui(alpha, S->s.bound_Y, S->Q);
    mpz_mul_ui(alpha, alpha, 1024);
    for(size_t i = 0; i < S->s.l; ++i) {
        mpz_mul(aux, S->s.bound_X, y[i]);
        mpz_add(bound, bound, aux);
    }
    mpz_add(bound, bound, alpha);

    int error = baby_giant_2(result, res, S->s.g, S->s.p, bound);
    end = clock();
    timesDec[4] = timesDec[4] + ((double)(end - begin) / CLOCKS_PER_SEC);
    
    mpz_clears(bound, t, res, alpha, aux, NULL);

    if(error != 0) {
        printf("Error is in discrete log\n");
        return false;
    }
    return err;
}