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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>
#include <mcl/bn_c384_256.h>
#include "IPFE/ipfe_FH.h"
#include "utils/rand.h"
#include "utils/dlog.h"
#include "config.h"

/**
* \struct rqfe_FH rqfe_FH.h "RFE/rqfe_FH.h"
* \brief It represents the public parameters of the randomized quadratic scheme. 
*/
typedef struct rqfe_FH {
    ipfe_FH s; /**< Public parameters of the function-hiding inner-product scheme. */
    float epsilon; /**< Privacy budget for the scheme. */
    int Q; /**< Number of functional key queries allowed. */
    size_t l; /**< Dimension of the input. */
} rqfe_FH;

/**
* \fn int rqfe_FH_precomp_init(rqfe_FH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y)
* \brief It initializes public parameters of the randomized inner-product scheme for a 
* precomputed set of safe prime values. 
*
* \param S A pointer to a ipfe_FH structure.
* \param l The dimension of the vectors for the quadratic scheme.
* \param bound_X The bound on the plaintext inputs.
* \param Q The maximum number of functional queries to be asked.
* \param bound_Y the bound on the function.
*/
int rqfe_FH_precomp_init(rqfe_FH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y) {
    S->epsilon = EPSILON;
    S->Q = Q;
    S->l = l;

    int err = ipfe_FH_precomp_init(&S->s, 2 * l, bound_X, bound_Y);

    return err;    
}

/**
* \fn void rqfe_FH_free(rqfe_FH *S)
* \brief It clears public parameters of the randomized quadratic scheme and frees allocated memory.
*
* \param S A pointer to a rqfe_FH structure.
*/
void rqfe_FH_free(rqfe_FH *S) {
    ipfe_FH_free(&S->s);
    return;
}

/**
* \struct rqfe_FH_sec_key rqfe_FH.h "RFE/rqfe_FH.h"
* \brief It represents a master secret key of the randomized quadratic scheme.
*/
typedef struct rqfe_FH_sec_key {
    ipfe_FH_sec_key msk_ipfe; /**< Master secret key of the function-hiding inner-product scheme. */
    mclBnFr *u; /**< Array of l random elements u. */
    mclBnFr *w; /**< Array of 2l random elements w (one-time pad). */
    mclBnFr c; /**< Random value c. */
    size_t l; /**< Dimension of the input. */
} rqfe_FH_sec_key;

/**
* \fn void rqfe_FH_sec_key_init(rqfe_FH_sec_key *MSK)
* \brief It initializes a master secret key of the randomized quadratic scheme.
*
* \param MSK A pointer to a rqfe_FH_sec_key structure.
*/
void rqfe_FH_sec_key_init(rqfe_FH_sec_key *MSK, rqfe_FH *S) {
    ipfe_FH_sec_key_init(&MSK->msk_ipfe, &S->s);

    MSK->u = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
    MSK->w = (mclBnFr *) malloc((2 * S->l) * sizeof(mclBnFr));
    MSK->l = S->l;
    return; 
}

/**
* \fn void rqfe_FH_sec_key_free(rqfe_FH_sec_key *MSK)
* \brief It clears a master secret key of the randomized quadratic scheme and frees allocated memory.
*
* \param MSK A pointer to a rqfe_FH_sec_key structure.
*/
void rqfe_FH_sec_key_free(rqfe_FH_sec_key *MSK) {
    free(MSK->u);
    free(MSK->w);
}

/**
* \struct rqfe_FH_fe_key rqfe_FH.h "RFE/rqfe_FH.h"
* \brief It represents a functional decryption key of the randomized quadratic scheme.
*/
typedef struct rqfe_FH_fe_key {
    ipfe_FH_fe_key fe_key; /**< Functional decryption key of the non-randomized scheme. */
    mclBnFr t_prime; /**< Padded differentially private noise. */
    mclBnFr zk; /**< Extra terms. */
} rqfe_FH_fe_key;

/**
* \fn void rqfe_FH_fe_key_init(rqfe_DDH_fe_key *FE_key)
* \brief It initializes a functional decryption key of the randomized quadratic scheme.
*
* \param FE_key A pointer to a rqfe_FH_fe_key structure.
* \param S A pointer to a rqfe_FH structure
*/
void rqfe_FH_fe_key_init(rqfe_FH_fe_key *FE_key, rqfe_FH *S) {
    ipfe_FH_fe_key_init(&FE_key->fe_key, &S->s);
    return;
}

/**
* \fn void rqfe_FH_fe_key_free(rqfe_FH_fe_key *FE_key)
* \brief It clears a functional decryption key of the randomized quadratic scheme and frees 
* allocated memory.
*
* \param FE_key A pointer to a rqfe_FH_fe_key structure.
*/
void rqfe_FH_fe_key_free(rqfe_FH_fe_key *FE_key) {
    ipfe_FH_fe_key_free(&FE_key->fe_key);
    return;
}

/**
* \struct rqfe_FH_ciphertext rqfe_FH.h "RFE/rqfe_FH.h"
* \brief It represents a ciphertext of the randomized quadratic scheme.
*/
typedef struct rqfe_FH_ciphertext {
    mclBnFr *ct; /**< An array of l elements ct. */
    ipfe_FH_ciphertext ct_ipfe; /**< An ipfe_FH_ciphertext. */
	size_t l; /**< The dimension for the scheme. */
} rqfe_FH_ciphertext;

/**
* \fn void rqfe_FH_ciphertext_init(rqfe_FH_ciphertext *c, rqfe_FH *S)
* \brief It initializes a ciphertext of the randomized quadratic scheme.
*
* \param c A pointer to a rqfe_FH_ciphertext structure.
* \param S A pointer to a rqfe_FH structure.
*/
void rqfe_FH_ciphertext_init(rqfe_FH_ciphertext *c, rqfe_FH *S) {
    c->ct = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
    ipfe_FH_ciphertext_init(&c->ct_ipfe, &S->s);
    c->l = S->l;
    return;
}

/**
* \fn void rqfe_FH_ciphertext_free(rqfe_FH_ciphertext *c)
* \brief It clears a ciphertext of the randomized quadratic scheme and frees allocated memory.
*
* \param c A pointer to a rqfe_FH_ciphertext structure.
*/
void rqfe_FH_ciphertext_free(rqfe_FH_ciphertext *c) {
    free(c->ct);
    ipfe_FH_ciphertext_free(&c->ct_ipfe);
    return;
}

/**
* \fn void rqfe_FH_generate_master_keys(rqfe_FH_sec_key *MSK, double timesSetUp[])
* \brief It generates a master secret key for the randomized inner-product scheme.
*
* \param MSK A pointer to a rqfe_FH_sec_key structure.
* \param timesSetUp An array to store the timings of this protocol.
*/
int rqfe_FH_generate_master_keys(rqfe_FH_sec_key *MSK, double timesSetUp[]) {
    // Sample c
    mclBnFr_setByCSPRNG(&MSK->c);

    // Sample u
    for(size_t i = 0; i < MSK->l; ++i) mclBnFr_setByCSPRNG(&MSK->u[i]);        

    // Sample w
    for(size_t i = 0; i < 2 * MSK->l; ++i) mclBnFr_setByCSPRNG(&MSK->w[i]);

    // Run ipfh_FH_generate_master_keys
    return ipfe_FH_generate_master_keys(&MSK->msk_ipfe, timesSetUp);
}

/**
* \fn bool rqfe_FH_encrypt(rqfe_FH_ciphertext *c, rqfe_FH *S, mpz_t *x, rqfe_FH_sec_key *MSK, double timesEnc[])
* \brief It encrypts a message following the randomized quadratic scheme.
*
* \param c A pointer to a rqfe_FH_ciphertext structure.
* \param S A pointer to a rqfe_FH structure.
* \param x An array of multiple precision integers as plaintext message.
* \param MSK A pointer to a rqfe_FH_sec_key structure.
* \param timesEnc An array to store the timings of this protocol.
*/
int rqfe_FH_encrypt(rqfe_FH_ciphertext *c, rqfe_FH *S, mpz_t *x, rqfe_FH_sec_key *MSK, double timesEnc[], mclBnFr *x_ipfe) {
    // Verify x is in bound
	int check = 0;
    for(size_t i = 0; i < S->l; ++i) {
        if(mpz_cmp(x[i], S->s.bound_X) > 0) {
            check = 1;
        }
        if(check != 0) break;
    }
    if(check != 0) return 1;

    // Swap the plaintext from mpz_t to mclBnFr
	mclBnFr *xFr;
	xFr = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
	mpz_to_mclBnFr(xFr, x, S->l);

    // Compute ct
    mclBnFr aux_Fr;
    for(size_t i = 0; i < S->l; ++i) {
        //mclBnFr_clear(&c->ct[i]);
        mclBnFr_mul(&aux_Fr, &MSK->c, &MSK->u[i]);
        mclBnFr_add(&c->ct[i], &aux_Fr, &xFr[i]);
    }

    // Compute input for ipfe_FH_encrypt_unbounded
    //mclBnFr *x_ipfe;
    //x_ipfe = (mclBnFr *) malloc(S->s.l * sizeof(mclBnFr));
    for(size_t i = 0; i < S->l; ++i) {
        mclBnFr_mul(&aux_Fr, &MSK->c, &c->ct[i]);
        mclBnFr_add(&x_ipfe[i], &aux_Fr, &MSK->w[i]);
    
        mclBnFr_mul(&aux_Fr, &MSK->c, &xFr[i]);
        mclBnFr_add(&x_ipfe[S->l + i], &aux_Fr, &MSK->w[S->l + i]);
    }

    // Encrypt through ipfe_FH_unbounded
    int verify = ipfe_FH_encrypt_unbounded(&c->ct_ipfe, &S->s, x_ipfe, &MSK->msk_ipfe, timesEnc);


    // Clear auxiliary values
    free(xFr);
    free(x_ipfe);

    return verify;
}

/**
* \fn int rqfe_FH_derive_fe_key(rqfe_FH_fe_key *FE_key, rqfe_FH *S, rqfe_FH_sec_key *MSK, mpz_t **F, mpz_t e_verification, double timesKeyGen[])
* \brief It derives functional decryption keys following the randomized quadratic scheme.
*
* \param FE_key A pointer to a rqfe_FH_fe_key structure.
* \param S A pointer to a rqfe_FH structure.
* \param MSK A pointer to a rqfe_FH_fe_key structure.
* \param F A two-dimensional array of multiple precision integers as a function.
* \param e_verification A multiple precision integer to store the noise e for verification purposes.
* \param timesKeyGen An array to store the timings of this protocol.
*/
int rqfe_FH_derive_fe_key(rqfe_FH_fe_key *FE_key, rqfe_FH *S, rqfe_FH_sec_key *MSK, mpz_t **F, mpz_t e_verification, double timesKeyGen[], mclBnFr *y_ipfe) {
    // Verify F is in bound
    int check = 0;
    for(size_t i = 0; i < S->l; ++i) {
        for(size_t j = 0; j < S->l; ++j) {
            if(mpz_cmp(F[i][j], S->s.bound_Y) > 0) {
                check = 1;
            }
            if(check != 0) break;
        }
    }
    if(check != 0) return 1;

    // Swap the function from mpz to mclBnFr
    mclBnFr **FFr;
    FFr = (mclBnFr **) malloc(S->l * sizeof(mclBnFr*));
    for(size_t i = 0; i < S->l; ++i) FFr[i] = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
    for(size_t i = 0; i < S->l; ++i) {
        mpz_to_mclBnFr(FFr[i], F[i], S->l);
    }
    
    // Generate e
    mclBnFr e;
    mpz_t e_mpz;
    mpz_init(e_mpz);
    // sample_geometric(e_mpz, S->epsilon, S->s.bound_Y, S->Q);
    mpz_set(e_verification, e_mpz);
    mpz_to_mclBnFr(&e, &e_mpz, 1);

    // Generate u_F
    mclBnFr u_F;
    mclBnFr_setByCSPRNG(&u_F);

    // Compute t_prime
    mclBnFr_add(&FE_key->t_prime, &e, &u_F);

    // Compute vector input for ipfe_FH_derive_fe_key
    //mclBnFr *y_ipfe;
    //y_ipfe = (mclBnFr *) malloc(S->s.l * sizeof(mclBnFr));
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

    // Use ipfe_FH_fe_derive_key_unbounded
    ipfe_FH_derive_fe_key_unbounded(&FE_key->fe_key, &S->s, &MSK->msk_ipfe, y_ipfe, timesKeyGen);

    // Compute zk
    FE_key->zk = u_F;
    mclBnFr_neg(&FE_key->zk, &FE_key->zk);
    for(size_t i = 0; i < S->s.l; ++i) {
        mclBnFr_mul(&aux, &MSK->w[i], &y_ipfe[i]);
        mclBnFr_add(&FE_key->zk, &FE_key->zk, &aux);
    }


    // Clear auxiliary values
    mpz_clear(e_mpz);
    for(size_t i = 0; i < S->l; ++i) free(FFr[i]);
    free(FFr);
    free(y_ipfe);
    return check;
}

/**
* \fn int rqfe_FH_decrypt(mpz_t result, rqfe_FH *S, rqfe_FH_ciphertext *c, rqfe_FH_fe_key *FE_key, mpz_t **F, double timesDec[])
* \brief It decrypts a ciphertext with a functional decryption key following the randomized inner-product 
* scheme.
*
* \param result A multiple precision integer to store the result.
* \param S A pointer to a rqfe_FH structure.
* \param ciphertext A pointer to a rqfe_FH_ciphertext structure.
* \param FE_key A pointer to a rqfe_fe_key structure.
* \param F A pointer to a two-dimensional function array.
* \param timesDec An array to store the timings of this protocol.
*/
int rqfe_FH_decrypt(mclBnGT *result, rqfe_FH *S, rqfe_FH_ciphertext *c, rqfe_FH_fe_key *FE_key, mpz_t **F, double timesDec[], mclBnGT d) {
    // Swap the function from mpz to mclBnFr
    mclBnFr **FFr;
    FFr = (mclBnFr **) malloc(S->l * sizeof(mclBnFr*));
    for(size_t i = 0; i < S->l; ++i) FFr[i] = (mclBnFr *) malloc(S->l * sizeof(mclBnFr));
    for(size_t i = 0; i < S->l; ++i) {
        mpz_to_mclBnFr(FFr[i], F[i], S->l);
    }

    // Compute [d]_T
    //mclBnGT d;
    ipfe_FH_decrypt_exp(&d, &S->s, &c->ct_ipfe, &FE_key->fe_key, timesDec);

    // Compute ct * F * ct + t_prime + zk
    mclBnFr sum, prod;
    mclBnFr_add(&sum, &FE_key->t_prime, &FE_key->zk);
    for(size_t i = 0; i < S->l; ++i) {
        for(size_t j = 0; j < S->l; ++j) {
            mclBnFr_mul(&prod, &c->ct[i], &c->ct[j]);
            mclBnFr_mul(&prod, &prod, &FFr[i][j]);
            mclBnFr_add(&sum, &sum, &prod);
        }
    }

    // Compute [v]_T 
    mclBnGT v;
    mclBnGT_pow(&v, &S->s.pg.gT, &sum);
    mclBnGT_div(result, &v, &d);


    // Clear auxiliary values
    for(size_t i = 0; i < S->l; ++i) free(FFr[i]);
    free(FFr);
    return 0;
}


int main () {
	char buf[1600];
	size_t l = 5;
	mpz_t bound_X, bound_Y;
	mpz_inits(bound_X, bound_Y, NULL);
	mpz_set_ui(bound_X, 10);
	mpz_set_ui(bound_Y, 10);
    int Q = 5;

	double timesSetUp[2], timesEnc[2], timesKeyGen[2], timesDec[1];
	timesSetUp[0] = timesSetUp[1] = 0.0;
	timesEnc[0] = timesEnc[1] = 0.0;
	timesKeyGen[0] = timesKeyGen[1] = 0.0;
	timesDec[0] = 0.0;

	// Seed for randomness sampling
	srand(time(NULL));
	int seed = rand();
    gmp_randstate_t state;
    gmp_randinit_default(state);
	gmp_randseed_ui(state, seed);

    // printf("Got here\n");
	
	// SetUp
	rqfe_FH S;
	clock_t begin = clock();
	int verify = rqfe_FH_precomp_init(&S, l, bound_X, Q, bound_Y);
	clock_t end = clock();
	timesSetUp[0] = timesSetUp[0] + ((double )(end - begin) / CLOCKS_PER_SEC);

    // printf("Got here\n");

	rqfe_FH_sec_key MSK;
	rqfe_FH_sec_key_init(&MSK, &S);
	rqfe_FH_generate_master_keys(&MSK, timesSetUp);

	// Encryption
	rqfe_FH_ciphertext c;
	rqfe_FH_ciphertext_init(&c, &S);

    mclBnFr *x_ipfe;
    x_ipfe = (mclBnFr *) malloc(S.s.l * sizeof(mclBnFr));

	mpz_t *x;
    x = (mpz_t *) malloc(S.l * sizeof(mpz_t));
    for(size_t i = 0; i < S.l; ++i) mpz_init(x[i]);
	for(size_t i = 0; i < S.l; ++i) {
		mpz_urandomm(x[i], state, S.s.bound_X);
	}
    printf("Got here\n");
	rqfe_FH_encrypt(&c, &S, x, &MSK, timesEnc, x_ipfe);

	// Key Generation 
	rqfe_FH_fe_key FE_key;
	rqfe_FH_fe_key_init(&FE_key, &S);

    mclBnFr *y_ipfe;
    y_ipfe = (mclBnFr *) malloc(S.s.l * sizeof(mclBnFr));


	mpz_t **F;
    F = (mpz_t **) malloc(S.l * sizeof(mpz_t*));
    for(size_t i = 0; i < S.l; ++i) {
        F[i] = (mpz_t *) malloc(S.l * sizeof(mpz_t));
        for(size_t j = 0; j < S.l; ++j) {
            mpz_init(F[i][j]);
            mpz_urandomm(F[i][j], state, S.s.bound_Y);
        }
    }
    mpz_t e_verification;
    mpz_init(e_verification);
	rqfe_FH_derive_fe_key(&FE_key, &S, &MSK, F, e_verification, timesKeyGen, y_ipfe);

	// Decryption
	mclBnGT result, d;
	rqfe_FH_decrypt(&result, &S, &c, &FE_key, F, timesDec, d);

	// Verification
	
	mclBnFr *xFr;
    mclBnFr **FFr;
	xFr = (mclBnFr *) malloc(S.l * sizeof(mclBnFr));
	FFr = (mclBnFr **) malloc(S.l * sizeof(mclBnFr*));
    for(size_t i= 0; i < S.l; ++i) {
        FFr[i] = (mclBnFr *) malloc(S.l * sizeof(mclBnFr));
        mpz_to_mclBnFr(FFr[i], F[i], S.l);
    }
	mpz_to_mclBnFr(xFr, x, S.l);
	

	mclBnFr result_Fr, auxFr;	
	mpz_t result_mpz, aux;
	mpz_inits(result_mpz, aux, NULL);
	for(size_t i = 0; i < l; ++i) {
        for(size_t j = 0; j < l; ++j) {
            mpz_mul(aux, x[i], x[j]);
            mpz_mul(aux, aux, F[i][j]);
            mpz_add(result_mpz, result_mpz, aux);
        }
	}
    mpz_add(result_mpz, result_mpz, e_verification);
	gmp_printf("Expected result in mpz = %Zd\n", result_mpz);
	mclBnFr_clear(&result_Fr);
	for(size_t i = 0; i < l; ++i) {
        for(size_t j = 0; j < l; ++j) {
            mclBnFr_mul(&auxFr, &xFr[i], &xFr[j]);
            mclBnFr_mul(&auxFr, &auxFr, &FFr[i][j]);
            mclBnFr_add(&result_Fr, &result_Fr, &auxFr);
        }
	}
    mclBnFr eFr;
    mpz_to_mclBnFr(&eFr, &e_verification, 1);
    mclBnFr_add(&result_Fr, &result_Fr, &eFr);
	mclBnFr_getStr(buf, sizeof(buf), &result_Fr, 10);
	printf("Expected result in Fr = %s\n", buf);

	mclBnGT verification;
	mclBnGT_pow(&verification, &S.s.pg.gT, &result_Fr);
	verify = mclBnGT_isEqual(&result, &verification);	

	printf("Print 1 if Decryption is correct: %d\n", verify);
	free(xFr);
	


    // Verifying computing in Fr works?
    printf("\n");
    printf("S.l = %ld\nS.s.l = %ld\n", S.l, S.s.l);
    mclBnFr verif_Fr, aux_Fr;
    mclBnFr sum, prod;
    mclBnFr_add(&sum, &FE_key.t_prime, &FE_key.zk);
    for(size_t i = 0; i < S.l; ++i) {
        for(size_t j = 0; j < S.l; ++j) {
            mclBnFr_mul(&prod, &c.ct[i], &c.ct[j]);
            mclBnFr_mul(&prod, &prod, &FFr[i][j]);
            mclBnFr_add(&sum, &sum, &prod);
        }
    }
    verif_Fr = sum;
    mclBnFr_clear(&sum);
    for(size_t i = 0; i < S.s.l; ++i) {
        mclBnFr_mul(&prod, &x_ipfe[i], &y_ipfe[i]);
        mclBnFr_add(&sum, &sum, &prod);
    }

    // Verifying gT^verif_Fr / gT^sum is correct
    mclBnGT auxGT, auxGT2;
    mclBnGT_pow(&auxGT, &S.s.pg.gT, &verif_Fr);
    mclBnGT_pow(&auxGT2, &S.s.pg.gT, &sum);
    mclBnGT_mul(&auxGT, &auxGT, &auxGT2);
    verify = mclBnGT_isEqual(&auxGT, &verification);
 	printf("Print 1 if operation in GT is correct: %d\n", verify);

    mclBnFr_sub(&verif_Fr, &verif_Fr, &sum);
    mclBnFr_getStr(buf, sizeof(buf), &verif_Fr, 10);
	printf("Verification result in Fr = %s\n", buf);


    mclBnGT verif_d;
    mclBnGT_pow(&verif_d, &S.s.pg.gT, &sum);
    verify = mclBnGT_isEqual(&verif_d, &d);
 	printf("Print 1 if d is correct: %d\n", verify);
 

    // Verifying everything in mpz
    // Constructing ct
    mpz_t c_mpz, aux_mpz;
    mpz_inits(c_mpz, aux_mpz, NULL);
    mpz_t *u_mpz, *ct_mpz;
    u_mpz = (mpz_t *) malloc(S.l * sizeof(mpz_t));
    ct_mpz = (mpz_t *) malloc(S.l * sizeof(mpz_t));
    for(size_t i = 0; i < S.l; ++i) mpz_inits(u_mpz[i], ct_mpz[i], NULL);
    mclBnFr_to_mpz(&c_mpz, &MSK.c, 1);
    mclBnFr_to_mpz(u_mpz, MSK.u, S.l);
    for(size_t i = 0; i < S.l; ++i) {
        mpz_mul(aux, c_mpz, u_mpz[i]);
        mpz_mod(aux, aux, S.s.pg.r);
        mpz_add(ct_mpz[i], x[i], aux);
        mpz_mod(ct_mpz[i], ct_mpz[i], S.s.pg.r);
    }
    mclBnFr *ct_verify;
    ct_verify = (mclBnFr *) malloc(S.l * sizeof(mclBnFr));
    // mpz_to_mclBnFr(ct_verify, ct_mpz, S.l);
    for(size_t i = 0; i < S.l; ++i) {
        mclBnFr_clear(&ct_verify[i]);
        mclBnFr_mul(&aux_Fr, &MSK.c, &MSK.u[i]);
        mclBnFr_add(&ct_verify[i], &aux_Fr, &xFr[i]);
    }
    int verify_ct = 1;
    for(size_t i = 0; i < S.l; ++i) {
        if(mclBnFr_isEqual(&ct_verify[i], &c.ct[i]) == 0) verify_ct = 0;
    }
    printf("Print 1 if c.ct is correct: %d\n", verify_ct);
    printf("Verification result in mpz = \n");
    for(size_t i = 0; i < S.l; ++i) {
        gmp_printf("%Zd\n", ct_mpz[i]);
    }
    printf("Verification result in Fr = \n");
    for(size_t i = 0; i < S.l; ++i) {
        mclBnFr_getStr(buf, sizeof(buf), &ct_verify[i], 10);
	    printf("%s\n", buf);
    }
    printf("Original result in Fr = \n");
    for(size_t i = 0; i < S.l; ++i) {
        mclBnFr_getStr(buf, sizeof(buf), &c.ct[i], 10);
	    printf("%s\n", buf);
    }


    // Constructing x_ipfe
    mpz_t *w_mpz, *x_ipfe_mpz;
    w_mpz = (mpz_t *) malloc(S.s.l * sizeof(mpz_t));
    x_ipfe_mpz = (mpz_t *) malloc(S.s.l * sizeof(mpz_t));
    for(size_t i = 0; i < S.l; ++i) mpz_inits(w_mpz[i], x_ipfe_mpz[i], NULL);
    mclBnFr_to_mpz(w_mpz, MSK.w, S.s.l);
    for(size_t i = 0; i < S.l; ++i) {
        mpz_mul(aux, c_mpz, ct_mpz[i]);
        mpz_mod(aux, aux, S.s.pg.r);
        mpz_add(x_ipfe_mpz[i], w_mpz[i], aux);
        mpz_mod(x_ipfe_mpz[i], x_ipfe_mpz[i], S.s.pg.r);

        mpz_mul(aux, c_mpz, x[i]);
        mpz_mod(aux, aux, S.s.pg.r);
        mpz_add(x_ipfe_mpz[S.l + i], w_mpz[S.l + i], aux);
        mpz_mod(x_ipfe_mpz[S.l + i], x_ipfe_mpz[S.l + i], S.s.pg.r);
    }
    mclBnFr *x_ipfe_verify;
    x_ipfe_verify = (mclBnFr *) malloc(S.s.l * sizeof(mclBnFr));
    mpz_to_mclBnFr(x_ipfe_verify, x_ipfe_mpz, S.s.l);
    int verify_ct_ipfe = 1;
    for(size_t i = 0; i < S.s.l; ++i) {
        if(mclBnFr_isEqual(&x_ipfe_verify[i], &x_ipfe[i]) == 0) verify_ct_ipfe = 0;
    }
    printf("Print 1 if x_ipfe is correct: %d\n", verify_ct_ipfe);

	// Clearing and freeing
	rqfe_FH_ciphertext_free(&c);
	rqfe_FH_fe_key_free(&FE_key);
	rqfe_FH_sec_key_free(&MSK);
	rqfe_FH_free(&S);
	
	for(size_t i = 0; i < S.l; ++i) mpz_clears(x[i], NULL);
    for(size_t i = 0; i < S.l; ++i) {
        for(size_t j = 0; j < S.l; ++j) mpz_clear(F[i][j]);
        free(F[i]);
        free(FFr[i]);
    }
	free(x);
    free(F);
    free(FFr);
	mpz_clears(bound_X, bound_Y, result_mpz, aux, e_verification, NULL);
	gmp_randclear(state);
}

