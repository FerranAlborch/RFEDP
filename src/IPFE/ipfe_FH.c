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

int ipfe_FH_precomp_init(ipfe_FH *s, size_t l, mpz_t bound_X, mpz_t bound_Y) {
	// Set the given values
	s->l = l;
	mpz_inits(s->bound_X, s->bound_Y, NULL);
	mpz_set(s->bound_X, bound_X);
	mpz_set(s->bound_Y, bound_Y);

	// Initialize the pairing groups PG
	return PG_init(&s->pg);
}

void ipfe_FH_free(ipfe_FH *s) {
	mpz_clears(s->bound_X, s->bound_Y, NULL);
	PG_free(&s->pg);
	return;
}

void ipfe_FH_sec_key_init(ipfe_FH_sec_key *msk, ipfe_FH *s) {
	msk->l = s->l;
	msk->u = (mclBnFr *) malloc((msk->l + 1) * sizeof(mclBnFr));
	msk->v = (mclBnFr *) malloc(msk->l * sizeof(mclBnFr));
	return;
}

void ipfe_FH_sec_key_free(ipfe_FH_sec_key *msk) {
	for(size_t i = 0; i < msk->l; ++i) {
		mclBnFr_clear(&msk->u[i]);
		mclBnFr_clear(&msk->v[i]);
	}
	mclBnFr_clear(&msk->u[msk->l]);
	free(msk->u);
	free(msk->v);
	return;
}

void ipfe_FH_fe_key_init(ipfe_FH_fe_key *fe_key, ipfe_FH *s) {
	fe_key->l = s->l;
	fe_key->sk = (mclBnG2 *) malloc((fe_key->l + 2) * sizeof(mclBnG2));
	return;
}

void ipfe_FH_fe_key_free(ipfe_FH_fe_key *fe_key) {
	for(size_t i = 0; i < fe_key->l + 2; ++i) mclBnG2_clear(&fe_key->sk[i]);
	free(fe_key->sk);
	return;
}

void ipfe_FH_ciphertext_init(ipfe_FH_ciphertext *c, ipfe_FH *s) {
	c->l = s->l;
	c->ct = (mclBnG1 *) malloc((c->l + 2) * sizeof(mclBnG1));
	return;
}

void ipfe_FH_ciphertext_free(ipfe_FH_ciphertext *c) {
	for(size_t i = 0; i < c->l + 2; ++i) mclBnG1_clear(&c->ct[i]);
	free(c->ct);
	return;
}

int ipfe_FH_generate_master_keys(ipfe_FH_sec_key *msk, double timesSetUp[]) {
	// Sample random element if Fr for every slot in u and v
	clock_t begin = clock();
	int verify;
	for(size_t i = 0; i < msk->l; ++i) {
		verify = mclBnFr_setByCSPRNG(&msk->u[i]);
		if(verify != 0) return 1;
		verify = mclBnFr_setByCSPRNG(&msk->v[i]);
		if(verify != 0) return 1;
	}
	verify = mclBnFr_setByCSPRNG(&msk->u[msk->l]);
	if(verify != 0) return 1;
	clock_t end = clock();
	timesSetUp[0] = timesSetUp[0] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;
	return verify;
}

int ipfe_FH_encrypt_unbounded(ipfe_FH_ciphertext *ct, ipfe_FH *s, mclBnFr *x, ipfe_FH_sec_key *msk, double timesEnc[]) {
	int verify;

	// Sample c in Fr
	clock_t begin = clock();
	mclBnFr c;
	verify = mclBnFr_setByCSPRNG(&c);
	if(verify != 0) return 1;

	// Compute ct1
	mclBnG1_mul(&ct->ct[0], &s->pg.P1, &c);
	clock_t end = clock();
	timesEnc[0] = timesEnc[0] + ((double )(end - begin) / CLOCKS_PER_SEC);

	// Compute first component of ct2
	begin = clock();
	mclBnFr aux;
	mclBnFr aux2;
	mclBnFr_clear(&aux2);
	for(size_t i = 0; i < s->l; ++i) {
		mclBnFr_mul(&aux, &msk->v[i], &x[i]);
		mclBnFr_sub(&aux2, &aux2, &aux);
	}
	mclBnFr_mul(&aux, &c, &msk->u[0]);
	mclBnFr_add(&aux2, &aux2, &aux);
	mclBnG1_mul(&ct->ct[1], &s->pg.P1, &aux2);

	// Compute rest of ct2
	for(size_t i = 0; i < s->l; ++i) {
		mclBnFr_mul(&aux, &c, &msk->u[i+1]);
		mclBnFr_add(&aux, &aux, &x[i]);
		mclBnG1_mul(&ct->ct[i+2], &s->pg.P1, &aux);
	}
	end = clock();
	timesEnc[1] = timesEnc[1] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;

	// Clear the auxiliary variables
	mclBnFr_clear(&c);
	mclBnFr_clear(&aux);
	mclBnFr_clear(&aux2);
	return verify;
}

int ipfe_FH_encrypt_bounded(ipfe_FH_ciphertext *ct, ipfe_FH *s, mpz_t *x, ipfe_FH_sec_key *msk, double timesEnc[]) {
	int verify;

	// Verify x is in bound
	int check = 0;
    for(size_t i = 0; i < s->l; ++i) {
        if(mpz_cmp(x[i], s->bound_X) != 0) {
            check = 1;
        }
        if(check != 0) break;
    }
    if(check != 0) return 1;

	
	// Swap the plaintext from mpz_t to mclBnFr
	mclBnFr *xFr;
	xFr = (mclBnFr *) malloc(s->l * sizeof(mclBnFr));
	mpz_to_mclBnFr(xFr, x, s->l);

	// Sample c in Fr
	clock_t begin = clock();
	mclBnFr c;
	verify = mclBnFr_setByCSPRNG(&c);
	if(verify != 0) return 1;

	// Compute ct1
	mclBnG1_mul(&ct->ct[0], &s->pg.P1, &c);
	clock_t end = clock();
	timesEnc[0] = timesEnc[0] + ((double )(end - begin) / CLOCKS_PER_SEC);

	// Compute first component of ct2
	begin = clock();
	mclBnFr aux;
	mclBnFr aux2;
	mclBnFr_clear(&aux2);
	for(size_t i = 0; i < s->l; ++i) {
		mclBnFr_mul(&aux, &msk->v[i], &xFr[i]);
		mclBnFr_sub(&aux2, &aux2, &aux);
	}
	mclBnFr_mul(&aux, &c, &msk->u[0]);
	mclBnFr_add(&aux2, &aux2, &aux);
	mclBnG1_mul(&ct->ct[1], &s->pg.P1, &aux2);

	// Compute rest of ct2
	for(size_t i = 0; i < s->l; ++i) {
		mclBnFr_mul(&aux, &c, &msk->u[i+1]);
		mclBnFr_add(&aux, &aux, &xFr[i]);
		mclBnG1_mul(&ct->ct[i+2], &s->pg.P1, &aux);
	}
	end = clock();
	timesEnc[1] = timesEnc[1] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;

	// Clear the auxiliary variables
	mclBnFr_clear(&c);
	mclBnFr_clear(&aux);
	mclBnFr_clear(&aux2);
	for(size_t i = 0; i < msk->l; ++i) {
		mclBnFr_clear(&xFr[i]);
	}
	free(xFr);
	return verify;
}

int ipfe_FH_derive_fe_key_unbounded(ipfe_FH_fe_key *fe_key, ipfe_FH *s, ipfe_FH_sec_key *msk, mclBnFr *y, double timesKeyGen[]) {
	int verify;

	// Sample t in Fr
	clock_t begin = clock();
	mclBnFr t;
	verify = mclBnFr_setByCSPRNG(&t);
	if(verify != 0) return 1;

	// Compute sk2
	mclBnFr *sk2;
	sk2 = (mclBnFr *) malloc((s->l + 1) * sizeof(mclBnFr));
	sk2[0] = t;
	mclBnG2_mul(&fe_key->sk[1], &s->pg.P2, &sk2[0]);
	for(size_t i = 0; i < s->l; ++i) {
		mclBnFr_mul(&sk2[i+1], &t, &msk->v[i]);
		mclBnFr_add(&sk2[i+1], &sk2[i+1], &y[i]);
		mclBnG2_mul(&fe_key->sk[i+2], &s->pg.P2, &sk2[i+1]);
	}
	clock_t end = clock();
	timesKeyGen[1] = timesKeyGen[1] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;

	// Compute sk1
	begin = clock();
	mclBnFr aux, aux2;
	mclBnFr_clear(&aux);
	for(size_t i = 0; i < s->l + 1; ++i) {
		mclBnFr_mul(&aux2, &msk->u[i], &sk2[i]);
		mclBnFr_sub(&aux, &aux, &aux2);
	}
	mclBnG2_mul(&fe_key->sk[0], &s->pg.P2, &aux);
	end = clock();
	timesKeyGen[0] = timesKeyGen[0] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;

	// Clear the auxiliary variables
	mclBnFr_clear(&t);
	mclBnFr_clear(&aux);
	mclBnFr_clear(&aux2);
	for(size_t i = 0; i < msk->l; ++i) {
		mclBnFr_clear(&sk2[i]);
	}
	mclBnFr_clear(&sk2[s->l]);
	free(sk2);
	return verify;
}

int ipfe_FH_derive_fe_key_bounded(ipfe_FH_fe_key *fe_key, ipfe_FH *s, ipfe_FH_sec_key *msk, mpz_t *y, double timesKeyGen[]) {
	int verify;

	// Verify x is in bound
	int check = 0;
    for(size_t i = 0; i < s->l; ++i) {
        if(mpz_cmp(y[i], s->bound_Y) != 0) {
            check = 1;
        }
        if(check != 0) break;
    }
    if(check != 0) return 1;

	// Swap the function from mpz_t to mclBnFr
	mclBnFr *yFr;
	yFr = (mclBnFr *) malloc(s->l * sizeof(mclBnFr));
	mpz_to_mclBnFr(yFr, y, s->l);

	// Sample t in Fr
	clock_t begin = clock();
	mclBnFr t;
	verify = mclBnFr_setByCSPRNG(&t);
	if(verify != 0) return 1;

	// Compute sk2
	mclBnFr *sk2;
	sk2 = (mclBnFr *) malloc((s->l + 1) * sizeof(mclBnFr));
	sk2[0] = t;
	mclBnG2_mul(&fe_key->sk[1], &s->pg.P2, &sk2[0]);
	for(size_t i = 0; i < s->l; ++i) {
		mclBnFr_mul(&sk2[i+1], &t, &msk->v[i]);
		mclBnFr_add(&sk2[i+1], &sk2[i+1], &yFr[i]);
		mclBnG2_mul(&fe_key->sk[i+2], &s->pg.P2, &sk2[i+1]);
	}
	clock_t end = clock();
	timesKeyGen[1] = timesKeyGen[1] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;

	// Compute sk1
	begin = clock();
	mclBnFr aux, aux2;
	mclBnFr_clear(&aux);
	for(size_t i = 0; i < s->l + 1; ++i) {
		mclBnFr_mul(&aux2, &msk->u[i], &sk2[i]);
		mclBnFr_sub(&aux, &aux, &aux2);
	}
	mclBnG2_mul(&fe_key->sk[0], &s->pg.P2, &aux);
	end = clock();
	timesKeyGen[0] = timesKeyGen[0] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;

	// Clear the auxiliary variables
	mclBnFr_clear(&t);
	mclBnFr_clear(&aux);
	mclBnFr_clear(&aux2);
	for(size_t i = 0; i < msk->l; ++i) {
		mclBnFr_clear(&yFr[i]);
		mclBnFr_clear(&sk2[i]);
	}
	mclBnFr_clear(&sk2[s->l]);
	free(yFr);
	free(sk2);
	return verify;
}

void ipfe_FH_decrypt_exp(mclBnGT *r, ipfe_FH *s, ipfe_FH_ciphertext *c, ipfe_FH_fe_key *fe_key, double timesDec[]) {
	mclBnGT aux;
	
	// Compute the Miller loop of ct and sk
	clock_t begin = clock();
	mclBn_millerLoopVec(&aux, c->ct, fe_key->sk, s->l + 2);

	// Compute the Final Exp
	mclBn_finalExp(r, &aux);
	clock_t end = clock();
	timesDec[0] = timesDec[0] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;

	// Clear auxiliary values
	mclBnGT_clear(&aux);
}