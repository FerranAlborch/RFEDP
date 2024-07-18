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


int main()
{
	char buf[1600];
	size_t l = 5;
	mpz_t bound_X, bound_Y;
	mpz_inits(bound_X, bound_Y, NULL);
	mpz_set_ui(bound_X, 50);
	mpz_set_ui(bound_Y, 50);

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

	
	// SetUp
	ipfe_FH s;
	clock_t begin = clock();
	int verify = ipfe_FH_precomp_init(&s, l ,bound_X, bound_Y);
	clock_t end = clock();
	timesSetUp[0] = timesSetUp[0] + ((double )(end - begin) / CLOCKS_PER_SEC);


	ipfe_FH_sec_key msk;
	ipfe_FH_sec_key_init(&msk, &s);
	ipfe_FH_generate_master_keys(&msk, timesSetUp);


	// Encryption
	ipfe_FH_ciphertext c;
	ipfe_FH_ciphertext_init(&c, &s);

	mpz_t *x;
    x = (mpz_t *) malloc(s.l * sizeof(mpz_t));
    for(size_t i = 0; i < s.l; ++i) mpz_init(x[i]);
	for(size_t i = 0; i < s.l; ++i) {
		mpz_urandomm(x[i], state, s.bound_X);
	}
	mclBnFr *xFr;
    xFr = (mclBnFr *) malloc(s.l * sizeof(mclBnFr));
	// mpz_to_mclBnFr(xFr, x, s.l);
	for(size_t i = 0; i < s.l; ++i) mclBnFr_setByCSPRNG(&xFr[i]);
	ipfe_FH_encrypt_unbounded(&c, &s, xFr, &msk, timesEnc);

	// Key Generation 
	ipfe_FH_fe_key fe_key;
	ipfe_FH_fe_key_init(&fe_key, &s);

	mpz_t *y;
    y = (mpz_t *) malloc(s.l * sizeof(mpz_t));
    for(size_t i = 0; i < s.l; ++i) mpz_init(y[i]);
	for(size_t i = 0; i < s.l; ++i) {
		mpz_urandomm(y[i], state, s.bound_Y);
	}
	mclBnFr *yFr;
    yFr = (mclBnFr *) malloc(s.l * sizeof(mclBnFr));
	// mpz_to_mclBnFr(yFr, y, s.l);
	for(size_t i = 0; i < s.l; ++i) mclBnFr_setByCSPRNG(&xFr[i]);
	ipfe_FH_derive_fe_key_unbounded(&fe_key, &s, &msk, yFr, timesKeyGen);


	// Decryption
	mclBnGT result;
	ipfe_FH_decrypt_exp(&result, &s, &c, &fe_key, timesDec);



	// Verification
	
	/*mclBnFr *xFr, *yFr;
	xFr = (mclBnFr *) malloc(s.l * sizeof(mclBnFr));
	yFr = (mclBnFr *) malloc(s.l * sizeof(mclBnFr));
	mpz_to_mclBnFr(xFr, x, s.l);
	mpz_to_mclBnFr(yFr, y, s.l);*/

	mclBnFr result_Fr, auxFr;	
	mpz_t result_mpz, aux;
	mpz_inits(result_mpz, aux, NULL);
	mclBnFr_to_mpz(x, xFr, l);
	mclBnFr_to_mpz(y, yFr, l);
	for(size_t i = 0; i < l; ++i) {
		mpz_mul(aux, x[i], y[i]);
		mpz_mod(aux, aux, s.pg.r);
		mpz_add(result_mpz, result_mpz, aux);
		mpz_mod(result_mpz, result_mpz, s.pg.r);
	}
	gmp_printf("Expected result in mpz = %Zd\n", result_mpz);
	mclBnFr_clear(&result_Fr);
	for(size_t i = 0; i < s.l; ++i) {
		mclBnFr_mul(&auxFr, &xFr[i], &yFr[i]);
		mclBnFr_add(&result_Fr, &result_Fr, &auxFr);
	}
	mclBnFr_getStr(buf, sizeof(buf), &result_Fr, 10);
	printf("Expected result in Fr = %s\n", buf);

	mclBnGT verification;
	mclBnGT_pow(&verification, &s.pg.gT, &result_Fr);
	verify = mclBnGT_isEqual(&result, &verification);	

	printf("Print 1 if Decryption is correct: %d\n", verify);
	free(xFr);
	free(yFr);
	

	// Clearing and freeing
	ipfe_FH_ciphertext_free(&c);
	ipfe_FH_fe_key_free(&fe_key);
	ipfe_FH_sec_key_free(&msk);
	ipfe_FH_free(&s);
	
	for(size_t i = 0; i < s.l; ++i) mpz_clears(x[i], y[i], NULL);
	free(x);
	free(y);
	mpz_clears(bound_X, bound_Y, result_mpz, aux, NULL);
	gmp_randclear(state);
}