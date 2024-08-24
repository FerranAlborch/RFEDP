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
#include "RFE/ripfe_FH.h"
#include "config.h"


// Function for the SetUp of the scheme. Includes generation of the master secret key.
int SetUp(ripfe_FH_sec_key *MSK, double timesSetUp[]) {

    // Generate the master secret key
    int err = ripfe_FH_generate_master_keys(MSK, timesSetUp);

    return err;
}

// Function for encryption of a database
int Encrypt(ripfe_FH *S, ripfe_FH_ciphertext *c, mpz_t *x, ripfe_FH_sec_key *MSK, double timesEnc[]) {
    
    // Encrypt x
    int err = ripfe_FH_encrypt(c, S, x, MSK, timesEnc);

    return err;
}

// Function for the key derivation
int KeyGen(ripfe_FH_fe_key *FE_key, ripfe_FH *S, ripfe_FH_sec_key *MSK, mpz_t *y, mpz_t e_verification, double timesKeyGen[]) {
    
    // Generate functional key for F
    int err = ripfe_FH_derive_fe_key(FE_key, S, MSK, y, e_verification, timesKeyGen);

    return err;
}

// Function for the decryption
int Decrypt(mpz_t *result, ripfe_FH *S, ripfe_FH_ciphertext *ciphertext, ripfe_FH_fe_key *FE_key, mpz_t *y, double timesDec[]) {
    
    // Decrypt c with FE_key
    int err = ripfe_FH_decrypt(result, y, S, ciphertext, FE_key, timesDec);
    
    return err;
}

int main(int argc, char *argv[]) {

	// First choose meta-parameters for the scheme
    size_t l = atoi(argv[1]); // dimension of encryption vector taken as input
    int Q = atoi(argv[2]); // number of queries that can be asked taken as input

	// bound of the input values set to 2^input
    mpz_t bound_X; 
    mpz_init(bound_X);
    mpz_set_ui(bound_X, 2);
    int bits_X = atoi(argv[3]);
    mpz_pow_ui(bound_X, bound_X, bits_X);

    // bound for the function set to 2^input
    mpz_t bound_Y;  
    mpz_init(bound_Y);  
    mpz_set_ui(bound_Y, 2);
    int bits_Y = atoi(argv[4]);
    mpz_pow_ui(bound_Y, bound_Y, bits_Y);

    // Seed for randomness sampling
    mpz_t seed;
    mpz_init2(seed, SEED_SIZE * sizeof(uint64_t));
    generate_seed(seed, SEED_SIZE);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed(state, seed);
    mpz_clear(seed);

	// Vectors for storing the timings
	double timeSetUp = 0., timeEncrypt = 0., timeKeyGen = 0., timeDecrypt = 0.;
	double timesSetUp[1], timesEnc[4], timesKeyGen[4], timesDec[3];
	timesSetUp[0] = 0.0;
	timesEnc[0] = timesEnc[1] = timesEnc[2] = timesEnc[3] = 0.0;
	timesKeyGen[0] = timesKeyGen[1] = timesKeyGen[2] = timesKeyGen[3] = 0.0;
	timesDec[0] = timesDec[1] = timesDec[2] = 0.0;


	// Start loop of executions of the scheme
	for(int i = 0; i < LOOP; ++i) {
		fprintf(stderr,"LOOP %d: ", i+1);

        int err = -1;


        // Compute public parameters (start of SetUp)
        ripfe_FH S;
        clock_t begin = clock();
	    err = ripfe_FH_precomp_init(&S, l, bound_X, Q, bound_Y);
        if (err != 0) {
            fprintf(stderr,"SetUp ERROR\n");
            return 0;
        }

        // Initialize master secret key
        ripfe_FH_sec_key MSK;
	    ripfe_FH_sec_key_init(&MSK, &S);

        // SetUp
        err = SetUp(&MSK, timesSetUp);
        clock_t end = clock();
        if (err != 0) {
            fprintf(stderr,"SetUp ERROR\n");
            return 0;
        }
        timeSetUp = timeSetUp + (double)(end - begin) / CLOCKS_PER_SEC;
        fprintf(stderr,"SetUp OK; ");


        // Generate plaintext random in bound_X
        mpz_t *x;
        x = (mpz_t *) malloc(S.l * sizeof(mpz_t));
        for(size_t i = 0; i < S.l; ++i) {
            mpz_init(x[i]);
            mpz_urandomm(x[i], state, S.s.bound_X);
        } 
        // Print x
        /*printf("\nx =");
        for(size_t i = 0; i < S.l; ++i) gmp_printf(" %Zd", x[i]);
        printf("\n");*/

        // Initialize ciphertext
        ripfe_FH_ciphertext c;
	    ripfe_FH_ciphertext_init(&c, &S);

        // Encryption phase
        begin = clock();
        err = Encrypt(&S, &c, x, &MSK, timesEnc);
        end = clock();
        if (err != 0) {
            fprintf(stderr,"Encryption ERROR\n");
            return 0;
        }
        timeEncrypt = timeEncrypt + (double)(end - begin) / CLOCKS_PER_SEC;
        fprintf(stderr,"Encryption OK; ");


        // Generate quadratic query random in bound_Y and mpz to store the noise sampled
        // during KeyGen for verification purposes
        mpz_t *y;
        y = (mpz_t *) malloc(S.l * sizeof(mpz_t));
        for(size_t i = 0; i < S.l; ++i) {
			mpz_init(y[i]);
			mpz_urandomm(y[i], state, S.s.bound_Y);

        }
        // Print y
        /*printf("\ny =");
        for(size_t i = 0; i < S.l; ++i) gmp_printf(" %Zd", F[i][j]);
		printf("\n");*/
        mpz_t e_verification;
        mpz_init(e_verification);

        // Initialize functional key
        ripfe_FH_fe_key FE_key;
	    ripfe_FH_fe_key_init(&FE_key, &S);

        // Key Generation phase
        begin = clock();
        err = KeyGen(&FE_key, &S, &MSK, y, e_verification, timesKeyGen);
        end = clock();
        if (err != 0) {
            fprintf(stderr,"Key Generation ERROR\n");
            return 0;
        }
        timeKeyGen = timeKeyGen + (double)(end - begin) / CLOCKS_PER_SEC;
        fprintf(stderr,"Key Generation OK; ");


        // Decryption phase
        mpz_t result;
        mpz_init(result);
        begin = clock();
        err = Decrypt(&result, &S, &c, &FE_key, y, timesDec);
        end = clock();
        if (err != 0) {
            fprintf(stderr,"Decryption ERROR\n");
            return 0;
        }
        timeDecrypt = timeDecrypt + (double)(end - begin) / CLOCKS_PER_SEC;
        fprintf(stderr,"Decryption OK\n");


        // Verification
        mpz_t verification, aux;
        mpz_inits(verification, aux, NULL);
        for(size_t i = 0; i < l; ++i) {
			mpz_mul(aux, x[i], y[i]);
			mpz_mod(aux, aux, S.s.pg.r);
			mpz_add(verification, verification, aux);
			mpz_mod(verification, verification, S.s.pg.r);
		}
        mpz_add(verification, verification, e_verification);
        int compare = mpz_cmp(verification, result);
        if (compare != 0) {
            printf("The result does not match the expected value.\n");
            return 0;
        }
        //gmp_printf("Expected result = %Zd\n", verification);
        //gmp_printf("Output of Decryption = %Zd\n", result);

        // Clearing and freeing 
        ripfe_FH_ciphertext_free(&c);
        ripfe_FH_fe_key_free(&FE_key);
        ripfe_FH_sec_key_free(&MSK);
        ripfe_FH_free(&S);

        for(size_t i = 0; i < S.l; ++i) mpz_clears(x[i], NULL);
        for(size_t i = 0; i < S.l; ++i) mpz_clear(y[i]);
        free(x);
        free(y);
        mpz_clears(e_verification, result, verification, aux, NULL);
	}

	
	// Compute time averages and print them
    timeSetUp = timeSetUp / LOOP;
    timesSetUp[0] = timesSetUp[0] / LOOP;

    timeEncrypt = timeEncrypt / LOOP;
    timesEnc[0] = timesEnc[0] / LOOP;
    timesEnc[1] = timesEnc[1] /LOOP;
    timesEnc[2] = timesEnc[2] /LOOP;
    timesEnc[3] = timesEnc[3] /LOOP;

    timeKeyGen = timeKeyGen / LOOP;
    timesKeyGen[0] = timesKeyGen[0] / LOOP;
    timesKeyGen[1] = timesKeyGen[1] / LOOP;
    timesKeyGen[2] = timesKeyGen[2] / LOOP;
    timesKeyGen[3] = timesKeyGen[3] / LOOP;

    timeDecrypt = timeDecrypt / LOOP;
    timesDec[0] = timesDec[0] / LOOP;
    timesDec[1] = timesDec[1] / LOOP;
	timesDec[2] = timesDec[2] / LOOP;

    printf("****************************************************************************\n");
    printf("Parameters:\n");
    printf("Dimension of the vectors: l = %ld\n", l);
    printf("Maximum number of key queries: Q = %d\n", Q);
    printf("Maximum bits of plaintext input: |X| = %d\n", bits_X);
    printf("Maximum bits of function input: |y| = %d\n", bits_Y);
    printf("\n");

    printf("Times:\n");
    printf("Total SetUp time: %fs, of which\n", timeSetUp);
    printf("    Time for computing public parameters: %fs\n", timeSetUp - timesSetUp[0]);
    printf("    Time for sampling IPFE.msk: %fs\n", timesSetUp[0]);

    // printf("\n");
    printf("Total Encryption time: %fs, of which\n", timeEncrypt);
    printf("    Time for verifying x is in bound: %fs\n", timesEnc[2]);
    printf("    Time for computing input for IPFE: %fs\n", timesEnc[3]);
    printf("    Time for computing IPFE.c: %fs\n", timesEnc[0] + timesEnc[1]);
    
    // printf("\n");    
    printf("Total Key Generation time: %fs, of which\n", timeKeyGen);
    printf("    Time for verifying y is in bound: %fs\n", timesKeyGen[2]);
    printf("    Time for computing input for IPFE: %fs\n", timesKeyGen[3]);
    printf("    Time for computing IPFE.sk: %fs\n", timesKeyGen[0] + timesKeyGen[1]);
    
    // printf("\n");    
    printf("Total Decryption time: %fs, of which\n", timeDecrypt);
    printf("    Time for computing bound: %fs\n", timesDec[2]);
    printf("    Time for computing pairing: %fs\n", timesDec[0]);
    printf("    Time for computing the discrete logarithm: %fs\n", timesDec[1]);

    // Compute sizes and print them
    // printf("\n");
    // printf("\n");
    printf("\n");
    printf("Sizes:TODO\n");
    //size_t p_bytes = MODULUS_LEN/8;

    // Database size: vector of l elements bounded by bound_X
    int padding_bits = bits_X % 64;
    padding_bits = 64 - padding_bits;
    bits_X = bits_X + padding_bits;
    int bytes_X = bits_X/8;
    size_t size_database = bytes_X * l;
    if (size_database > 1024*1024) {
        printf("Database size: %ldMB\n", size_database/(1024*1024));
    } 
    else if (size_database > 1024) {
        printf("Database size: %ldKB\n", size_database/1024);
    }
    else printf("Database size: %ldB\n", size_database);
    // printf("\n");

    // Precomputing sizes of mclBnFr, mclBnG1, mclBnG2 and mclBnGT
    size_t size_mclBnFr = 4 * sizeof(uint64_t); // vector of 4 uint64_t
    size_t size_mclBnFp = 6 * sizeof(uint64_t); // vector of 6 uint64_t
    size_t size_mclBnFp2 = 2 * size_mclBnFp; // vector of 2 mclBnFp
    size_t size_mclBnG1 = 3 * size_mclBnFp; // 3 coordinates in mclBnFp
    size_t size_mclBnG2 = 3 * size_mclBnFp2; // 3 coordinates in mclBnFp2
    //size_t size_mclBnGT = 12 * size_mclBnFp; // vector of 12 mclBnFp

    // msk: msk_ipfe (u in Fr^(l+2) + v in Fr^(l+1))
    size_t size_msk = (l+2)*size_mclBnFr + (l+1)*size_mclBnFr;
    if (size_msk > 1024*1024*1024) {
        printf("Master secret key size: %ldGB\n", size_msk/(1024*1024*1024));
    }
    else if (size_msk > 1024*1024) {
        printf("Master secret key size: %ldMB\n", size_msk/(1024*1024));
    } 
    else if (size_msk > 1024) {
        printf("Master secret key size: %ldKB\n", size_msk/1024);
    }
    else printf("Master secret key size: %ldB\n", size_msk);
    // printf("\n");

    // ciphertext: ct_ipfe (ct_ipfe in G1^(l+3))
    size_t size_ciphertext = (l+3)*size_mclBnG1;
    if (size_ciphertext > 1024*1024*1024) {
        printf("Ciphertext size: %ldGB\n", size_ciphertext/(1024*1024*1024));
    }
    else if (size_ciphertext > 1024*1024) {
        printf("Ciphertext size: %ldMB\n", size_ciphertext/(1024*1024));
    } 
    else if (size_ciphertext > 1024) {
        printf("Ciphertext size: %ldKB\n", size_ciphertext/1024);
    }
    else printf("Ciphertext key size: %ldB\n", size_ciphertext);
    // printf("\n");

    // fe_key: ipfe_fe_key (sk in G2^(l+3))
    size_t size_fe_key = (l+3)*size_mclBnG2;
    if (size_fe_key > 1024*1024*1024) {
        printf("Functional decryption key size: %ldGB\n", size_fe_key/(1024*1024*1024));
    }
    else if (size_fe_key > 1024*1024) {
        printf("Functional decryption key size: %ldMB\n", size_fe_key/(1024*1024));
    } 
    else if (size_fe_key > 1024) {
        printf("Functional decryption key size: %ldKB\n", size_fe_key/1024);
    }
    else printf("Functional decryption key size: %ldB\n", size_fe_key);
    // printf("\n");
    printf("****************************************************************************\n");


	// Clearing and freeing
	mpz_clears(bound_X, bound_Y, NULL);
	gmp_randclear(state);

	return 0;
}