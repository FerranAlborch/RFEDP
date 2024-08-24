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
#include "RFE/rqfe_FH.h"
#include "config.h"


// Function for the SetUp of the scheme. Includes generation of the master secret key.
int SetUp(rqfe_FH_sec_key *MSK, double timesSetUp[]) {

    // Generate the master secret key
    int err = rqfe_FH_generate_master_keys(MSK, timesSetUp);

    return err;
}

// Function for encryption of a database
int Encrypt(rqfe_FH *S, rqfe_FH_ciphertext *c, mpz_t *x, rqfe_FH_sec_key *MSK, double timesEnc[]) {
    
    // Encrypt x
    int err = rqfe_FH_encrypt(c, S, x, MSK, timesEnc);

    return err;
}

// Function for the key derivation
int KeyGen(rqfe_FH_fe_key *FE_key, rqfe_FH *S, rqfe_FH_sec_key *MSK, mpz_t **F, mpz_t e_verification, double timesKeyGen[]) {
    
    // Generate functional key for F
    int err = rqfe_FH_derive_fe_key(FE_key, S, MSK, F, e_verification, timesKeyGen);

    return err;
}

// Function for the decryption
int Decrypt(mpz_t *result, rqfe_FH *S, rqfe_FH_ciphertext *ciphertext, rqfe_FH_fe_key *FE_key, mpz_t **F, double timesDec[]) {
    
    // Decrypt c with FE_key
    int err = rqfe_FH_decrypt(result, S, ciphertext, FE_key, F, timesDec);
    
    return err;
}


int main (int argc, char *argv[]) {
    
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
    mpz_t bound_F;  
    mpz_init(bound_F);  
    mpz_set_ui(bound_F, 2);
    int bits_F = atoi(argv[4]);
    mpz_pow_ui(bound_F, bound_F, bits_F);

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
    
    double timesSetUp[4];
    timesSetUp[0] = timesSetUp[1] = timesSetUp[2] = timesSetUp[3] =  0.0;
    
    double timesEnc[5];
    timesEnc[0] = timesEnc[1] = timesEnc[2] = timesEnc[3] = timesEnc[4] = 0.0;
    
    double timesKeyGen[6];
    timesKeyGen[0] = timesKeyGen[1] = timesKeyGen[2] = timesKeyGen[3] = timesKeyGen[4] = timesKeyGen[5] = 0.0;

    double timesDec[5];
    timesDec[0] = timesDec[1] = timesDec[2] = timesDec[3] = timesDec[4] = 0.0;

    clock_t begin, end;


    // Start loop of executions of the scheme
    for(int i = 0; i < LOOP; ++i) {
        fprintf(stderr,"LOOP %d: ", i+1);

        int err = -1;


        // Compute public parameters (start of SetUp)
        rqfe_FH S;
        begin = clock();
	    err = rqfe_FH_precomp_init(&S, l, bound_X, Q, bound_F);
        if (err != 0) {
            fprintf(stderr,"SetUp ERROR\n");
            return 0;
        }

        // Initialize master secret key
        rqfe_FH_sec_key MSK;
	    rqfe_FH_sec_key_init(&MSK, &S);

        // SetUp
        err = SetUp(&MSK, timesSetUp);
        end = clock();
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
        rqfe_FH_ciphertext c;
	    rqfe_FH_ciphertext_init(&c, &S);

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
        mpz_t **F;
        F = (mpz_t **) malloc(S.l * sizeof(mpz_t*));
        for(size_t i = 0; i < S.l; ++i) {
            F[i] = (mpz_t *) malloc(S.l * sizeof(mpz_t));
            for(size_t j = 0; j < S.l; ++j) {
                mpz_init(F[i][j]);
                mpz_urandomm(F[i][j], state, S.s.bound_Y);
            }
        }
        // Print F
        /*printf("\nF =\n");
        for(size_t i = 0; i < S.l; ++i) {
            for(size_t j = 0; j < S.l; ++j) {
                gmp_printf(" %Zd", F[i][j]);
            }
            printf("\n");
        }*/
        mpz_t e_verification;
        mpz_init(e_verification);

        // Initialize functional key
        rqfe_FH_fe_key FE_key;
	    rqfe_FH_fe_key_init(&FE_key, &S);

        // Key Generation phase
        begin = clock();
        err = KeyGen(&FE_key, &S, &MSK, F, e_verification, timesKeyGen);
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
        err = Decrypt(&result, &S, &c, &FE_key, F, timesDec);
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
            for(size_t j = 0; j < l; ++j) {
                mpz_mul(aux, x[i], x[j]);
                mpz_mul(aux, aux, F[i][j]);
                mpz_add(verification, verification, aux);
            }
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
        rqfe_FH_ciphertext_free(&c);
        rqfe_FH_fe_key_free(&FE_key);
        rqfe_FH_sec_key_free(&MSK);
        rqfe_FH_free(&S);

        for(size_t i = 0; i < S.l; ++i) mpz_clears(x[i], NULL);
        for(size_t i = 0; i < S.l; ++i) {
            for(size_t j = 0; j < S.l; ++j) mpz_clear(F[i][j]);
            free(F[i]);
        }
        free(x);
        free(F);
        mpz_clears(e_verification, result, verification, aux, NULL);
    }

    // Compute time averages and print them
    timeSetUp = timeSetUp / LOOP;
    timesSetUp[0] = timesSetUp[0] / LOOP;
    timesSetUp[1] = timesSetUp[1] / LOOP;
    timesSetUp[2] = timesSetUp[2] / LOOP;
    timesSetUp[3] = timesSetUp[3] / LOOP;

    timeEncrypt = timeEncrypt / LOOP;
    timesEnc[0] = timesEnc[0] / LOOP;
    timesEnc[1] = timesEnc[1] /LOOP;
    timesEnc[2] = timesEnc[2] /LOOP;
    timesEnc[3] = timesEnc[3] /LOOP;
    timesEnc[4] = timesEnc[4] /LOOP;

    timeKeyGen = timeKeyGen / LOOP;
    timesKeyGen[0] = timesKeyGen[0] / LOOP;
    timesKeyGen[1] = timesKeyGen[1] / LOOP;
    timesKeyGen[2] = timesKeyGen[2] / LOOP;
    timesKeyGen[3] = timesKeyGen[3] / LOOP;
    timesKeyGen[4] = timesKeyGen[4] / LOOP;
    timesKeyGen[5] = timesKeyGen[5] / LOOP;

    timeDecrypt = timeDecrypt / LOOP;
    timesDec[0] = timesDec[0] / LOOP;
    timesDec[1] = timesDec[1] / LOOP;
    timesDec[2] = timesDec[2] / LOOP;
    timesDec[3] = timesDec[3] / LOOP;
    timesDec[4] = timesDec[4] / LOOP;

    printf("****************************************************************************\n");
    printf("Parameters:\n");
    printf("Dimension of the vectors: l = %ld\n", l);
    printf("Maximum number of key queries: Q = %d\n", Q);
    printf("Maximum bits of plaintext input: |X| = %d\n", bits_X);
    printf("Maximum bits of function input: |F| = %d\n", bits_F);
    printf("\n");

    printf("Times:\n");
    printf("Total SetUp time: %fs, of which\n", timeSetUp);
    printf("    Time for computing public parameters: %fs\n", timeSetUp - timesSetUp[0] - timesSetUp[1] - timesSetUp[2] - timesSetUp[3]);
    printf("    Time for sampling u: %fs\n", timesSetUp[2]);
    printf("    Time for sampling w: %fs\n", timesSetUp[3]);
    printf("    Time for sampling c: %fs\n", timesSetUp[1]);
    printf("    Time for sampling IPFE.msk: %fs\n", timesSetUp[0]);

    // printf("\n");
    printf("Total Encryption time: %fs, of which\n", timeEncrypt);
    printf("    Time for verifying x is in bound: %fs\n", timesEnc[2]);
    printf("    Time for computing ct_x: %fs\n", timesEnc[3]);
    printf("    Time for computing input for IPFE: %fs\n", timesEnc[4]);
    printf("    Time for computing IPFE.c: %fs\n", timesEnc[0] + timesEnc[1]);
    
    // printf("\n");    
    printf("Total Key Generation time: %fs, of which\n", timeKeyGen);
    printf("    Time for verifying F is in bound: %fs\n", timesKeyGen[2]);
    printf("    Time for computing t'_F: %fs\n", timesKeyGen[3]);
    printf("    Time for computing input for IPFE: %fs\n", timesKeyGen[4]);
    printf("    Time for computing IPFE.sk: %fs\n", timesKeyGen[0] + timesKeyGen[1]);
    printf("    Time for computing zk_F: %fs\n", timesKeyGen[5]);
    
    // printf("\n");    
    printf("Total Decryption time: %fs, of which\n", timeDecrypt);
    printf("    Time for verifying F is in bound: %fs\n", timesDec[4]);
    printf("    Time for computing [d]_T: %fs\n", timesDec[0]);
    printf("    Time for computing [v]_T: %fs\n", timesDec[1] + timesDec[2]);
    printf("    Time for computing the discrete logarithm: %fs\n", timesDec[3]);

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

    // msk: msk_ipfe (u in Fr^(l+1) + v in Fr^l) + u in Fr^l + w in Fr^2l + c in Fr
    size_t size_msk = (l+1)*size_mclBnFr + l*size_mclBnFr + l*size_mclBnFr + 2*l*size_mclBnFr + size_mclBnFr;
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

    // ciphertext: ct in Fr^l + ct_ipfe (ct in G1^(l+2))
    size_t size_ciphertext = l*size_mclBnFr + (l+2)*size_mclBnG1;
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

    // fe_key: ipfe_fe_key (sk in G2^(l+2)) + t_prime in Fr + zk in Fr
    size_t size_fe_key = (l+2)*size_mclBnG2 + size_mclBnFr + size_mclBnFr;
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
	mpz_clears(bound_X, bound_F, NULL);
	gmp_randclear(state);

    return 0;
}

