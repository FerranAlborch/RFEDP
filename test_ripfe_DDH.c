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

#include<stdio.h>
#include <gmp.h>
#include <time.h>
#include <stdint.h>
#include "RFE/ripfe_DDH.h"
#include "config.h"



// Function for the SetUp of the scheme. Includes initialization of the scheme and generation of the master secret key
bool SetUp(ripfe_DDH *S, ripfe_DDH_sec_key *MSK, double timesSetUp[]) {

    // Generate the master secret key and the precomputations for FComb
    ripfe_DDH_generate_master_keys(MSK, S, timesSetUp);

    return true;
}


// Function for encryption of a database
bool Encrypt(ripfe_DDH *S, ipfe_DDH_ciphertext *c, mpz_t *x, ripfe_DDH_sec_key *MSK, double timesEnc[]) {
    bool err = ripfe_DDH_encrypt(c, S, x, MSK, timesEnc);
    if (!err) {
        printf("ERROR in RIPFE encryption.\n");
        return err;
    }

    return err;
}



// Function for the key derivation
bool KeyGen(ripfe_DDH_fe_key *FE_key, ripfe_DDH *S, ripfe_DDH_sec_key *MSK, mpz_t *y, mpz_t e_verification, double timesKeyGen[]) {
    bool err = ripfe_DDH_derive_fe_key(FE_key, S, MSK, y, e_verification, timesKeyGen);
    if (!err) {
        printf("ERROR in RIPFE key generation.\n");
        return err;
    }

    return err;
}


// Function for the decryption
bool Decrypt(mpz_t result, ripfe_DDH *S, ipfe_DDH_ciphertext *ciphertext, ripfe_DDH_fe_key *FE_key, mpz_t *y, double timesDec[]) {
    bool err = ripfe_DDH_decrypt(result, S, ciphertext, FE_key, y, timesDec);
    if (!err) {
        printf("ERROR in RIPFE decryption.\n");
        return err;
    }

    return err;
}


int main(int argc, char *argv[]) {

    // first choose meta-parameters for the scheme
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


    double timeSetUp = 0., timeEncrypt = 0., timeKeyGen = 0., timeDecrypt = 0.;
    
    double timesSetUp[2];
    timesSetUp[0] = timesSetUp[1] = 0.0;
    
    double timesEnc[2];
    timesEnc[0] = timesEnc[1] = 0.0;
    
    double timesKeyGen[3];
    timesKeyGen[0] = timesKeyGen[1] = timesKeyGen[2] = 0.0;

    double timesDec[5];
    timesDec[0] = timesDec[1] = timesDec[2] = timesDec[3] = timesDec[4] = 0.0;

    clock_t begin, end;


    for (int i = 0; i < LOOP; ++i) {
        fprintf(stderr,"LOOP %d: ", i+1);

        // Initialize public parameters
        ripfe_DDH S;
        bool err = ripfe_DDH_precomp_init(&S, l, bound_X, Q, bound_Y);
        if (!err) {
            fprintf(stderr,"SetUp ERROR\n");
            return 0;
        }

        // Initialize master secret key
        ripfe_DDH_sec_key MSK;
        ripfe_DDH_sec_key_init(&MSK);

        // SetUp phase
        begin = clock();
        err = SetUp(&S, &MSK, timesSetUp);
        end = clock();
        if (!err) {
            fprintf(stderr,"SetUp ERROR\n");
            return 0;
        }
        timeSetUp = timeSetUp + (double)(end - begin) / CLOCKS_PER_SEC;
        fprintf(stderr,"SetUp OK; ");


        // Initialize plaintext
        mpz_t *x;
        x = (mpz_t *) malloc(S.s.l * sizeof(mpz_t));
        for(size_t i = 0; i < S.s.l; ++i) mpz_init(x[i]);

        // set the vector (of length l) that you want to encrypt
        // x has a random value for each coefficient
        mpz_t bound_X2;
        mpz_init(bound_X2);
        mpz_mul_ui(bound_X2, bound_X, 2);
        for(size_t i = 0; i < S.s.l; ++i) {
            mpz_urandomm(x[i], state, S.s.bound_X);
            //mpz_sub(x[i], x[i], S.s.bound_X);
        } 
        mpz_clear(bound_X2);
        //cfe_uniform_sample_vec(&x, bound_X);

        
        // Initialize ciphertext
        ipfe_DDH_ciphertext c;
        ipfe_DDH_ciphertext_init(&c, &S.s);

        // Encryption phase
        begin = clock();
        err = Encrypt(&S, &c, x, &MSK, timesEnc);
        end = clock();
        if (!err) {
            fprintf(stderr,"Encryption ERROR\n");
            return 0;
        }
        timeEncrypt = timeEncrypt + (double)(end - begin) / CLOCKS_PER_SEC;
        fprintf(stderr,"Encryption OK; ");


        // Initialize query
        mpz_t *y;
        y = (mpz_t *) malloc(S.s.l * sizeof(mpz_t));
        for(size_t i = 0; i < S.s.l; ++i) mpz_init(y[i]);

        // choose an inner product vector y that will be multiplied with
        // the encrypted x; we set it at random
        mpz_t bound_Y2;
        mpz_init(bound_Y2);
        mpz_mul_ui(bound_Y2, bound_Y, 2);
        for(size_t i = 0; i < S.s.l; ++i) {
            mpz_urandomm(y[i], state, S.s.bound_Y);
            //mpz_sub(y[i], y[i], S.s.bound_Y);
        } 
        mpz_clear(bound_Y2);
        //cfe_uniform_sample_vec(&y, bound_Y);


        // Initialize functional decryption key
        ripfe_DDH_fe_key FE_key;
        ripfe_DDH_fe_key_init(&FE_key);

        mpz_t e_verification;
        mpz_init(e_verification);

        // Key Generation phase
        begin = clock();
        err = KeyGen(&FE_key, &S, &MSK, y, e_verification, timesKeyGen);
        end = clock();
        if (!err) {
            fprintf(stderr,"Key Generation ERROR\n");
            return 0;
        }
        timeKeyGen = timeKeyGen + (double)(end - begin) / CLOCKS_PER_SEC;
        fprintf(stderr,"Key Generation OK; ");
        

        // Initialize values for verification
        mpz_t expected;
        mpz_t result;
        mpz_inits(expected, result, NULL);

        mpz_t aux, verification_dec;
        mpz_inits(aux, verification_dec, NULL);
        // Compute the expected value
        // Generate u
        gmp_randstate_t state_u;
        gmp_randinit_default(state_u);
        gmp_randseed(state_u, MSK.seed_u);
        mpz_t *u = (mpz_t *) malloc(S.s.l * sizeof(mpz_t));
        for(size_t i = 0; i < S.s.l; ++i) {
            mpz_init(u[i]);
            mpz_urandomm(u[i], state_u, S.s.phi_p);
            mpz_add_ui(u[i], u[i], 1);
        }
        gmp_randclear(state_u);
        for(size_t i = 0; i < S.s.l; ++i) {
            mpz_mul(aux, x[i], y[i]);
            mpz_add(expected, expected, aux);

            mpz_add(aux, x[i], u[i]);
            mpz_mod(aux, aux, S.s.p);
            mpz_mul(aux, aux, y[i]);
            mpz_add(verification_dec, verification_dec, aux);
        }
        for(size_t i = 0; i < S.s.l; ++i) mpz_clear(u[i]);
        free(u);

        mpz_sub(aux, FE_key.d, FE_key.zk);
        mpz_add(verification_dec, verification_dec, aux);

        mpz_clear(aux);
        mpz_add(expected, expected, e_verification);

        int compare = mpz_cmp(verification_dec, expected);
        //printf("The verification decryption value is as expected: %d\n", compare);

        mpz_clear(verification_dec);

        // Decryption phase
        begin = clock();
        err = Decrypt(result, &S, &c, &FE_key, y, timesDec);
        end = clock();
        if (!err) {
            fprintf(stderr,"Decryption ERROR\n");
            return 0;
        }
        timeDecrypt = timeDecrypt + (double)(end - begin) / CLOCKS_PER_SEC;
        fprintf(stderr,"Decryption OK\n");
        
        
        // printf("Dimension of the input database %ld\n", l);
        //gmp_printf("The randomized inner product of the vector x and y in dimension %ld is %Zd\n", l, result);
        compare = mpz_cmp(expected, result);
        if (compare != 0) printf("The result does not match the expected value.\n");
        // else printf("The result is correct.\n");


        // we clear the memory
        mpz_clears(result, expected, e_verification, NULL);
        for(size_t i = 0; i < S.s.l; ++i) {
            mpz_clears(x[i], y[i], NULL);
        }
        free(x);
        free(y);
        ipfe_DDH_ciphertext_free(&c);
        ripfe_DDH_sec_key_free(&MSK);
        ripfe_DDH_fe_key_free(&FE_key);
        ripfe_DDH_free(&S);
    }

    
    // Compute time averages and print them
    timeSetUp = timeSetUp / LOOP;
    timesSetUp[0] = timesSetUp[0] / LOOP;
    timesSetUp[1] = timesSetUp[1] / LOOP;

    timeEncrypt = timeEncrypt / LOOP;
    timesEnc[0] = timesEnc[0] / LOOP;
    timesEnc[1] = timesEnc[1] /LOOP;

    timeKeyGen = timeKeyGen / LOOP;
    timesKeyGen[0] = timesKeyGen[0] / LOOP;
    timesKeyGen[1] = timesKeyGen[1] / LOOP;
    timesKeyGen[2] = timesKeyGen[2] / LOOP;

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
    printf("Maximum bits of function input: |Y| = %d\n", bits_Y);
    printf("\n");

    printf("Times:\n");
    printf("Total SetUp time: %fs, of which\n", timeSetUp);
    printf("    Time for sampling each seed: %fs * 3\n", timesSetUp[0]);
    printf("    Time for doing FComb precomputations: %fs * 2\n", timesSetUp[1]);

    // printf("\n");
    printf("Total Encryption time: %fs, of which\n", timeEncrypt);
    printf("    Time for computing C (and D): %fs * 2\n", timesEnc[0]);
    printf("    Time for computing E: %fs\n", timesEnc[1]);
    
    // printf("\n");    
    printf("Total Key Generation time: %fs, of which\n", timeKeyGen);
    printf("    Time for computing d_y: %fs\n", timesKeyGen[0]);
    printf("    Time for computing zk_y: %fs\n", timesKeyGen[1]);
    printf("    Time for computing the inner product: %fs * 2\n", timesKeyGen[2]);
    
    // printf("\n");    
    printf("Total Decryption time: %fs, of which\n", timeDecrypt);
    printf("    Time for computing large multiexponentiation in numerator: %fs\n", timesDec[0]);
    printf("    Time for computing little multiexponentiation in denominator: %fs\n", timesDec[1]);
    printf("    Time for computing the division: %fs\n", timesDec[2]);
    printf("    Time for computing the extra exponentiation: %fs\n", timesDec[3]);
    printf("    Time for computing the discrete logarithm: %fs\n", timesDec[4]);

    // Compute sizes and print them
    // printf("\n");
    // printf("\n");
    printf("\n");
    printf("Sizes:\n");
    size_t p_bytes = MODULUS_LEN/8;

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

    // msk: 3 seeds of size seed_size * sizeof(uint64_t)
    size_t size_msk = 3 * SEED_SIZE * sizeof(uint64_t);
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

    // ciphertext: vector of elements in Zp and size l+2
    size_t size_ciphertext = (l + 2) * p_bytes;
    if (size_ciphertext > 1024*1024) {
        printf("Ciphertext size: %ldMB\n", size_ciphertext/(1024*1024));
    } 
    else if (size_ciphertext > 1024) {
        printf("Ciphertext size: %ldKB\n", size_ciphertext/1024);
    }
    else printf("Ciphertext key size: %ldB\n", size_ciphertext);
    // printf("\n");

    // fe_key: element d, element zk, and two elements in cfe_fe_key all in Zp
    size_t size_fe_key = 4 * p_bytes;
    if (size_fe_key > 1024) {
        printf("Functional decryption key size: %ldKB\n", size_fe_key/1024);
    }
    else printf("Functional decryption key size: %ldB\n", size_fe_key);
    // printf("\n");
    printf("****************************************************************************\n");

    // we clear the memory
    mpz_clears(bound_X, bound_Y, NULL);
    gmp_randclear(state);

    return 0;
}
