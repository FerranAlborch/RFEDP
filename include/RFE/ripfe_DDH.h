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
#include "IPFE/ipfe_DDH.h"

/**
* \file
* \ingroup RFE
* \brief This is the secret-key randomized inner-product functional encryption in Section 4 
* from the paper "Computational Differential Privacy for Encrypted Databases Supporting Linear 
* Queries" by Alborch Escobar, Canard, Laguillaumie and Phan, based on the DDH scheme from 
* Section 3 from the paper "Adaptive simulation security for inner product functional encryption" 
* by Agrawal, Libert, Maitra and Titiu.
*/

/**
* \struct ripfe_DDH ripfe_DDH.h "RFE/ripfe_DDH.h"
* \brief It represents the public parameters of the randomized inner-product scheme. 
*/
typedef struct ripfe_DDH {
    ipfe_DDH s; /**< Public parameters of the non-randomized scheme. */
    float epsilon; /**< Privacy budget for the scheme. */
    int Q; /**< Number of functional key queries allowed. */
} ripfe_DDH;

/**
* \struct ripfe_DDH_sec_key ripfe_DDH.h "RFE/ripfe_DDH.h"
* \brief It represents a master secret key of the randomized inner-product scheme.
*/
typedef struct ripfe_DDH_sec_key {
    ipfe_DDH_sec_key msk; /**< Master secret key of the non-randomized scheme. */
    mpz_t seed_u; /**< One-time pad u. */
} ripfe_DDH_sec_key;

/**
* \struct ripfe_DDH_fe_key ripfe_DDH.h "RFE/ripfe_DDH.h"
* \brief It represents a functional decryption key of the randomized inner-product scheme.
*/
typedef struct ripfe_DDH_fe_key {
    ipfe_DDH_fe_key fe_key; /**< Functional decryption key of the non-randomized scheme. */
    mpz_t d; /**< Padded differentially private noise. */
    mpz_t zk; /**< Extra terms. */
} ripfe_DDH_fe_key;

/**
* \fn bool ripfe_DDH_precomp_init(ripfe_DDH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y)
* \brief It initializes public parameters of the randomized inner-product scheme for a 
* precomputed set of safe prime values. 
*
* \param S A pointer to a ipfe_DDH structure.
* \param l The dimension of the vectors for the inner-product scheme.
* \param bound_X The bound on the plaintext inputs.
* \param Q The maximum number of functional queries to be asked.
* \param bound_Y the bound on the function.
*/
bool ripfe_DDH_precomp_init(ripfe_DDH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y);

/**
* \fn void ripfe_DDH_free(ripfe_DDH *S)
* \brief It clears public parameters of the randomized inner-product scheme and frees allocated memory.
*
* \param S A pointer to a ripfe_DDH structure.
*/
void ripfe_DDH_free(ripfe_DDH *S);

/**
* \fn void ripfe_DDH_sec_key_init(ripfe_DDH_sec_key *MSK)
* \brief It initializes a master secret key of the randomized inner-product scheme.
*
* \param MSK A pointer to a ripfe_DDH_sec_key structure.
*/
void ripfe_DDH_sec_key_init(ripfe_DDH_sec_key *MSK);

/**
* \fn void ripfe_DDH_sec_key_free(ripfe_DDH_sec_key *MSK)
* \brief It clears a master secret key of the randomized inner-product scheme and frees allocated memory.
*
* \param MSK A pointer to a ripfe_DDH_sec_key structure.
*/
void ripfe_DDH_sec_key_free(ripfe_DDH_sec_key *MSK);

/**
* \fn void ripfe_DDH_fe_key_init(ripfe_DDH_fe_key *FE_key)
* \brief It initializes a functional decryption key of the randomized inner-product scheme.
*
* \param FE_key A pointer to a ripfe_DDH_fe_key structure.
*/
void ripfe_DDH_fe_key_init(ripfe_DDH_fe_key *FE_key);

/**
* \fn void ripfe_DDH_fe_key_free(ripfe_DDH_fe_key *FE_key)
* \brief It clears a functional decryption key of the randomized inner-product scheme and frees 
* allocated memory.
*
* \param FE_key A pointer to a ripfe_DDH_fe_key structure.
*/
void ripfe_DDH_fe_key_free(ripfe_DDH_fe_key *FE_key);

/**
* \fn void ripfe_DDH_generate_master_keys(ripfe_DDH_sec_key *MSK, ripfe_DDH *S, double timesSetUp[])
* \brief It generates a master secret key for the randomized inner-product scheme.
*
* \param MSK A pointer to a ripfe_DDH_sec_key structure.
* \param S A pointer to a ripfe_DDH structure.
* \param timesSetUp An array to store the timings of this protocol.
*/
void ripfe_DDH_generate_master_keys(ripfe_DDH_sec_key *MSK, ripfe_DDH *S, double timesSetUp[]);

/**
* \fn bool ripfe_DDH_encrypt(ipfe_DDH_ciphertext *c, ripfe_DDH *S, mpz_t *x, ripfe_DDH_sec_key *MSK, double timesEnc[])
* \brief It encrypts a message following the randomized inner-product scheme.
*
* \param c A pointer to a ipfe_DDH_ciphertext structure.
* \param S A pointer to a ripfe_DDH structure.
* \param x An array of multiple precision integers as plaintext message.
* \param MSK A pointer to a ripfe_DDH_sec_key structure.
* \param timesEnc An array to store the timings of this protocol.
*/
bool ripfe_DDH_encrypt(ipfe_DDH_ciphertext *c, ripfe_DDH *S, mpz_t *x, ripfe_DDH_sec_key *MSK, double timesEnc[]);

/**
* \fn bool ripfe_DDH_derive_fe_key(ripfe_DDH_fe_key *FE_key, ripfe_DDH *S, ripfe_DDH_sec_key *MSK, mpz_t *y, mpz_t e_verification, double timesKeyGen[])
* \brief It derives functional decryption keys following the randomized inner-product scheme.
*
* \param FE_key A pointer to a ripfe_DDH_fe_key structure.
* \param S A pointer to a ripfe_DDH structure.
* \param MSK A pointer to a ripfe_DDH_fe_key structure.
* \param y An array of multiple precision integers as a function.
* \param e_verification A multiple precision integer to store the noise e for verification purposes.
* \param timesKeyGen An array to store the timings of this protocol.
*/
bool ripfe_DDH_derive_fe_key(ripfe_DDH_fe_key *FE_key, ripfe_DDH *S, ripfe_DDH_sec_key *MSK, mpz_t *y, mpz_t e_verification, double timesKeyGen[]);

/**
* \fn bool ripfe_DDH_decrypt(mpz_t result, ripfe_DDH *S, ipfe_DDH_ciphertext *ciphertext, ripfe_DDH_fe_key *FE_key, mpz_t *y, double timesDec[])
* \brief It decrypts a ciphertext with a functional decryption key following the randomized inner-product 
* scheme.
*
* \param result A multiple precision integer to store the result.
* \param S A pointer to a ripfe_DDH structure.
* \param ciphertext A pointer to a ipfe_DDH_ciphertext structure.
* \param FE_key A pointer to a ripfe_key structure.
* \param y A pointer to a function array.
* \param timesDec An array to store the timings of this protocol.
*/
bool ripfe_DDH_decrypt(mpz_t result, ripfe_DDH *S, ipfe_DDH_ciphertext *ciphertext, ripfe_DDH_fe_key *FE_key, mpz_t *y, double timesDec[]);