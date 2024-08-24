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

#include <stdbool.h>
#include <gmp.h>
#include "IPFE/ipfe_FH.h"
#include "utils/rand.h"

/**
* \file
* \ingroup RFE
* \brief This is the secret-key randomized inner-product functional encryption TODO
*
*/

/**
* \struct ripfe_FH ripfe_FH.h "RFE/ripfe_FH.h"
* \brief It represents the public parameters of the randomized inner-product scheme. 
*/
typedef struct ripfe_FH {
    ipfe_FH s; /**< Public parameters of the function-hiding inner-product scheme. */
    float epsilon; /**< Privacy budget for the scheme. */
    int Q; /**< Number of functional key queries allowed. */
    size_t l; /**< Dimension of the input. */
} ripfe_FH;

/**
* \struct ripfe_FH_sec_key ripfe_FH.h "RFE/ripfe_FH.h"
* \brief It represents a master secret key of the randomized inner-product scheme.
*/
typedef struct ripfe_FH_sec_key {
    ipfe_FH_sec_key msk_ipfe; /**< Master secret key of the function-hiding inner-product scheme. */
    size_t l; /**< Dimension of the input. */
} ripfe_FH_sec_key;

/**
* \struct ripfe_FH_fe_key ripfe_FH.h "RFE/ripfe_FH.h"
* \brief It represents a functional decryption key of the randomized inner-product scheme.
*/
typedef struct ripfe_FH_fe_key {
    ipfe_FH_fe_key fe_key; /**< Functional decryption key of the non-randomized scheme. */
} ripfe_FH_fe_key;

/**
* \struct ripfe_FH_ciphertext ripfe_FH.h "RFE/ripfe_FH.h"
* \brief It represents a ciphertext of the randomized inner-product scheme.
*/
typedef struct ripfe_FH_ciphertext {
    ipfe_FH_ciphertext ct_ipfe; /**< An ipfe_FH_ciphertext. */
	size_t l; /**< The dimension for the scheme. */
} ripfe_FH_ciphertext;

/**
* \fn ripfe_FH_precomp_init(ripfe_FH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y)
* \brief It initializes public parameters of the randomized inner-product scheme for a 
* precomputed pairing friendly elliptic curve. 
*
* \param S A pointer to a ripfe_FH structure.
* \param l The dimension of the vectors for the inner-product scheme.
* \param bound_X The bound on the plaintext inputs.
* \param Q The maximum number of functional queries to be asked.
* \param bound_Y the bound on the function.
*/
int ripfe_FH_precomp_init(ripfe_FH *S, size_t l, mpz_t bound_X, int Q, mpz_t bound_Y);

/**
* \fn void rqfe_FH_free(rqfe_FH *S)
* \brief It clears public parameters of the randomized inner-product scheme and frees allocated memory.
*
* \param S A pointer to a ripfe_FH structure.
*/
void ripfe_FH_free(ripfe_FH *S);

/**
* \fn void ripfe_FH_sec_key_init(ripfe_FH_sec_key *MSK, ripfe_FH *S)
* \brief It initializes a master secret key of the randomized inner-product scheme.
*
* \param MSK A pointer to a ripfe_FH_sec_key structure.
* \param S A pointer to a ripfe_FH structure.
*/
void ripfe_FH_sec_key_init(ripfe_FH_sec_key *MSK, ripfe_FH *S);

/**
* \fn void ripfe_FH_sec_key_free(ripfe_FH_sec_key *MSK)
* \brief It clears a master secret key of the randomized inner.product scheme and frees allocated memory.
*
* \param MSK A pointer to a ripfe_FH_sec_key structure.
*/
void ripfe_FH_sec_key_free(ripfe_FH_sec_key *MSK);

/**
* \fn void ripfe_FH_fe_key_init(ripfe_FH_fe_key *FE_key, ripfe_FH *S)
* \brief It initializes a functional decryption key of the randomized inner-product scheme.
*
* \param FE_key A pointer to a ripfe_FH_fe_key structure.
* \param S A pointer to a ripfe_FH structure
*/
void ripfe_FH_fe_key_init(ripfe_FH_fe_key *FE_key, ripfe_FH *S);

/**
* \fn void ripfe_FH_fe_key_free(ripfe_FH_fe_key *FE_key)
* \brief It clears a functional decryption key of the randomized inner-product scheme and frees 
* allocated memory.
*
* \param FE_key A pointer to a ripfe_FH_fe_key structure.
*/
void ripfe_FH_fe_key_free(ripfe_FH_fe_key *FE_key);

/**
* \fn void ripfe_FH_ciphertext_init(ripfe_FH_ciphertext *c, ripfe_FH *S)
* \brief It initializes a ciphertext of the randomized inner-product scheme.
*
* \param c A pointer to a ripfe_FH_ciphertext structure.
* \param S A pointer to a ripfe_FH structure.
*/
void ripfe_FH_ciphertext_init(ripfe_FH_ciphertext *c, ripfe_FH *S);

/**
* \fn void ripfe_FH_ciphertext_free(ripfe_FH_ciphertext *c)
* \brief It clears a ciphertext of the randomized inner-product scheme and frees allocated memory.
*
* \param c A pointer to a ripfe_FH_ciphertext structure.
*/
void ripfe_FH_ciphertext_free(ripfe_FH_ciphertext *c);

/**
* \fn void ripfe_FH_generate_master_keys(ripfe_FH_sec_key *MSK, double timesSetUp[])
* \brief It generates a master secret key for the randomized inner-product scheme.
*
* \param MSK A pointer to a ripfe_FH_sec_key structure.
* \param timesSetUp An array to store the timings of this protocol.
*/
int ripfe_FH_generate_master_keys(ripfe_FH_sec_key *MSK, double timesSetUp[]);

/**
* \fn int ripfe_FH_encrypt(ripfe_FH_ciphertext *c, ripfe_FH *S, mpz_t *x, ripfe_FH_sec_key *MSK, double timesEnc[])
* \brief It encrypts a message following the randomized inner-product scheme.
*
* \param c A pointer to a ripfe_FH_ciphertext structure.
* \param S A pointer to a ripfe_FH structure.
* \param x An array of multiple precision integers as plaintext message.
* \param MSK A pointer to a ripfe_FH_sec_key structure.
* \param timesEnc An array to store the timings of this protocol.
*/
int ripfe_FH_encrypt(ripfe_FH_ciphertext *c, ripfe_FH *S, mpz_t *x, ripfe_FH_sec_key *MSK, double timesEnc[]);

/**
* \fn int ripfe_FH_derive_fe_key(ripfe_FH_fe_key *FE_key, ripfe_FH *S, ripfe_FH_sec_key *MSK, mpz_t *y, mpz_t e_verification, double timesKeyGen[])
* \brief It derives functional decryption keys following the randomized inner-product scheme.
*
* \param FE_key A pointer to a ripfe_FH_fe_key structure.
* \param S A pointer to a ripfe_FH structure.
* \param MSK A pointer to a ripfe_FH_fe_key structure.
* \param y An array of multiple precision integers as a function.
* \param e_verification A multiple precision integer to store the noise e for verification purposes.
* \param timesKeyGen An array to store the timings of this protocol.
*/
int ripfe_FH_derive_fe_key(ripfe_FH_fe_key *FE_key, ripfe_FH *S, ripfe_FH_sec_key *MSK, mpz_t *y, mpz_t e_verification, double timesKeyGen[]);

/**
* \fn int ripfe_FH_decrypt(mpz_t result, ripfe_FH *S, ripfe_FH_ciphertext *c, ripfe_FH_fe_key *FE_key, double timesDec[])
* \brief It decrypts a ciphertext with a functional decryption key following the randomized inner-product 
* scheme.
*
* \param result A multiple precision integer to store the result.
* \param y An array of multiple precision integers representing the function.
* \param S A pointer to a ripfe_FH structure.
* \param ciphertext A pointer to a ripfe_FH_ciphertext structure.
* \param FE_key A pointer to a rqipfe_fe_key structure.
* \param timesDec An array to store the timings of this protocol.
*/
int ripfe_FH_decrypt(mpz_t *result, mpz_t *y, ripfe_FH *S, ripfe_FH_ciphertext *c, ripfe_FH_fe_key *FE_key, double timesDec[]);