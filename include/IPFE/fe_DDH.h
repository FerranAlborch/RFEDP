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
#include "utils/FComb.h"
#include "utils/multi_expo.h"
#include "utils/rand.h"
#include "utils/wNAF.h"

/**
* \file
* \ingroup IPFE
* \brief This is a secret-key adaptation of the DDH-based scheme in Section 3 from the paper "Adaptive 
* Simulation Security for Inner Product Functional Encryption" by Agrawal, Libert, Maitra and 
* Titiu, as explained in Appendix I from "Computational Differential Privacy for Encrypted Databases 
* Supporting Linear Queries" by Alborch Escobar, Canard, Laguillaumie and Phan
*/


/**
* \struct fe_DDH fe_DDH.h "IPFE/fe_DDH.h"
* \brief It represents the public parameters of the inner-product scheme. 
*/
typedef struct fe_DDH {
    size_t l; /**< Dimension of the input vector and function. */
    mpz_t bound_X; /**< Bound for the input plaintexts. */
    mpz_t bound_Y; /**< Bound for the functions. */
    mpz_t g; /**< Generator g of the group. */
    mpz_t h; /**< Generator h of the group (different from g). */
    FCombInt *F; /**< Precomputations for the fixed-comb method for fast exponentiation. */
    mpz_t p; /**< Prime order of the group (safe prime). */
    mpz_t phi_p; /**< Number of non-zero elements in the group. */
    mpz_t q; /**< Prime (p-1)/2 (since p is a safe prime). */
} fe_DDH;

/**
* \struct fe_DDH_sec_key fe_DDH.h "IPFE/fe_DDH.h"
* \brief It represents a master secret key of the inner-product scheme.
*/
typedef struct fe_DDH_sec_key {
    mpz_t seed_s; /**< Seed for s in the master secret key. */
    mpz_t seed_t; /**< Seed for t in the master secret key. */
} fe_DDH_sec_key;

/**
* \struct fe_DDH_fe_key fe_DDH.h "IPFE/fe_DDH.h"
* \brief It represents a functional decryption key of the inner-product scheme.
*/
typedef struct fe_DDH_fe_key {
    mpz_t *sy_ty; /**< An array containing <s,y> and <t,y>. */
} fe_DDH_fe_key;

/**
* \struct fe_DDH_ciphertext fe_DDH.h "IPFE/fe_DDH.h"
* \brief It represents a ciphertext of the inner-product scheme.
*/
typedef struct fe_DDH_ciphertext {
    mpz_t *C_D; /**< Array containing C and D. */
    mpz_t *E; /**< Array containing E. */
    size_t l; /**< Size of the array E. */
} fe_DDH_ciphertext;

/**
* \fn bool fe_DDH_precomp_init(fe_DDH *s, size_t l, mpz_t bound_X, mpz_t bound_Y)
* \brief It initializes public parameters of the inner-product scheme for a precomputed set 
* of safe prime values. 
*
* \param s A pointer to a fe_DDH structure.
* \param l The dimension of the vectors for the inner-product scheme.
* \param bound_X The bound on the plaintext inputs.
* \param bound_Y the bound on the function.
*/
bool fe_DDH_precomp_init(fe_DDH *s, size_t l, mpz_t bound_X, mpz_t bound_Y);

/**
* \fn void fe_DDH_free(fe_DDH *s)
* \brief It clears public parameters of the inner-product scheme and frees allocated memory.
*
* \param s A pointer to a fe_DDH structure.
*/
void fe_DDH_free(fe_DDH *s);

/**
* \fn void fe_DDH_sec_key_init(fe_DDH_sec_key *msk)
* \brief It initializes a master secret key of the inner-product scheme.
*
* \param msk A pointer to a fe_DDH_sec_key structure.
*/
void fe_DDH_sec_key_init(fe_DDH_sec_key *msk);

/**
* \fn void fe_DDH_sec_key_free(fe_DDH_sec_key *msk)
* \brief It clears a master secret key of the inner-product scheme and frees allocated memory.
*
* \param msk A pointer to a fe_DDH_sec_key structure.
*/
void fe_DDH_sec_key_free(fe_DDH_sec_key *msk);

/**
* \fn void fe_DDH_fe_key_init(fe_DDH_fe_key *fe_key)
* \brief It initializes a functional decryption key of the inner-product scheme.
*
* \param fe_key A pointer to a fe_DDH_fe_key structure.
*/
void fe_DDH_fe_key_init(fe_DDH_fe_key *fe_key);

/**
* \fn void fe_DDH_fe_key_free(fe_DDH_fe_key *fe_key)
* \brief It clears a functional decryption key of the inner-product scheme and frees 
* allocated memory.
*
* \param fe_key A pointer to a fe_DDH_fe_key structure.
*/
void fe_DDH_fe_key_free(fe_DDH_fe_key *fe_key);

/**
* \fn void fe_DDH_ciphertext_init(fe_DDH_ciphertext *c, fe_DDH *s)
* \brief It initializes a ciphertext of the inner-product scheme.
*
* \param c A pointer to a fe_DDH_ciphertext structure.
* \param s A pointer to a fe_DDH structure.
*/
void fe_DDH_ciphertext_init(fe_DDH_ciphertext *c, fe_DDH *s);

/**
* \fn void fe_DDH_ciphertext_free(fe_DDH_ciphertext *c)
* \brief It clears a ciphertext of the inner-product scheme and frees allocated memory.
*
* \param c A pointer to a fe_DDH_ciphertext structure.
*/
void fe_DDH_ciphertext_free(fe_DDH_ciphertext *c);

/**
* \fn void fe_DDH_generate_master_keys(fe_DDH_sec_key *msk, fe_DDH *s, double timesSetUp[])
* \brief It generates a master secret key for the inner-product scheme.
*
* \param msk A pointer to a fe_DDH_sec_key structure.
* \param s A pointer to a fe_DDH structure.
* \param timesSetUp An array to store the timings of this protocol.
*/
void fe_DDH_generate_master_keys(fe_DDH_sec_key *msk, fe_DDH *s, double timesSetUp[]);

/**
* \fn bool fe_DDH_encrypt(fe_DDH_ciphertext *ciphertext, fe_DDH *s, mpz_t *x, fe_DDH_sec_key *msk, double timesEnc[])
* \brief It encrypts a message following the inner-product scheme.
*
* \param ciphertext A pointer to a fe_DDH_ciphertext structure.
* \param s A pointer to a fe_DDH structure.
* \param x An array of multiple precision integers as plaintext message.
* \param msk A pointer to a fe_DDH_sec_key structure.
* \param timesEnc An array to store the timings of this protocol.
*/
bool fe_DDH_encrypt(fe_DDH_ciphertext *ciphertext, fe_DDH *s, mpz_t *x, fe_DDH_sec_key *msk, double timesEnc[]);

/**
* \fn bool fe_DDH_derive_fe_key(fe_DDH_fe_key *fe_key, fe_DDH *s, fe_DDH_sec_key *msk, mpz_t *y, double timesKeyGen[])
* \brief It derives functional decryption keys following the inner-product scheme.
*
* \param fe_key A pointer to a fe_DDH_fe_key structure.
* \param s A pointer to a fe_DDH structure.
* \param msk A pointer to a fe_DDH_fe_key structure.
* \param y An array of multiple precision integers as a function.
* \param timesKeyGen An array to store the timings of this protocol.
*/
bool fe_DDH_derive_fe_key(fe_DDH_fe_key *fe_key, fe_DDH *s, fe_DDH_sec_key *msk, mpz_t *y, double timesKeyGen[]);

/**
* \fn bool fe_DDH_decrypt_exp(mpz_t r, fe_DDH *s, fe_DDH_ciphertext *ciphertext, fe_DDH_fe_key *fe_key, mpz_t *y, double timesDec[])
* \brief It decrypts a ciphertext with a functional decryption key following the inner-product 
* scheme returning the value in the exponent.
*
* \param r A multiple precision integer to store the result.
* \param s A pointer to a fe_DDH structure.
* \param ciphertext A pointer to a fe_DDH_ciphertext structure.
* \param fe_key A pointer to a fe_key structure.
* \param y A pointer to a function array.
* \param timesDec An array to store the timings of this protocol.
*/
bool fe_DDH_decrypt_exp(mpz_t r, fe_DDH *s, fe_DDH_ciphertext *ciphertext, fe_DDH_fe_key *fe_key, mpz_t *y, double timesDec[]);