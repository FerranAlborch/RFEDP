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

#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <mcl/bn_c384_256.h>


/**
* \file
* \ingroup utils
* \brief Functions for pairing groups
* Initializin and freeing a pairing group from a predetermined elliptic curve,
* namely BLS12-381.
*/

/**
* \struct PG PG.h "utils/PG.h"
* \brief It represents the pairing groups.
*/
typedef struct PG {
    mpz_t r; /**< Prime order of the groups G1, G2 and GT. */
    mclBnG1 P1; /**< Generator of additive group G1. */
	mclBnG2 P2; /**< Generator of additive group G2. */
	mclBnGT gT; /**< Generator of multiplicative group GT. */
} PG;

/**
* \fn int PG_init(PG *PG)
* \brief It initializes the pairing groups using the elliptic curve BLS12-381 using the same
* the same generators as zkcrypto
*
* \param PG A pointer to a PG structure.
*/
int PG_init(PG *PG);

/**
* \fn void PG_free(PG *PG)
* \brief It clears the pairing groups and frees allocated memory.
*
* \param PG A pointer to a PG structure.
*/
void PG_free(PG *PG);