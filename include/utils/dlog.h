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

#include <gmp.h>
#include <mcl/bn_c384_256.h>
#include <string>
#include "utils/PG.h"

/**
* \file
* \ingroup utils
* \brief Function for computing discrete logarithm using the baby giant steps algorithm, in a 
* C version.
*/


/**
* \fn int baby_giant_2(mpz_t res, mpz_t h, mpz_t g, mpz_t p, mpz_t bound)
* \brief It computes the discrete logarithm modulo p.
*
* \param res A multiple precision integer to store the result.
* \param h The value from which the discrete logarithm is computed.
* \param g The base over which the discrete logarithm is computed.
* \param p The modulo over which the discrete logarithm is computed.
* \param bound A bound on the result of the discrete logarithm.
*/
int baby_giant_2(mpz_t res, mpz_t h, mpz_t g, mpz_t p, mpz_t bound);


/**
* \fn int baby_giant_mcl(mclBnFr res, mclBnGT h, mclBnGT gT, PG pg, mclBnFr bound)
* \brief It computes the discrete logarithm in GT.
*
* \param res A mclBnFr element to store the result.
* \param h The value from which the discrete logarithm is computed.
* \param gT The base over which the discrete logarithm is computed.
* \param pg The representation of the pairing groups.
* \param bound A bound on the result of the discrete logarithm.
*/
int baby_giant_mcl(mclBnFr res, mclBnGT h, mclBnGT gT, PG pg, mclBnFr bound);