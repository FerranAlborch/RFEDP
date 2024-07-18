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
* \brief Functions for converting mpz_t elements into mclBnFr elements 
* Conversion functions from array of mpz_t to array of mclBnFr going 
* through hexadecimal representation.
*/


/**
* \fn mpz_to_mclBnFr(mclBnFr *res, mpz_t *a, size_t size)
* \brief It swaps an array of mpz to an array of mclBnFr.
*
* \param res A vector of mclBnFr elements to store the result.
* \param a The  element to swap.
* \param modulo The size of the array.
*/
int mpz_to_mclBnFr(mclBnFr *res, mpz_t *a, size_t size);

/**
* \fn void mpz_add_mod(mpz_t res, mpz_t a, mpz_t b, mpz_t modulo)
* \brief It swaps an array of mpz to an array of mclBnFr.
*
* \param res A vector of mclBnFr elements to store the result.
* \param a The  element to swap.
* \param modulo The size of the array.
*/
void mclBnFr_to_mpz(mpz_t *res, mclBnFr *a, size_t size);