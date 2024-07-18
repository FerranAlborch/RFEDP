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
#include <gmp.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


/**
* \file
* \ingroup utils
* \brief Functions for performing fast modulo operations.
*/


/**
* \fn void mpz_add_mod(mpz_t res, mpz_t a, mpz_t b, mpz_t modulo)
* \brief It adds two multiple precision integers with a modulo.
*
* \param res A multiple precision integer to store the result.
* \param a The first element to add.
* \param b The second element to add.
* \param modulo The modulo.
*/
void mpz_add_mod(mpz_t res, mpz_t a, mpz_t b, mpz_t modulo);


/**
* \fn void mpz_sub_mod(mpz_t res, mpz_t a, mpz_t b, mpz_t modulo)
* \brief It substracts two multiple precision integers with a modulo.
*
* \param res A multiple precision integer to store the result.
* \param a The first element of the substraction.
* \param b The element being substracted.
* \param modulo The modulo.
*/
void mpz_sub_mod(mpz_t res, mpz_t a, mpz_t b, mpz_t modulo);