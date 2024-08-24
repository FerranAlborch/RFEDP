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
#include <stdlib.h>
#include <stdbool.h>


/**
* \file
* \ingroup utils
* \brief Functions for sampling the different random variables needed.
*/


/**
* \fn void geometric_search(mpz_t e, double p)
* \brief It samples a one-sided geometric with parameter p >= 1/3.
*
* \param e A multiple precision integer to store the result.
* \param p The parameter p.
*/
void geometric_search(mpz_t e, double p);


/**
* \fn void geometric_inversion(mpz_t e, double p)
* \brief It samples a one-sided geometric with parameter p < 1/3.
*
* \param e A multiple precision integer to store the result.
* \param p The parameter p.
*/
void geometric_inversion(mpz_t e, double p);


/**
* \fn void sample_one_sided_geometric(mpz_t e, double p)
* \brief It samples a one-sided geometric with any parameter p.
*
* \param e A multiple precision integer to store the result.
* \param p The parameter p.
*/
void sample_one_sided_geometric(mpz_t e, double p);


/**
* \fn void sample_geometric_IP(mpz_t e, double epsilon, mpz_t bound, int Q)
* \brief It samples a two-sided geometric with the parameter for inner-product:
* p = exp(-epsilon / (Q * bound_Y) ).
*
* \param e A multiple precision integer to store the result.
* \param epsilon The privacy budget for differential privacy.
* \param bound The bound for the linear functions to evaluate.
* \param Q The number of functional key queries supported.
*/
void sample_geometric_IP(mpz_t e, double epsilon, mpz_t bound, int Q);

/**
* \fn void sample_geometric(mpz_t e, double epsilon, mpz_t bound, int Q)
* \brief It samples a two-sided geometric with the parameter for quadratic:
* p = exp(-epsilon / (2 * Q * l * bound_X * bound_F) ).
*
* \param e A multiple precision integer to store the result.
* \param epsilon The privacy budget for differential privacy.
* \param bound_X The bound for the database values to evaluate.
* \param bound_X The bound for the function to evaluate.
* \param Q The number of functional key queries supported.
* \param Q The size of the database.
*/
void sample_geometric_Q(mpz_t e, double epsilon, mpz_t bound_X, mpz_t bound_F, int Q, size_t l);


/**
* \fn void generate_seed(mpz_t result, size_t seed_size)
* \brief It generates a a secure multiple precision integer seed for random number 
* generation of size seed_size * 64.
*
* \param result A multiple precision integer to store the result.
* \param seed_size Number of bytes in the generated seed.
*/
void generate_seed(mpz_t result, size_t seed_size);