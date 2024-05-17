/*
* Software Name : RFEDP
* Version: 1.0
* SPDX-FileCopyrightText: Copyright (c) 2024[-2024] Orange Innovation
*
* This software is confidential and proprietary information of Orange Innovation.
* You shall not disclose such Confidential Information and shall not copy, use or distribute it
* in whole or in part without the prior written consent of Orange Innovation
*
* Author: Ferran Alborch Escobar
*/

#include <stdio.h>
#include <gmp.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include "utils/rand.h"



void geometric_search(mpz_t e, double p) {
    
    double r, sum, prod, q;

    mpz_set_ui(e, 1);
    sum = prod = p;
    q = 1.0 - p;
    r = (double) rand()/ (double) RAND_MAX;

    while(r > sum) {
        prod = prod * q;
        sum = sum + prod;
        mpz_add_ui(e ,e, 1);
    }

    return;
}


void geometric_inversion(mpz_t e, double p) {

    double r = (double) rand()/ (double) RAND_MAX;
    long sample = (long)ceil(log(1.0-r)/log(1.0-p));
    mpz_set_ui(e, sample);

    return;
}


void sample_one_sided_geometric(mpz_t e, double p) {

    // Two different algorithms depending on how big p is
    if (p >= 0.333333333333333333333333) geometric_search(e, p);
    else geometric_inversion(e, p);
    return;
}



void sample_geometric(mpz_t e, double epsilon, mpz_t bound_Y, int Q) {
    
    // Compute value p = exp(-epsilon/(Q*bound_Y))
    mpz_t denom;
    mpf_t p_mpf, denom_mpf; 
    mpz_init(denom);
    mpf_inits(p_mpf, denom_mpf, NULL);
    mpz_mul_ui(denom, bound_Y, Q);
    mpf_set_d(p_mpf, (double)(-1.0*epsilon));
    mpf_set_z(denom_mpf, denom);
    mpf_div(p_mpf, p_mpf, denom_mpf);
    double p = mpf_get_d(p_mpf);
    p = exp(p);
    //printf("The parameter p for the geometric is %.12f\n", p);
    
    mpz_clear(denom);
    mpf_clears(p_mpf, denom_mpf, NULL);

    
    // Compute two one-sided geometrics and substract them
    mpz_t e1, e2;
    mpz_inits(e1, e2, NULL);
    sample_one_sided_geometric(e1, 1-p);
    //gmp_printf("First sample of the one-sided geometric distribution %Zd\n", e1);
    sample_one_sided_geometric(e2, 1-p);
    //gmp_printf("Second sample of the one-sided geometric distribution %Zd\n", e2);
    mpz_sub(e, e1, e2);
    //gmp_printf("Sample of the two-sided geometric distribution %Zd\n", e);


    mpz_clears(e1, e2, NULL);

    return;
}


void generate_seed(mpz_t result, size_t seed_size) {
    // Generate secure seed of size seed_size * 64
    int fd = open("/dev/urandom", O_RDONLY);
    uint64_t* rand_number = (uint64_t*) malloc(seed_size * sizeof(uint64_t));
    read(fd, rand_number, sizeof(seed_size * sizeof(uint64_t)));
    close(fd);  

    // Set seed into mpz_t
    mpz_import(result, seed_size, 1, sizeof(uint64_t), 0, 0, rand_number);

    free(rand_number);
}
