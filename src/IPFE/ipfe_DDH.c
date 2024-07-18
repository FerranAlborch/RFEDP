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
#include <stdint.h>
#include <gmp.h>
#include <time.h>
#include "IPFE/ipfe_DDH.h"
#include "config.h"


bool ipfe_DDH_precomp_init(ipfe_DDH *s, size_t l, mpz_t bound_X, mpz_t bound_Y) {
    
    mpz_t check;
    mpz_inits(s->bound_X, s->bound_Y, s->g, s->p, s->q, s->h, s->phi_p, check, NULL);


    // Set precomputed safe prime p of MODULUS_LEN bits
    if (MODULUS_LEN == 1024) {
        mpz_set_str(s->p, "a1928cf89bfcb7a84a997f4d83c5ef02f8475b6185029f667e141f8af9a2780aa91f007d744a971a70f8d105fe24844d4a944e5eee4a263d2c7edac6b810f216a43043ed2bd7e929d7469719ad6a1bb0f173fbc30ddcd23919a82bffaa333ba512958f554af71030aa033637401c537dac5a76298a62c84e0ef74508b852244f", 16);
    } else if (MODULUS_LEN == 1536) {
        mpz_set_str(s->p, "d3081b4b04a121fcf59796e9dc49940e40d1dc77fef202455368ef1ec9adb28a51eebd869033b87a2a46018570c47019d0528c91a5228ecd94a046861be516c7942ff5db05dc464d3f0163acec2e49a050c93671420b50b39452606c3858cbac5c2b90cc49f99bb17614271bb0dbc995d8c6d2c8257cf72c3ab2345bd33735913db1917ff17b0d91eda9ddac7b1e9822ff120eeac2614b431738733c87260efdad8017cc17975d739bd081031dbff9bf535138f790a589aaeb3b4571064d9047", 16);
    } else if (MODULUS_LEN == 2048) {
        mpz_set_str(s->p, "9abc567accd577960d906cc4346c71b07e18c121b8586f290ef8f2276b3fa339a9fe1f38afd6dfd857642c9340c0509bd7fbb40e6df3d28cee1796f851018ac71f22237014a9c3b1f697138894aa6dd4a97127fd89b42faa05c84ab47c8a87181f5d24f7b41bcd6f3364800f0c29a0017a2b6efdb5e40e23edc4d6b6bd0f73e9790ced4b008572672c852ac50b2abe9a6bdf8c6822aa5a2772e3433a41f942a2804382cc33bebce5f50cbd25a090f4f2f18d43bc3db443a50c7b8f3373306de124936cf251c23a1dfdeae0f9d0f724812cc5486bf6f117c645aab3283c1a8ee24dbea8ae85217d7c890919299a77a9879ee8ab03191ab0ef46db053a1ff401c7", 16);
    } else if (MODULUS_LEN == 2560) {
        mpz_set_str(s->p, "8251c9670e09215d77529c58cfed31f237b7fa731260471bfe0390dc9c43e7361c6e2ea3aa0d0981486c8d54d071114756656b4caf370b4a5dc2b5aec811d3168f779e3bac9ec415371244c8cf9ec5e3655b2867154e859734d19521a27c4c0e5d5052bba2c3ce8931e8d68d9346c5c886f7cf03cb2f469c2ec707469d8b724ad5eb6b8d96003f835658a9826cb54752a853347f49e896d48fe867d20731f47ad845fc7f1b4227ae5d07bd19e25383baa870c2e5846b5aab37d0570f19d614be14997586e1dccbc27f273cf9b23079632c633fbd5a74fbff8b743bbeb80a7442da0c27bc9da316b4f623def688bf2138482510044be95082130be190fd3b72dcf3a9d20608acf639c3557c9b056548516de08ba086eb55147a9cb8c1e518c24a307b5a7d122f7f52caa9725985eb8f0599cfa6bf2191268b09c443b18923622f", 16);
    } else if (MODULUS_LEN == 3072) {
        mpz_set_str(s->p, "ee17c10678f111833e92ba266c2472ac08166151187afebf67123c41c709568e89e50ba768355ce5c2ccb16a5e391a5af1b32fc16586243173bdc0e8cd1ff82a00d9f659f0aecae3efd9767019a38322e68c05e7f7e64c22633dcdbd457296c24adc7489623b1ba6f4fd19379e6fb234c4d40859494600f84af028cad9916c798e99cd7cd4c762fc89b12823652db150de04b0b07c3cda64407261652dc1ca4a458c5e8af7ce6d49292811bac38666b2c7d791a0735f25b003fb9bf426c17501db86a74a3d55235c48df1350139acf0b924688a45a9d529776c58bc6961ea20d0840b4442eaf40b3a6e8701bfacc44c1abadc3bb22db91db06ef4538551cc391eebe1cc1cb1cf220fd920431a16e65aa50b5dd4665cf67e35a2c26cf1ded5fa0417391903f8f6e3529163b4f9aa47f2943562206bb09321152bc428f9991130148d00d6e68bbbf3d93e1b3f9ad3a27cff4379e13b351900faf6b6360c5ec284286a3f4dff1532a391b164d435e0f804c9a1db0cad7135fdaaa61da47c1b44713", 16);
    } else if (MODULUS_LEN == 4096) {
        mpz_set_str(s->p, "d0c7d2519158f355ed0131e3415135dc0cf6ea5f52c72e21091b7021bbe47c6b51c4209a334245276405ada9a1c12580cd7ccbcbab6b63cde33ad9fb999aa4504c5b0f02f9a01089e4fedf6f3dbf937d16895a964bbe90a3b534c3694ebc4480945d5362743f3de5b59b2f8ccabf9f05875ec2cb3e83a0c373d948cb644f4dbd30cb415004c658d660129ae9e87b6544a1dd0e613c7be0580e115c2a584ec81bd2699dd5d7f8820030f52b221c3cebf100b3ea1230c14ec928a29e0bed4a461aec75aee6a4310049e6a4f6c500d5d40580d9137571fb42d2d64f4ad3110c59cae61e4f4f6f3b0792d47b68dbd9fa881154f95828e66abda7adf09e960201680c364bbf4a3059ae7be57e273c639ffb45eebaf5507e302ffd0c607e612bbcba185cd2088d101f62415a1211173400ff5a4f6300e441128e03ecdeecb4f6aa3a83661a7f20bd139b6bc743021cc0f2ed6404dbde50a9506388717b43e11e8f6dbd24e0d4daedf0f6fcbc40804c79cbf237e7f73bab56f8341a58ee94605f753a49e096007f8fe40db4c82888979f7a9deed2ec149f6e9b9ebb5d5bd8a25e8f75a21c1c545f214062ca0665aa7172b04da18af95f9cab42752045ea55365f6fc5cd691e9ff802c79d5050be607d4e1baf45299d9686e2bcd4f3cdeed1963b86e66f194c76f436220102ca1216b19685fbf2fa58455b33a038502550aadb55bee02f", 16);
    } else {
        mpz_clears(s->bound_X, s->bound_Y, s->g, s->p, s->q, s->h, s->phi_p, check, NULL);
        return false;
    }

    // Set phi_p = p - 1 
    mpz_sub_ui(s->phi_p, s->p, 1);

    // Sample random generators g and h
    // Initialize secure seed
    mpz_t seed;
    mpz_init2(seed, SEED_SIZE * sizeof(uint64_t));
    generate_seed(seed, SEED_SIZE);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed(state, seed);
    mpz_clear(seed);
    // Sample g and h between 2 and p-1
    mpz_t limit;
    mpz_init(limit);
    mpz_sub_ui(limit, s->p, 3);
    mpz_urandomm(s->g, state, limit);
    mpz_add_ui(s->g, s->g, 2);
    mpz_urandomm(s->h, state, limit);
    mpz_add_ui(s->h, s->h, 2);
    mpz_clear(limit);
    gmp_randclear(state);

    // Set q = (p - 1)/2
    mpz_div_ui(s->q, s->phi_p, 2);

    // Check that the maximum possible decrypted value is in bound ( i.e. 2 * l * bound_X * bound_Y < q )
    mpz_mul(check, bound_X, bound_Y);
    mpz_mul_ui(check, check, 2 * l);
    if (mpz_cmp(check, s->q) >= 0) {
        mpz_clears(s->bound_X, s->bound_Y, s->g, s->p, s->q, s->h, s->phi_p, check, NULL);
        return false;
    }
    mpz_clear(check);

    // Set l, bound_X and bound_Y
    s->l = l;
    mpz_set(s->bound_X, bound_X);
    mpz_set(s->bound_Y, bound_Y);

    // Allocate memory for FComb precomputations
    s->F = (FCombInt *) malloc(2 * sizeof(FCombInt));
    FCombInt_alloc(&s->F[0], s->p, s->g, MODULUS_LEN, 12, 2);
    FCombInt_alloc(&s->F[1], s->p, s->h, MODULUS_LEN, 12, 2);

    return true;
}


void ipfe_DDH_free(ipfe_DDH *s) {
    mpz_clears(s->bound_X, s->bound_Y, s->g, s->p, s->q, s->h, s->phi_p, NULL);
    FCombInt_free(&s->F[0]);
    FCombInt_free(&s->F[1]);
    free(s->F);
    return;
}


void ipfe_DDH_sec_key_init(ipfe_DDH_sec_key *msk) {
    mpz_init2(msk->seed_s, SEED_SIZE * sizeof(uint64_t));
    mpz_init2(msk->seed_t, SEED_SIZE * sizeof(uint64_t));
    return;
}


void ipfe_DDH_sec_key_free(ipfe_DDH_sec_key *msk) {
    mpz_clear(msk->seed_s);
    mpz_clear(msk->seed_t);
    return;
}


void ipfe_DDH_fe_key_init(ipfe_DDH_fe_key *fe_key) {
    fe_key->sy_ty = (mpz_t *) malloc(2 * sizeof(mpz_t));
    mpz_inits(fe_key->sy_ty[0], fe_key->sy_ty[1], NULL);
    return;
}


void ipfe_DDH_fe_key_free(ipfe_DDH_fe_key *fe_key) {
    mpz_clears(fe_key->sy_ty[0], fe_key->sy_ty[1], NULL);
    free(fe_key->sy_ty);
    return;
}


void ipfe_DDH_ciphertext_init(ipfe_DDH_ciphertext *c, ipfe_DDH *s) {
    c->l = s->l;
    
    c->C_D = (mpz_t *) malloc(2 * sizeof(mpz_t));
    mpz_inits(c->C_D[0], c->C_D[1], NULL);
    
    c->E = (mpz_t *) malloc(c->l * sizeof(mpz_t));
    for(size_t i = 0; i < c->l; ++i) mpz_init(c->E[i]);
    return;
}


void ipfe_DDH_ciphertext_free(ipfe_DDH_ciphertext *c) {
    mpz_clears(c->C_D[0], c->C_D[1], NULL);
    for(size_t i = 0; i < c->l; ++i) mpz_clear(c->E[i]);
    free(c->C_D);
    free(c->E);
    return;
}


void ipfe_DDH_generate_master_keys(ipfe_DDH_sec_key *msk, ipfe_DDH *s, double timesSetUp[]) {
    // Sample the seeds
    clock_t begin = clock();
    generate_seed(msk->seed_s, SEED_SIZE);
    generate_seed(msk->seed_t, SEED_SIZE);
    clock_t end = clock();
    timesSetUp[0] = timesSetUp[0] + ((double )(end - begin) / CLOCKS_PER_SEC) / 2;

    // Do the precomputations for g and h
    begin = clock();
    FCombInt_init(&s->F[0]);
    FCombInt_init(&s->F[1]);
    end = clock();
    timesSetUp[1] = timesSetUp[1] + ((double)(end - begin) / CLOCKS_PER_SEC) / 2;

    return;
}


bool ipfe_DDH_encrypt(ipfe_DDH_ciphertext *ciphertext, ipfe_DDH *s, mpz_t *x, ipfe_DDH_sec_key *msk, double timesEnc[]) {
    // Initialize secure seed for r and sample
    mpz_t seed;
    mpz_init2(seed, SEED_SIZE * sizeof(uint64_t));
    generate_seed(seed, SEED_SIZE);
    gmp_randstate_t state_r;
    gmp_randinit_default(state_r);
    gmp_randseed(state_r, seed);
    mpz_clear(seed);

    mpz_t r;
    mpz_inits(r, NULL);
    mpz_urandomm(r, state_r, s->phi_p);
    mpz_add_ui(r, r, 1);

    clock_t begin = clock();
    FComb_multiMult(ciphertext->C_D[0], &s->F[0], &r, 1);
    FComb_multiMult(ciphertext->C_D[1], &s->F[1], &r, 1);
    clock_t end = clock();
    timesEnc[0] = timesEnc[0] + ((double)(end - begin) / CLOCKS_PER_SEC) / 2;

    begin = clock();
    // Sample s and t
    gmp_randstate_t state_s;
    gmp_randinit_default(state_s);
    gmp_randseed(state_s, msk->seed_s);
    mpz_t *s_key = (mpz_t *) malloc(s->l * sizeof(mpz_t));
    gmp_randstate_t state_t;
    gmp_randinit_default(state_t);
    gmp_randseed(state_t, msk->seed_t);
    mpz_t *t = (mpz_t *) malloc(s->l * sizeof(mpz_t));
    for(size_t i = 0; i < s->l; ++i) {
        mpz_inits(s_key[i], t[i], NULL);
        mpz_urandomm(s_key[i], state_s, s->phi_p);
        mpz_urandomm(t[i], state_t, s->phi_p);
        mpz_add_ui(s_key[i], s_key[i], 1);
        mpz_add_ui(t[i], t[i], 1);
    }
    gmp_randclear(state_s);
    gmp_randclear(state_t);
    gmp_randclear(state_r);


    size_t end_for = s->l;
    mpz_t *exponents = (mpz_t *) malloc(sizeof(mpz_t) * 2);
    mpz_inits(exponents[0], exponents[1], NULL);

    // TODO parallelization
    // #pragma omp parallel for schedule(static, 100)
    for (size_t i = 0; i < end_for; i++) {
        mpz_mul(exponents[0], s_key[i], r);
        // mpz_mod(exponents[0], exponents[0], s->phi_p);
        mpz_add(exponents[0], exponents[0], x[i]);
        mpz_mod(exponents[0], exponents[0], s->phi_p);

        mpz_mul(exponents[1], t[i], r);
        mpz_mod(exponents[1], exponents[1], s->phi_p);

        FComb_multiMult(ciphertext->E[i], s->F, exponents, 2);
        // printf("Iteration %d\n", i);
    }
    end = clock();
    timesEnc[1] = timesEnc[1] + ((double)(end - begin) / CLOCKS_PER_SEC);

    for(size_t i = 0; i < s->l; ++i) mpz_clears(s_key[i], t[i], NULL);
    free(s_key);
    free(t);

    mpz_clears(exponents[0], exponents[1], NULL);
    free(exponents);
    
    mpz_clears(r, NULL);
    return true;
}


bool ipfe_DDH_derive_fe_key(ipfe_DDH_fe_key *fe_key, ipfe_DDH *s, ipfe_DDH_sec_key *msk, mpz_t *y, double timesKeyGen[]) {
    // Verifiy decryption vector is in bound
    bool check = true;
    for(size_t i = 0; i < s->l; ++i) {
        if(mpz_cmp(y[i], s->bound_Y) > 0) {
            check = false;
        }
        if(!check) break;
    }
    if(!check) return false;

    mpz_t aux;
    mpz_init(aux);

    // Sample s and t
    gmp_randstate_t state_s;
    gmp_randinit_default(state_s);
    gmp_randseed(state_s, msk->seed_s);
    mpz_t *s_key = (mpz_t *) malloc(s->l * sizeof(mpz_t));
    gmp_randstate_t state_t;
    gmp_randinit_default(state_t);
    gmp_randseed(state_t, msk->seed_t);
    mpz_t *t = (mpz_t *) malloc(s->l * sizeof(mpz_t));
    for(size_t i = 0; i < s->l; ++i) {
        mpz_inits(s_key[i], t[i], NULL);
        mpz_urandomm(s_key[i], state_s, s->phi_p);
        mpz_urandomm(t[i], state_t, s->phi_p);
        mpz_add_ui(s_key[i], s_key[i], 1);
        mpz_add_ui(t[i], t[i], 1);
    }
    gmp_randclear(state_s);
    gmp_randclear(state_t);

    clock_t begin = clock();
    mpz_set_ui(fe_key->sy_ty[0], 0);
    mpz_set_ui(fe_key->sy_ty[1], 0);
    for(size_t i = 0; i < s->l; ++i) {
        mpz_mul(aux, y[i], s_key[i]);
        // mpz_mod(aux, aux, s->phi_p);
        mpz_add(fe_key->sy_ty[0], fe_key->sy_ty[0], aux);
        mpz_mod(fe_key->sy_ty[0], fe_key->sy_ty[0], s->phi_p);

        mpz_mul(aux, y[i], t[i]);
        // mpz_mod(aux, aux, s->phi_p);
        mpz_add(fe_key->sy_ty[1], fe_key->sy_ty[1], aux);
        mpz_mod(fe_key->sy_ty[1], fe_key->sy_ty[1], s->phi_p);
    }
    clock_t end = clock();
    timesKeyGen[2] = timesKeyGen[2] + ((double)(end - begin) / CLOCKS_PER_SEC) / 2;

    for(size_t i = 0; i < s->l; ++i) mpz_clears(s_key[i], t[i], NULL);
    free(s_key);
    free(t);

    mpz_clear(aux);

    return true;
}


bool ipfe_DDH_decrypt_exp(mpz_t r, ipfe_DDH *s, ipfe_DDH_ciphertext *ciphertext, ipfe_DDH_fe_key *fe_key, mpz_t *y, double timesDec[]) {
    // Verifiy decryption vector is in bound
    bool check = true;
    for(size_t i = 0; i < s->l; ++i) {
        if(mpz_cmp(y[i], s->bound_Y) > 0) {
            check = false;
        }
        if(!check) break;
    }
    if(!check) return false;

    mpz_t num, denom, denom_inv;
    mpz_inits(num, denom, denom_inv,NULL);

    // Compute numerator with multi-exponentiation
    clock_t begin = clock();
    multiple_exponentiation(num, s->l, ciphertext->E, y, s->p);
    clock_t end = clock();
    timesDec[0] = timesDec[0] + ((double)(end - begin) / CLOCKS_PER_SEC);


    // Compute denominator with multi-exponentiation
    begin = clock();
    multiple_exponentiation(denom, 2, ciphertext->C_D, fe_key->sy_ty, s->p);
    end = clock();
    timesDec[1] = timesDec[1] + ((double)(end - begin) / CLOCKS_PER_SEC);


    //int verification = mpz_cmp(denom, denom2);
    //printf("Output 0 if the denominator is well computed: %d\n", verification);

    begin = clock();
    mpz_invert(denom_inv, denom, s->p);
    mpz_mul(r, denom_inv, num);
    mpz_mod(r, r, s->p);
    end = clock();
    timesDec[2] = timesDec[2] + ((double)(end - begin) / CLOCKS_PER_SEC);

    mpz_clears(num, denom, denom_inv, NULL);
    return true;
}

