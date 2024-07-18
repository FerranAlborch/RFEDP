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
#include "utils/PG.h"

int PG_init(PG *PG) {
	// Initialize the curve
	int verify = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (verify != 0) return 1;

	// Set the prime order r
	mpz_init(PG->r);
	mpz_set_str(PG->r, "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

	// Set the generators P1, P2 as in zkcrypto
	const char *g1Str = "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
	mclBnG1_setStr(&PG->P1, g1Str, strlen(g1Str), 16);
	const char *g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
	mclBnG2_setStr(&PG->P2, g2Str, strlen(g2Str), 16);

	// Compute the generator gT as e(P1,P2)
	mclBn_pairing(&PG->gT, &PG->P1, &PG->P2);
	return verify;
}

void PG_free(PG *PG) {
	mpz_clear(PG->r);
	mclBnG1_clear(&PG->P1);
	mclBnG2_clear(&PG->P2);
	mclBnGT_clear(&PG->gT);
	return;
}

