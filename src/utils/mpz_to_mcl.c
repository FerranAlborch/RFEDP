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
#include "utils/mpz_to_mcl.h"

int mpz_to_mclBnFr(mclBnFr *res, mpz_t *a, size_t size) {
	char *buff;
	buff = (char *) malloc(1600 * sizeof(char));
	for(size_t i = 0; i < size; ++i) {
		mpz_get_str(buff, 16, a[i]);
		int verify = mclBnFr_setStr(&res[i], buff, strlen(buff), 16);
		if(verify != 0) return 1;
	}
	free(buff);
	return 0;
}

void mclBnFr_to_mpz(mpz_t *res, mclBnFr *a, size_t size) {
	for(size_t i = 0; i < size; ++i) {
		char buf[1600];
		mclBnFr_getStr(buf, sizeof(buf), &a[i], 16);
		mpz_set_str(res[i], buf, 16);
	}
	return;
}