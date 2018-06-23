#ifndef _PARAMS_H
#define _PARAMS_H

/*
 * Copyright (c) 2018, Henry Corrigan-Gibbs
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef __cplusplus
extern "C"{
#endif

#include <openssl/ec.h>

struct params;

typedef struct params* Params;

typedef enum {
  P256 = 1, 
  P384 = 2, 
  P521 = 3 
} CurveName;

Params Params_new (CurveName c);
void Params_free (Params p);
const EC_GROUP *Params_group (Params p);
const BIGNUM *Params_order (Params p);
BN_CTX *Params_ctx (Params p);

int Params_rand_point (Params p, EC_POINT *point);
int Params_rand_exponent (Params p, BIGNUM *x);

// Compute g^x where g is the fixed generator
int Params_exp (Params p, EC_POINT *point, const BIGNUM *exponent);

int Params_hash_to_exponent (Params p, BIGNUM *exp, 
    const uint8_t *str, int strlen);

#ifdef __cplusplus
}
#endif
#endif
