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

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common.h"
#include "params.h"
#include "vrf.h"

#define NID_P256 714
#define NID_P384 715
#define NID_P521 716

struct params {
  EC_GROUP *group;
  BIGNUM *order;
  BN_CTX *ctx;
};

static int
curve_name_to_nid (CurveName c) 
{
  switch (c) {
    case P256:
      return NID_P256;
    case P384:
      return NID_P384;
    case P521:
      return NID_P521;
  }
  return 0;
}

Params 
Params_new (CurveName c)
{
  Params p = NULL;

  int nid = curve_name_to_nid (c);
  if (!nid)
    return NULL;

  p = (Params) malloc (sizeof *p);
  if (!p)
    return NULL;

  p->group = NULL;
  p->order = NULL;
  p->ctx = NULL;
  p->group = EC_GROUP_new_by_curve_name (nid);
  if (!p->group) {
    Params_free (p);
    return NULL;
  }

  p->order = BN_new();
  if (!p->group) {
    Params_free (p);
    return NULL;
  }

  if (!EC_GROUP_get_order (p->group, p->order, NULL)) {
    Params_free (p);
    return NULL;
  }

  if (!(p->ctx = BN_CTX_new ())) {
    Params_free (p);
    return NULL;
  }

  // Precompute powers of g for faster multiplication
  if (!EC_GROUP_precompute_mult (p->group, p->ctx)) {
    Params_free (p);
    return NULL;
  }


  return p;
}

EC_POINT *
Params_point_new (const_Params p)
{
  return EC_POINT_new (p->group);
}


void 
Params_free (Params p)
{
  if (p->group) 
    EC_GROUP_clear_free (p->group);
  if (p->order) 
    BN_free (p->order);
  if (p->ctx) 
    BN_CTX_free (p->ctx);

  free (p);
}

const EC_GROUP *
Params_group (const_Params p) 
{
  return p->group;
}

const EC_POINT *
Params_gen (const_Params p)
{
  return EC_GROUP_get0_generator (p->group);
}

const BIGNUM *
Params_order (const_Params p) 
{
  return p->order;
}

BN_CTX *
Params_ctx (const_Params p) 
{
  return p->ctx;
}

int 
Params_rand_point (const_Params p, EC_POINT *point)
{
  int rv = ERROR;
  BIGNUM *exp = NULL;
  exp = BN_new ();

  CHECK_C ((exp != NULL));
  CHECK_C (Params_rand_point_exp (p, point, exp));

cleanup:
  BN_clear_free (exp);
  return rv;
}

int 
Params_mul (const_Params p, EC_POINT *res, const EC_POINT *g, const EC_POINT *h)
{
  return EC_POINT_add (p->group, res, g, h, p->ctx); 
}

int 
Params_rand_point_exp (const_Params p, EC_POINT *point, BIGNUM *x)
{
  int rv = ERROR;
  CHECK_C (Params_rand_exponent (p, x));
  CHECK_C (Params_exp (p, point, x));

cleanup:
  return rv;
}

int 
Params_exp_base (const_Params p, EC_POINT *point, 
    const EC_POINT *base, const BIGNUM *exponent)
{
  return EC_POINT_mul (p->group, point, NULL, base, exponent, p->ctx);
}

int 
Params_exp_base2 (const_Params p, EC_POINT *point, 
    const EC_POINT *base1, const BIGNUM *e1,
    const EC_POINT *base2, const BIGNUM *e2)
{
  const EC_POINT *points[2] = {base1, base2};
  const BIGNUM *exps[2] = {e1, e2};

  return EC_POINTs_mul(p->group, point, NULL, 2, points, exps , p->ctx);
}

int 
Params_rand_exponent (const_Params p, BIGNUM *x)
{
  // TODO: Generate a uniform number in the range [0, q).
  int bits = BN_num_bits (p->order);
  return BN_rand (x, bits, 0, 0) ? OKAY : ERROR;
}

int 
Params_exp (const_Params p, EC_POINT *point, const BIGNUM *exp)
{
  return EC_POINT_mul (p->group, point, exp, NULL, NULL, p->ctx); 
}

/*
 * Use SHA-256 to hash the string in `bytes_in`
 * with the integer given in `counter`.
 */
static int
hash_once (EVP_MD_CTX *mdctx, uint8_t *bytes_out, 
    const uint8_t *bytes_in, int inlen, uint16_t counter) 
{
  int rv = ERROR;
  CHECK_C (EVP_DigestInit_ex (mdctx, EVP_sha256 (), NULL));
  CHECK_C (EVP_DigestUpdate (mdctx, &counter, sizeof counter));
  CHECK_C (EVP_DigestUpdate (mdctx, bytes_in, inlen));
  CHECK_C (EVP_DigestFinal_ex (mdctx, bytes_out, NULL));

cleanup:
  return rv;
}

/*
 * Output a string of pseudorandom bytes by hashing a 
 * counter with the bytestring provided:
 *    Hash(0|bytes_in) | Hash(1|bytes_in) | ... 
 */
int
hash_to_bytes (uint8_t *bytes_out, int outlen,
    const uint8_t *bytes_in, int inlen)
{
  int rv = ERROR;
  uint16_t counter = 0;
  uint8_t buf[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx = NULL; 
  int bytes_filled = 0;

  CHECK_A (mdctx = EVP_MD_CTX_create());

  do {
    const int to_copy = min (SHA256_DIGEST_LENGTH, outlen - bytes_filled);
    CHECK_C (hash_once (mdctx, buf, bytes_in, inlen, counter));
    memcpy (bytes_out + bytes_filled, buf, to_copy);
    
    counter++;
    bytes_filled += SHA256_DIGEST_LENGTH;
  } while (bytes_filled < outlen);

cleanup:

  if (mdctx) EVP_MD_CTX_destroy (mdctx);
  return rv;
}

int 
Params_hash_to_exponent (const_Params p, BIGNUM *exp, 
    const uint8_t *str, int strlen)
{
  int rv = ERROR;

  int nbytes = BN_num_bytes (p->order);
  uint8_t bytes_out[nbytes];
  
  CHECK_C (hash_to_bytes (bytes_out, nbytes, str, strlen));
  CHECK_A (BN_bin2bn (bytes_out, SHA256_DIGEST_LENGTH, exp));
  CHECK_C (BN_mod (exp, exp, p->order, p->ctx));

cleanup:
  return rv;
}

