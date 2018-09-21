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

#define NID_P256 714
#define NID_P384 715
#define NID_P521 716
#define NID_X9_62_prime256v1 415

struct params {
  EC_GROUP *group;
  BIGNUM *order;
  BIGNUM *base_prime;
  BN_CTX *ctx;

  EC_POINT *g;
  EC_POINT *h;
};

static int
curve_name_to_nid (CurveName c) 
{
  switch (c) {
    case P256:
      return NID_X9_62_prime256v1;
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
  int rv = ERROR; 
  Params p = NULL;

  int nid = curve_name_to_nid (c);
  if (!nid)
    return NULL;

  p = (Params) malloc (sizeof *p);
  if (!p)
    return NULL;

  p->group = NULL;
  p->order = NULL;
  p->base_prime = NULL;
  p->ctx = NULL;

  CHECK_A (p->ctx = BN_CTX_new ());
  CHECK_A (p->group = EC_GROUP_new_by_curve_name (nid));

  CHECK_A (p->order = BN_new());
  CHECK_C (EC_GROUP_get_order (p->group, p->order, NULL));

  CHECK_A (p->base_prime = BN_new());
  CHECK_C (EC_GROUP_get_curve_GFp (p->group, p->base_prime, NULL, NULL, p->ctx));

  // Precompute powers of g for faster multiplication
  CHECK_C (EC_GROUP_precompute_mult (p->group, p->ctx));
  const EC_POINT *gen = EC_GROUP_get0_generator(p->group);
  if (!gen) {
    Params_free (p);
    return NULL;
  }

  CHECK_A (p->g = EC_POINT_dup(gen, p->group));
  CHECK_A (p->h = EC_POINT_new(p->group));

  // Pick some random constant point for h value.
  BIGNUM *tmp = BN_new();
  if (!tmp) {
    Params_free (p);
    return NULL;
  }
  BN_one(tmp);
  BN_add_word(tmp, 5);

  do {
    BN_add_word(tmp, 1);
  } while (!(EC_POINT_set_compressed_coordinates_GFp(p->group, p->h, tmp, 1, p->ctx) &&
             EC_POINT_is_on_curve(p->group, p->h, p->ctx)));
  BN_clear_free(tmp);

cleanup:
  if (rv != OKAY) {
    Params_free(p);
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

const EC_POINT *
Params_g (const_Params p)
{
  return p->g;
}

const EC_POINT *
Params_h (const_Params p)
{
  return p->h;
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

// g/h
int
Params_div (const_Params p, EC_POINT *res, const EC_POINT *g, const EC_POINT *h)
{
  int rv = ERROR;
  BIGNUM *t1 = NULL;
  EC_POINT *t2 = NULL;

  CHECK_A (t1 = BN_new());
  CHECK_A (t2 = Params_point_new(p));

  CHECK_C (BN_zero(t1));
  CHECK_C (BN_sub_word(t1, 1));
  // t2 = h^-1
  CHECK_C (Params_exp_base(p, t2, h, t1));
  // res = g / h
  CHECK_C (Params_mul(p, res, g, t2));

cleanup:
  if (t1) BN_clear_free(t1);
  if (t2) EC_POINT_clear_free(t2);
  return rv;
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
Params_exp_base_g (const_Params p, EC_POINT *point,
    const BIGNUM *exp) {
  return EC_POINT_mul (p->group, point, NULL, p->g, exp, p->ctx);
}

int
Params_exp_base_h (const_Params p, EC_POINT *point,
    const BIGNUM *exp) {
  return EC_POINT_mul (p->group, point, NULL, p->h, exp, p->ctx);
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

int Params_point_to_exponent (const_Params p, BIGNUM *exp,
                              const EC_POINT *point)
{
  int rv = ERROR;
  unsigned char buf[33];
  EC_POINT_point2oct(p->group, point, POINT_CONVERSION_COMPRESSED, buf, 33, p->ctx);
  CHECK_C (Params_hash_to_exponent(p, exp, buf, 33));

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

static int 
hash_to_int_max (const_Params p, BIGNUM *exp, 
    const BIGNUM *max, const uint8_t *str, int strlen)
{
  int rv = ERROR;

  int nbytes = BN_num_bytes (max);
  uint8_t bytes_out[nbytes];

  CHECK_C (hash_to_bytes (bytes_out, nbytes, str, strlen));
  CHECK_A (BN_bin2bn (bytes_out, SHA256_DIGEST_LENGTH, exp));
  CHECK_C (BN_mod (exp, exp, p->order, p->ctx));

cleanup:
  return rv;
}

int Params_hash_to_exponent(const_Params p, BIGNUM *exp,
                            const uint8_t *str, int strlen)
{
  return hash_to_int_max(p, exp, p->order, str, strlen);
}

/* Hash EC point, prefixed with tag. */
int
Params_hash_point (const_Params p, EVP_MD_CTX *mdctx, const uint8_t *tag, int taglen,
            const EC_POINT *pt)
{
  int rv = ERROR;
  const EC_GROUP *group = Params_group (p);
  BN_CTX *ctx = Params_ctx (p);

  const size_t nlen = EC_POINT_point2oct (group, pt,
        POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
  uint8_t buf[nlen];
  const size_t wrote = EC_POINT_point2oct (group, pt,
        POINT_CONVERSION_COMPRESSED, buf, nlen, ctx);

  CHECK_C (EVP_DigestUpdate (mdctx, &taglen, sizeof taglen));
  CHECK_C (EVP_DigestUpdate (mdctx, tag, taglen));
  CHECK_C (EVP_DigestUpdate (mdctx, buf, wrote));

cleanup:
  return rv;
}

/* Hash to EC point. */
int 
Params_hash_to_point (const_Params p, EC_POINT *point, 
    const uint8_t *str, int strlen)
{
  int rv = ERROR;
  BIGNUM *x = NULL;
  CHECK_A (point);    // point should already be allocated with EC_POINT_new()
  CHECK_A (x = BN_new());

  // Hash string into an x coordinate
  CHECK_C (hash_to_int_max (p, x, p->base_prime, str, strlen));

  // TODO: To be completely correct, we should also derive the y_bit 
  // from the hash of the input string.
  int y_bit = 0;
  while (true) {
    // This will fail if there is not solution to the curve equation
    // with this x.
    if (EC_POINT_set_compressed_coordinates_GFp(p->group, point, x, y_bit, p->ctx))
      break;

    // If we fail to hash successfully, try again.
    //   - Increment x coordinate.
    //   - Flip the y bit.
    CHECK_C (BN_add_word (x, 1));
    CHECK_C (BN_mod (x, x, p->base_prime, p->ctx));
    y_bit = (y_bit + 1) % 2;
  }

cleanup:
  if (x) BN_clear_free (x);
  return rv;
}

