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

  p = malloc (sizeof *p);
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
Params_group (Params p) 
{
  return p->group;
}

int 
Params_rand_point (Params p, EC_POINT *point)
{
  BIGNUM *exp = NULL;
  exp = BN_new ();

  if (!exp) return ERROR;
  if (Params_rand_exponent (p, exp) != OKAY) {
    BN_clear_free (exp);
    return ERROR;
  }

  int ret = Params_exp (p, point, exp);
      
  
  BN_clear_free (exp);
  return ret;
}

int 
Params_rand_exponent (Params p, BIGNUM *x)
{
  // TODO: Generate a uniform number in the range [0, q).
  int bits = BN_num_bits (p->order);
  return BN_rand (x, bits, 0, 0) ? OKAY : ERROR;
}

int 
Params_exp (Params p, EC_POINT *point, const BIGNUM *exp)
{
  return OKAY ? EC_POINT_mul (p->group, point, exp, NULL, NULL, p->ctx) : ERROR;
}

