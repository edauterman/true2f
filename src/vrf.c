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
#include "common.h"
#include "vrf.h"

struct public_key {
  EC_POINT *gx;
};

struct secret_key {
  BIGNUM *x;
};


PublicKey 
PublicKey_new (Params params)
{
  PublicKey pk = NULL;
  pk = malloc (sizeof *pk);
  if (!pk)
    return NULL;

  pk->gx = NULL;
  pk->gx = EC_POINT_new (Params_group(params));
  if (!pk->gx) {
    PublicKey_free (pk);
    return NULL;
  }

  return pk;
}

void 
PublicKey_free (PublicKey pk)
{
  if (pk->gx)
    EC_POINT_clear_free (pk->gx);
  free (pk);
}


SecretKey 
SecretKey_new (void)
{
  SecretKey sk = NULL;
  sk = malloc (sizeof *sk);
  if (!sk)
    return NULL;

  sk->x = NULL;
  sk->x = BN_new ();
  if (!sk->x) {
    SecretKey_free (sk);
    return NULL;
  }

  return sk;
}

void 
SecretKey_free (SecretKey sk)
{
  if (sk->x)
    BN_clear_free (sk->x);    
  free (sk);
}

int 
VRF_keygen (Params p, PublicKey pk_out, SecretKey sk_out)
{
  int rv = ERROR;
  CHECK_C (Params_rand_exponent (p, sk_out->x));
  CHECK_C (Params_exp (p, pk_out->gx, sk_out->x));

cleanup:
  return rv; 
}

int 
VRF_eval (Params params, const_SecretKey master_sk, 
    const uint8_t *input, int inputlen,
    PublicKey output_pk, SecretKey output_sk, VRFProof *proof)
{
  int rv;
  const BIGNUM *q = Params_order (params);
  BN_CTX *ctx = Params_ctx (params);
  // x = Hash(input)
  CHECK_C (Params_hash_to_exponent (params, output_sk->x, input, inputlen));

  // x + sk  mod q
  CHECK_C (BN_mod_add (output_sk->x, output_sk->x, master_sk->x, q, ctx)); 

  // output = 1/(x + sk)  mod q
  CHECK_A (BN_mod_inverse (output_sk->x, output_sk->x, q, ctx)); 

  // Compute public key as g^output
  CHECK_C (Params_exp (params, output_pk->gx, output_sk->x));

cleanup:
  return ERROR;
}

