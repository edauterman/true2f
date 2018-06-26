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
#include "ddh.h"
#include "vrf.h"

struct public_key {
  EC_POINT *gx;
};

struct secret_key {
  BIGNUM *x;
};


PublicKey 
PublicKey_new (const_Params params)
{
  int rv = ERROR;
  PublicKey pk = NULL;
  pk = malloc (sizeof *pk);
  if (!pk)
    return NULL;

  pk->gx = NULL;
  CHECK_A (pk->gx = Params_point_new (params));

cleanup:
  if (rv == ERROR) {
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
  int rv = ERROR;
  SecretKey sk = NULL;
  CHECK_A (sk = malloc (sizeof *sk));

  sk->x = NULL;
  CHECK_A (sk->x = BN_new ());

cleanup:
  if (rv == ERROR) {
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
VRF_keygen (const_Params p, PublicKey pk_out, SecretKey sk_out)
{
  int rv = ERROR;
  CHECK_C (Params_rand_exponent (p, sk_out->x));
  CHECK_C (Params_exp (p, pk_out->gx, sk_out->x));

cleanup:
  return rv; 
}

int 
VRF_eval (const_Params params, const_SecretKey master_sk, 
    const uint8_t *input, int inputlen,
    PublicKey output_pk, SecretKey output_sk, DDHProof proof)
{
  int rv;
  const BIGNUM *q = Params_order (params);
  BN_CTX *ctx = Params_ctx (params);
  EC_POINT *ddh_gx = NULL;
  CHECK_A (ddh_gx = Params_point_new (params));

  // x = Hash(input)
  CHECK_C (Params_hash_to_exponent (params, output_sk->x, input, inputlen));

  // x + sk  mod q
  CHECK_C (BN_mod_add (output_sk->x, output_sk->x, master_sk->x, q, ctx)); 

  // Store g^{x + msk} in ddh_gx
  CHECK_C (Params_exp (params, ddh_gx, output_sk->x));

  // output = 1/(x + msk)  mod q
  CHECK_A (BN_mod_inverse (output_sk->x, output_sk->x, q, ctx)); 

  // Compute public key as g^output
  CHECK_C (Params_exp (params, output_pk->gx, output_sk->x));

  // Prove that
  //    (g, pk_input, g^H(input).g^{msk}, g) is a DDH tuple
  DDHStatement st; 
  st.g = Params_gen (params);
  st.gx = output_pk->gx;
  st.h = ddh_gx;
  st.hx = Params_gen (params);

  CHECK_C (DDHProof_prove (params, proof, &st, output_sk->x));

cleanup:
  if (ddh_gx) EC_POINT_clear_free (ddh_gx);
  return rv;
}

int 
VRF_verify (const_Params params,
    const_PublicKey mpk, const uint8_t *input, int inputlen,
    const_PublicKey output_pk, const_DDHProof proof)
{
  int rv;
  BIGNUM *x = NULL;
  EC_POINT *ddh_gx = NULL;

  CHECK_A (x = BN_new());
  CHECK_A (ddh_gx = Params_point_new (params));

  // x = Hash(input)
  CHECK_C (Params_hash_to_exponent (params, x, input, inputlen));

  // Compute g^H(input).g^{msk}
  CHECK_C (Params_exp (params, ddh_gx, x));
  CHECK_C (Params_mul (params, ddh_gx, ddh_gx, mpk->gx));

  // Check that
  //    (g, pk_input, g^H(input).g^{msk}, g) is a DDH tuple
  DDHStatement st; 
  st.g = Params_gen (params);
  st.gx = output_pk->gx;
  st.h = ddh_gx;
  st.hx = Params_gen (params);

  CHECK_C (DDHProof_verify (params, proof, &st));

cleanup:
  if (x) BN_clear_free (x);
  if (ddh_gx) EC_POINT_clear_free (ddh_gx);
  return rv;
}



