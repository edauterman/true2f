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

VRFProof
VRFProof_new(const_Params params)
{
  int rv = ERROR;
  VRFProof proof = NULL;
  CHECK_A (proof = malloc(sizeof *proof));

  proof->val_pt = NULL;
  proof->ddh_proof = NULL;
  CHECK_A (proof->val_pt = Params_point_new(params));
  CHECK_A (proof->ddh_proof = DDHProof_new());

cleanup:
  if (rv == ERROR) {
    VRFProof_free(proof);
    return NULL;
  }
  return proof;
}

void
VRFProof_free(VRFProof proof)
{
  if (proof->val_pt) EC_POINT_clear_free(proof->val_pt);
  if (proof->ddh_proof) DDHProof_free(proof->ddh_proof);
  free(proof);
}

int
VRF_keygen (const_Params p, EC_POINT *pk_out, BIGNUM *sk_out)
{
  int rv = ERROR;
  CHECK_C (Params_rand_exponent (p, sk_out));
  CHECK_C (Params_exp (p, pk_out, sk_out));

cleanup:
  return rv;
}

int
VRF_eval (const_Params params, const BIGNUM *sk,
    const uint8_t *input, int inputlen,
    BIGNUM *val_out, VRFProof proof_out)
{
  int rv;
  EC_POINT *hash_input = NULL;
  EC_POINT *pk = NULL;

  CHECK_A (hash_input = Params_point_new(params));
  CHECK_A (pk = Params_point_new(params));

  // Compute Hash(input)
  CHECK_C (Params_hash_to_point (params, hash_input, input, inputlen));

  // Compute Hash(input)^sk
  CHECK_C (Params_exp_base (params, proof_out->val_pt, hash_input, sk));

  // Get val by converting point to exponent.
  CHECK_C (Params_point_to_exponent(params, val_out, proof_out->val_pt));

  // pk = g^sk
  CHECK_C (Params_exp(params, pk, sk));

  // Prove that
  //    (g, g^sk, Hash(input), Hash(input)^sk) is a DDH tuple
  DDHStatement st;
  st.g = Params_gen (params);                 // g
  st.gx = pk;                                 // g^sk
  st.h = hash_input;  // Hash(input)
  st.hx = proof_out->val_pt;    // Hash(input)^sk

  CHECK_C (DDHProof_prove (params, proof_out->ddh_proof, &st, sk));

cleanup:
  if (hash_input) EC_POINT_clear_free(hash_input);
  if (pk) EC_POINT_clear_free(pk);
  return rv;
}

int
VRF_verify (const_Params params,
    const EC_POINT *pk, const uint8_t *input, int inputlen,
    const BIGNUM *val, const_VRFProof proof)
{
  int rv;
  EC_POINT *hash_input = NULL;
  BIGNUM *calc_val = NULL;

  CHECK_A (hash_input = Params_point_new(params));
  CHECK_A (calc_val = BN_new());

  // Hash(input)
  CHECK_C (Params_hash_to_point (params, hash_input, input, inputlen));

  // Check that
  //    (g, g^sk, Hash(input), Hash(input)^sk) is a DDH tuple
  DDHStatement st;
  st.g = Params_gen (params);     // g
  st.gx = pk;                     // g^sk
  st.h = hash_input;              // Hash(input)
  st.hx = proof->val_pt;          // Hash(input)^sk

  // Verify DDH proof.
  CHECK_C (DDHProof_verify (params, proof->ddh_proof, &st));

  // Check that proof->val_pt corresponds to val.
  CHECK_C (Params_point_to_exponent(params, calc_val, proof->val_pt));
  CHECK_C (!BN_cmp(calc_val, val));

cleanup:
  if (hash_input) EC_POINT_clear_free(hash_input);
  if (calc_val) BN_clear_free(calc_val);
  return rv;
}
