/*
 * Copyright (c) 2018, Google Inc.
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
#include "common.h"
#include "params.h"
#include "vif.h"
#include "vrf.h"

VIFProof
VIFProof_new(const_Params params)
{
  int rv = ERROR;
  VIFProof proof = NULL;
  CHECK_A (proof = malloc(sizeof *proof));

  proof->val = NULL;
  proof->vrf_proof = NULL;
  CHECK_A (proof->val = BN_new());
  CHECK_A (proof->vrf_proof = VRFProof_new(params));

cleanup:
  if (rv == ERROR) {
    VIFProof_free(proof);
    return NULL;
  }
  return proof;
}

void
VIFProof_free(VIFProof proof)
{
  if (proof->val) BN_clear_free(proof->val);
  if (proof->vrf_proof) VRFProof_free(proof->vrf_proof);
  free(proof);
}

int
VIF_eval (const_Params params, const BIGNUM *msk, const BIGNUM *sk_vrf,
          const uint8_t *input, int inputlen, BIGNUM *sk_out,
          EC_POINT *pk_out, VIFProof proof_out)
{
  int rv = ERROR;
  EC_POINT *x = NULL;
  CHECK_A (x = Params_point_new(params));

  // VRF.Eval(sk_vrf, input) --> val, vrf_proof
  CHECK_C (VRF_eval(params, sk_vrf, input, inputlen, proof_out->val, proof_out->vrf_proof));
  // sk_out = msk . val
  CHECK_C (BN_mod_mul(sk_out, msk, proof_out->val, Params_order(params), Params_ctx(params)));
  // pk_out = g^sk_out
  CHECK_C (Params_exp(params, pk_out, sk_out));

cleanup:
  if (x) EC_POINT_clear_free(x);
  return rv;
}

int
VIF_verify (const_Params params,
            const EC_POINT *mpk, const EC_POINT *pk_vrf, const uint8_t *input, int inputlen,
            const EC_POINT *pk, const_VIFProof proof)
{
  int rv = ERROR;
  EC_POINT *calc_pk = NULL;
  CHECK_A (calc_pk = Params_point_new(params));

  // VRF.Verify(pk_vrf, input, proof) --> {0,1}
  CHECK_C (VRF_verify(params, pk_vrf, input, inputlen, proof->val, proof->vrf_proof));

  // Check that pk = mpk^{g^val}
  CHECK_C (Params_exp_base(params, calc_pk, mpk, proof->val));

  CHECK_C (!EC_POINT_cmp(Params_group(params), calc_pk, pk, Params_ctx(params)));

cleanup:
  if (calc_pk) EC_POINT_clear_free(calc_pk);
  return rv;
}


