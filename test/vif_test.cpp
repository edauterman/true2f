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

#include <gtest/gtest.h> 

#include "src/common.h"
#include "src/vif.h"
#include "src/vrf.h"

TEST(VIF, KeyGen) {
  int rv = ERROR;
  Params p = NULL;
  EC_POINT *mpk = NULL;
  EC_POINT *pk_vrf = NULL;
  EC_POINT *pk = NULL;
  BIGNUM *msk = NULL;
  BIGNUM *sk_vrf = NULL;
  BIGNUM *sk = NULL;
  VIFProof pf = NULL;
  const uint8_t input[] = "www.example.com";
  const uint8_t input_bad[] = "www.evil.com";
 
  CHECK_A (p = Params_new (P256));
  CHECK_A (pf = VIFProof_new (p));
  CHECK_A (mpk = Params_point_new(p));
  CHECK_A (msk = BN_new());
  CHECK_A (pk_vrf = Params_point_new(p));
  CHECK_A (sk_vrf = BN_new());
  CHECK_A (pk = Params_point_new(p));
  CHECK_A (sk = BN_new());

  CHECK_C (VRF_keygen (p, mpk, msk));
  CHECK_C (VRF_keygen (p, pk_vrf, sk_vrf));
  CHECK_C (VIF_eval (p, msk, sk_vrf, input, sizeof input, sk, pk, pf));
  EXPECT_EQ (VIF_verify (p, mpk, pk_vrf, input, sizeof input, pk, pf), OKAY);
  EXPECT_EQ (VIF_verify (p, mpk, pk_vrf, input_bad, sizeof input_bad, pk, pf), ERROR);
  EXPECT_EQ (VIF_verify (p, mpk, pk_vrf, input, sizeof(input_bad) - 1, pk, pf), ERROR);
  EXPECT_EQ (VIF_verify (p, mpk, pk_vrf, input, 0, pk, pf), ERROR);
  EXPECT_EQ (VIF_verify (p, pk, pk_vrf, input, sizeof input, pk, pf), ERROR);
  EXPECT_EQ (VIF_verify (p, mpk, pk_vrf, input, sizeof input, mpk, pf), ERROR);

cleanup:
  if (mpk) EC_POINT_clear_free (mpk);
  if (msk) BN_clear_free (msk);
  if (pk) EC_POINT_clear_free (pk);
  if (sk) BN_clear_free (sk);
  if (p) Params_free (p);
  if (pf) VIFProof_free (pf);
  EXPECT_TRUE (rv == OKAY);
}


