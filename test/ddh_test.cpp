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
#include "src/ddh.h"
#include "src/params.h"

TEST(DDH, Prove) {
  int rv;
  Params p = NULL;
  DDHProof pf = NULL;
  EC_POINT *g = NULL;
  EC_POINT *gx = NULL;
  EC_POINT *h = NULL;
  EC_POINT *hx = NULL;
  BIGNUM *x = NULL;

  CHECK_A (p = Params_new (P256));
  CHECK_A (pf = DDHProof_new ());
  CHECK_A (g = Params_point_new (p));
  CHECK_A (gx = Params_point_new (p));
  CHECK_A (h = Params_point_new (p));
  CHECK_A (hx = Params_point_new (p));
  CHECK_A (x = BN_new ());

  CHECK_C (Params_rand_point (p, g));
  CHECK_C (Params_rand_point (p, h));
  CHECK_C (Params_exp_base (p, gx, g, x));
  CHECK_C (Params_exp_base (p, hx, h, x));

  DDHStatement st;
  st.g = g;
  st.gx = gx;
  st.h = h;
  st.hx = hx;

  CHECK_C (DDHProof_prove (p, pf, &st, x));
  EXPECT_EQ (DDHProof_verify (p, pf, &st), OKAY);
  st.h = g;
  EXPECT_EQ (DDHProof_verify (p, pf, &st), ERROR);
  st.h = h;
  CHECK_C (Params_rand_point (p, h));
  EXPECT_EQ (DDHProof_verify (p, pf, &st), ERROR);

cleanup:
  EXPECT_TRUE (rv == OKAY);
  if (pf) DDHProof_free (pf);
  if (p) Params_free (p);
  if (g) EC_POINT_clear_free (g);
  if (gx) EC_POINT_clear_free (gx);
  if (h) EC_POINT_clear_free (h);
  if (hx) EC_POINT_clear_free (hx);
  if (x) BN_clear_free (x);
}

