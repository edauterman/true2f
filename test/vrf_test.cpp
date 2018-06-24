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
#include "src/vrf.h"

TEST(VRF, KeyGen) {
  int rv = ERROR;
  Params p = NULL;
  PublicKey pk = NULL;
  SecretKey sk = NULL;
 
  CHECK_A (p = Params_new (P256));
  CHECK_A (pk = PublicKey_new (p));
  CHECK_A (sk = SecretKey_new ());

  CHECK_C (VRF_keygen (p, pk, sk));

cleanup:
  if (pk) PublicKey_free (pk);
  if (sk) SecretKey_free (sk);
  if (p) Params_free (p);
  EXPECT_TRUE (rv == OKAY);
}


