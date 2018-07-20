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
#include "src/params.h"

class ParamTest : public ::testing::TestWithParam<CurveName> {
  public:
    Params p;

  virtual void SetUp() {
    p = Params_new (GetParam());
    EXPECT_TRUE (p != NULL);

  }

  virtual void TearDown() {
    if (p)
      Params_free (p);
  }
};


TEST_P (ParamTest, Init) {
  // Just tests setup and teardown
  EXPECT_TRUE (true);
}

TEST_P (ParamTest, RandPoint) {
  BIGNUM *x = NULL;
  EC_POINT *pt = NULL;
  
  x = BN_new ();
  EXPECT_TRUE (x);
  if (!x) goto cleanup;

  pt = EC_POINT_new (Params_group (p));

  EXPECT_TRUE (Params_rand_exponent (p, x));
  EXPECT_TRUE (Params_rand_point (p, pt));

cleanup:
  if (x) BN_free (x);
  if (pt) EC_POINT_free (pt);
}

TEST_P (ParamTest, Exp) {
  int rv = ERROR;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  EC_POINT *pt = NULL;
  EC_POINT *pt2 = NULL;
  const EC_GROUP *grp = Params_group (p);
  BN_CTX *ctx = Params_ctx (p);
  
  CHECK_A (x = BN_new ());
  CHECK_A (y = BN_new ());

  pt = EC_POINT_new (Params_group (p));
  pt2 = EC_POINT_new (Params_group (p));

  EXPECT_TRUE (Params_rand_exponent (p, x));
  EXPECT_TRUE (Params_exp (p, pt, x));

  EXPECT_TRUE (EC_POINT_mul (grp, pt2, x, NULL, NULL, ctx));
  EXPECT_TRUE (EC_POINT_cmp (grp, pt, pt2, ctx) == 0);

cleanup:
  if (x) BN_free (x);
  if (y) BN_free (y);
  if (pt) EC_POINT_free (pt);
  if (pt2) EC_POINT_free (pt2);
  EXPECT_TRUE (rv);
}

TEST_P (ParamTest, HashToExp) {
  int rv = ERROR;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  uint8_t str[] = "this is the string";

  CHECK_A (x = BN_new ());
  CHECK_A (y = BN_new ());

  CHECK_C (Params_hash_to_exponent (p, x, str, sizeof str));
  CHECK_C (Params_hash_to_exponent (p, y, str, sizeof str));
  EXPECT_TRUE (BN_cmp (x, y) == 0);

  str[0] = '3';
  CHECK_C (Params_hash_to_exponent (p, y, str, sizeof str));
  EXPECT_FALSE (BN_cmp (x, y) == 0);

cleanup:
  if (x) BN_free (x);
  if (y) BN_free (y);
  EXPECT_TRUE (rv);
}

TEST_P (ParamTest, HashToPoint) {
  int rv = ERROR;
  EC_POINT *x = NULL;
  EC_POINT *y = NULL;
  const EC_GROUP *grp = Params_group (p);
  BN_CTX *ctx = Params_ctx (p);
  uint8_t str[] = "this is the string";

  CHECK_A (x = Params_point_new (p));
  CHECK_A (y = Params_point_new (p));

  CHECK_C (Params_hash_to_point (p, x, str, sizeof str));
  CHECK_C (Params_hash_to_point (p, y, str, sizeof str));
  EXPECT_TRUE (EC_POINT_cmp (grp, x, y, ctx) == 0);

  str[0] = '3';
  CHECK_C (Params_hash_to_point (p, y, str, sizeof str));
  EXPECT_FALSE (EC_POINT_cmp (grp, x, y, ctx) == 0);

  str[7] = '2';
  CHECK_C (Params_hash_to_point (p, y, str, sizeof str));
  EXPECT_FALSE (EC_POINT_cmp (grp, x, y, ctx) == 0);

cleanup:
  if (x) EC_POINT_free (x);
  if (y) EC_POINT_free (y);
  EXPECT_TRUE (rv);
}

INSTANTIATE_TEST_CASE_P (Init,
                        ParamTest,
                        ::testing::Values(P256, P384, P521));

class HashTest : public ::testing::TestWithParam<int> {};

TEST_P (HashTest, Basic) {
  int rv = ERROR;
  const int inlen = 123;
  const int outlen = GetParam();
  uint8_t bytes_out[outlen]; 
  uint8_t bytes_in[inlen];
  int zeros = 0;

  for (int i=0; i<inlen; i++) {
    bytes_in[i] = (uint8_t)i;
  }

  CHECK_C (hash_to_bytes (bytes_out, outlen, bytes_in, inlen));

  for (int i=0; i<outlen; i++) {
    if (!bytes_out[i]) zeros++;
  }
  
  EXPECT_LE (zeros, outlen/(64));

cleanup:
  EXPECT_TRUE (rv);
}

INSTANTIATE_TEST_CASE_P (Init,
                        HashTest,
                        ::testing::Values(0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 10023, 23103));

