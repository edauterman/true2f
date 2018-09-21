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
#include <gtest/gtest.h>

#include "src/common.h"
#include "src/keygen.h"
#include "src/params.h"
#include "src/pedersen_proof.h"

/* Test collaborative DSA key generation protocol. Model interaction between
 * device and entropy authority with function calls. */
TEST(Keygen, Basic) {
  int rv;
  Params params = NULL;
  BIGNUM *sk = NULL;
  EC_POINT *pk = NULL;
  PedersenEvidence ev = NULL;
  PedersenStatement st = NULL;

  CHECK_A (params = Params_new(P256));
  CHECK_A (sk = BN_new());
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (ev = PedersenEvidence_new(params));
  CHECK_A (st = PedersenStatement_new());

  // Run key generation.
  EXPECT_EQ (Keygen_run(params, sk, pk, st, ev), OKAY);

  // Entropy authority verifies ev.
  EXPECT_EQ (PedersenEvidence_verify(params, ev, st), OKAY);

cleanup:
  if (params) Params_free(params);
  if (sk) BN_clear_free(sk);
  if (pk) EC_POINT_clear_free(pk);
  if (ev) PedersenEvidence_free(ev);
  if (st) PedersenStatement_free(st);
  EXPECT_TRUE (rv == OKAY);
}

/* Try to prove bad statement. */
TEST(Keygen, BadStatement) {
  int rv;
  Params params = NULL;
  BIGNUM *sk = NULL;
  EC_POINT *pk = NULL;
  PedersenEvidence ev = NULL;
  PedersenStatement st = NULL;
  BIGNUM *rand_num = NULL;
  EC_POINT *rand_point1 = NULL;
  EC_POINT *rand_point2 = NULL;

  CHECK_A (params = Params_new(P256));
  CHECK_A (sk = BN_new());
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (ev = PedersenEvidence_new(params));
  CHECK_A (st = PedersenStatement_new());
  CHECK_A (rand_num = BN_new());
  CHECK_A (rand_point1 = Params_point_new(params));
  CHECK_A (rand_point2 = Params_point_new(params));

  CHECK_C (Params_rand_exponent(params, rand_num));
  CHECK_C (Params_rand_point(params, rand_point1));
  CHECK_C (Params_rand_point(params, rand_point2));

  // Run key generation.
  EXPECT_EQ (Keygen_run(params, sk, pk, st, ev), OKAY);

  // Bad statement.
  EXPECT_EQ (Params_rand_exponent(params, rand_num), OKAY);
  EXPECT_EQ (Params_rand_point(params, rand_point1), OKAY);
  EXPECT_EQ (Params_rand_point(params, rand_point2), OKAY);
  EXPECT_EQ (PedersenStatement_generate(params, rand_num, rand_point1,
                                        rand_point2, st), OKAY);
  EXPECT_EQ (PedersenEvidence_verify(params, ev, st), ERROR);

cleanup:
  if (params) Params_free(params);
  if (sk) BN_clear_free(sk);
  if (pk) EC_POINT_clear_free(pk);
  if (ev) PedersenEvidence_free(ev);
  if (st) PedersenStatement_free(st);
  if (rand_num) BN_clear_free(rand_num);
  if (rand_point1) EC_POINT_clear_free(rand_point1);
  if (rand_point2) EC_POINT_clear_free(rand_point2);
  EXPECT_TRUE (rv == OKAY);
}

/* Try to prove statement using bad evidence. */
TEST(Keygen, BadEvidence) {
  int rv;
  Params params = NULL;
  BIGNUM *sk = NULL;
  EC_POINT *pk = NULL;
  PedersenEvidence ev = NULL;
  PedersenStatement st = NULL;
  BIGNUM *rand = NULL;

  CHECK_A (params = Params_new(P256));
  CHECK_A (sk = BN_new());
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (ev = PedersenEvidence_new(params));
  CHECK_A (st = PedersenStatement_new());
  CHECK_A (rand = BN_new());

  CHECK_C (Params_rand_exponent(params, rand));

  // Run key generation.
  EXPECT_EQ (Keygen_run(params, sk, pk, st, ev), OKAY);

  // Bad evidence.
  EXPECT_EQ (Params_rand_exponent(params, rand), OKAY);
  EXPECT_EQ (PedersenEvidence_prove(params, rand, ev), OKAY);
  EXPECT_EQ (PedersenEvidence_verify(params, ev, st), ERROR);

cleanup:
  if (params) Params_free(params);
  if (sk) BN_clear_free(sk);
  if (pk) EC_POINT_clear_free(pk);
  if (ev) PedersenEvidence_free(ev);
  if (st) PedersenStatement_free(st);
  if (rand) BN_clear_free(rand);
  EXPECT_TRUE (rv == OKAY);
}

/* Try to generate keypair with different value than committed to. */
TEST(Keygen, UseCommittedNum) {
  int rv;
  Params params = NULL;
  BIGNUM *sk = NULL;
  EC_POINT *pk = NULL;
  PedersenEvidence ev = NULL;
  PedersenStatement st = NULL;
  BIGNUM *rand = NULL;
  BIGNUM *x = NULL;
  EC_POINT *commit_x = NULL;
  BIGNUM *r = NULL;
  BIGNUM *x_prime = NULL;

  CHECK_A (params = Params_new(P256));
  CHECK_A (sk = BN_new());
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (ev = PedersenEvidence_new(params));
  CHECK_A (st = PedersenStatement_new());
  CHECK_A (rand = BN_new());
  CHECK_A (x = BN_new());
  CHECK_A (commit_x = Params_point_new(params));
  CHECK_A (r = BN_new());
  CHECK_A (x_prime = BN_new());

  CHECK_C(Params_rand_exponent(params, rand));

  // Device sends entropy request.
  EXPECT_EQ (Keygen_entropy_req(params, x, commit_x, r), OKAY);
  // Entropy authority responds to request.
  EXPECT_EQ (Keygen_entropy_resp(params, x_prime), OKAY);
  // Device generates keypair using different value than it committed to.
  EXPECT_EQ (Keygen_gen_keypair_with_ev(params, rand, x_prime, r, sk, pk, ev),
             OKAY);
  // Entropy authority generates statement.
  EXPECT_EQ (PedersenStatement_generate(params, x_prime, commit_x, pk, st),
             OKAY);
  // Check proof.
  EXPECT_EQ (PedersenEvidence_verify(params, ev, st), ERROR);

cleanup:
  if (params) Params_free(params);
  if (sk) BN_clear_free(sk);
  if (pk) EC_POINT_clear_free(pk);
  if (ev) PedersenEvidence_free(ev);
  if (st) PedersenStatement_free(st);
  if (rand) BN_clear_free(rand);
  if (x) BN_clear_free(x);
  if (commit_x) EC_POINT_clear_free(commit_x);
  if (r) BN_clear_free(r);
  if (x_prime) BN_clear_free(x_prime);
  EXPECT_TRUE (rv == OKAY);
}

/* Try to generate keypair with different value than given by entropy
 * authority. */
TEST(Keygen, UseEaNum) {
  int rv;
  Params params = NULL;
  BIGNUM *sk = NULL;
  EC_POINT *pk = NULL;
  PedersenEvidence ev = NULL;
  PedersenStatement st = NULL;
  BIGNUM *rand = NULL;
  BIGNUM *x = NULL;
  EC_POINT *commit_x = NULL;
  BIGNUM *r = NULL;
  BIGNUM *x_prime = NULL;

  CHECK_A (params = Params_new(P256));
  CHECK_A (sk = BN_new());
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (ev = PedersenEvidence_new(params));
  CHECK_A (st = PedersenStatement_new());
  CHECK_A (rand = BN_new());
  CHECK_A (x = BN_new());
  CHECK_A (commit_x = Params_point_new(params));
  CHECK_A (r = BN_new());
  CHECK_A (x_prime = BN_new());

  CHECK_C(Params_rand_exponent(params, rand));

  // Device sends entropy request.
  EXPECT_EQ (Keygen_entropy_req(params, x, commit_x, r), OKAY);
  // Entropy authority responds to request.
  EXPECT_EQ (Keygen_entropy_resp(params, x_prime), OKAY);
  // Device generates keypair using different value than given by entropy
  // authority.
  EXPECT_EQ (Keygen_gen_keypair_with_ev(params, x, rand, r, sk, pk, ev), OKAY);
  // Entropy authority generates statement.
  EXPECT_EQ (PedersenStatement_generate(params, x_prime, commit_x, pk, st),
             OKAY);
  // Check proof.
  EXPECT_EQ (PedersenEvidence_verify(params, ev, st), ERROR);

cleanup:
  if (params) Params_free(params);
  if (sk) BN_clear_free(sk);
  if (pk) EC_POINT_clear_free(pk);
  if (ev) PedersenEvidence_free(ev);
  if (st) PedersenStatement_free(st);
  if (rand) BN_clear_free(rand);
  if (x) BN_clear_free(x);
  if (commit_x) EC_POINT_clear_free(commit_x);
  if (r) BN_clear_free(r);
  if (x_prime) BN_clear_free(x_prime);
  EXPECT_TRUE (rv == OKAY);
}
