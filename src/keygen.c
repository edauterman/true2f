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
#include <stdlib.h>

#include "common.h"
#include "keygen.h"
#include "params.h"

int Keygen_run(const_Params params, BIGNUM *sk_out, EC_POINT *pk_out,
               PedersenStatement st_out, PedersenEvidence ev_out)
{
  int rv = ERROR;
  BIGNUM *x = NULL;
  EC_POINT *commit_x = NULL;
  BIGNUM *r = NULL;
  BIGNUM *x_prime = NULL;

  CHECK_A (x = BN_new());
  CHECK_A (commit_x = Params_point_new(params));
  CHECK_A (r = BN_new());
  CHECK_A (x_prime = BN_new());

  // Device sends entropy request.
  CHECK_C (Keygen_entropy_req(params, x, commit_x, r));
  // Entropy authority responds to request.
  CHECK_C (Keygen_entropy_resp(params, x_prime));
  // Device generates keypair and ev.
  CHECK_C (Keygen_gen_keypair_with_ev(params, x, x_prime, r, sk_out, pk_out, ev_out));
  // Entropy authority generates statement.
  CHECK_C (PedersenStatement_generate(params, x_prime, commit_x, pk_out, st_out));

cleanup:
  if (x) BN_clear_free(x);
  if (commit_x) EC_POINT_clear_free(commit_x);
  if (r) BN_clear_free(r);
  if (x_prime) BN_clear_free(x_prime);
  return rv;
}

/**
 * Send entropy request from device to entropy authority. Device samples
 * random x and r and outputs commitment to x.
 */
int
Keygen_entropy_req(const_Params params, BIGNUM *x_out,
                           EC_POINT *commit_x_out, BIGNUM *r_out)
{
  int rv = ERROR;
  EC_POINT *g_to_the_x = NULL;
  EC_POINT *h_to_the_r = NULL;

  CHECK_A (g_to_the_x = Params_point_new (params));
  CHECK_A (h_to_the_r = Params_point_new (params));

  // Sample a random x.
  CHECK_C (Params_rand_exponent (params, x_out));

  // Sample a random r.
  CHECK_C (Params_rand_exponent (params, r_out));

  // C(x;r) = g^x*h^r
  // g^x
  CHECK_C (Params_exp_base_g (params, g_to_the_x, x_out));
  // h^r
  CHECK_C (Params_exp_base_h (params, h_to_the_r, r_out));
  // commit_x = g^x*h^r
  CHECK_C (Params_mul (params, commit_x_out, g_to_the_x, h_to_the_r));

cleanup:
  if (g_to_the_x) EC_POINT_clear_free(g_to_the_x);
  if (h_to_the_r) EC_POINT_clear_free(h_to_the_r);
  return rv;
}

/**
 * Entropy authority responds to device's entropy request. Entropy authority
 * simply samples random x'.
 */
int
Keygen_entropy_resp(const_Params params, BIGNUM *x_prime_out)
{
  int rv = ERROR;

  // Sample a random x'.
  CHECK_C (Params_rand_exponent (params, x_prime_out));

cleanup:
  return rv;
}

/**
 * Device uses its own randomness and randomness from entropy authority to
 * generate a keypair (sk_out, pk_out). Device also outputs ev that
 * pk_out is derived using x (as committed to by device) and x' (given by
 * entropy authority).
 *
 * sk_out = x + x'
 * pk_out = g^{x+x'}
 */
int
Keygen_gen_keypair_with_ev(const_Params params, const BIGNUM *x,
              const BIGNUM *x_prime, const BIGNUM *r, BIGNUM *sk_out,
              EC_POINT *pk_out, PedersenEvidence ev_out)
{
  int rv = ERROR;

  // sk = x + x'
  CHECK_C (BN_mod_add(sk_out, x, x_prime, Params_order(params),
                      Params_ctx(params)));
  // mpk = g^msk
  CHECK_C (Params_exp_base_g (params, pk_out, sk_out));
  // Generate ev using r.
  CHECK_C (PedersenEvidence_prove(params, r, ev_out));

cleanup:
  return rv;
}
