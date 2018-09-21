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
#include "pedersen_proof.h"
#include "sanitizable_ecdsa.h"

int extract_x_point(const_Params params, const EC_POINT *pt, BIGNUM *x_out);

/* Generate new keypair for Sanitizable ECDSA signature. */
int
SanitizableEcdsa_keygen(const_Params params, BIGNUM *sk_out, EC_POINT *vk_out)
{
  return Params_rand_point_exp(params, vk_out, sk_out);
}

/* Outputs ECDSA signature on message using sk and proof that the nonce contains
 * randomness from both the device and entropy authority (the choice of nonce
 * cannot be used to leak information). Uses collaborative keygen protocol
 * to generate the nonce and ZKP. Note only generates signatures of the form
 * (r,s) and not of the form (r,-s). */
int
SanitizableEcdsa_sign(const_Params params, const uint8_t *message,
                      int messagelen, const BIGNUM *sk, ECDSA_SIG *sig_out,
                      PedersenStatement st_out, PedersenEvidence ev_out)
{
  int rv = ERROR;
  BIGNUM *m = NULL;     // Hash of message
  BIGNUM *k = NULL;     // nonce k
  EC_POINT *K = NULL;   // g^k
  BIGNUM *k_inv = NULL; // inverse of nonce k mod q
  BIGNUM *zero = NULL;
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;

  CHECK_A (m = BN_new());
  CHECK_A (k = BN_new());
  CHECK_A (K = Params_point_new(params));
  CHECK_A (zero = BN_new());
  CHECK_A (r = BN_new());
  CHECK_A (s = BN_new());

  CHECK_C (BN_zero(zero));
  // m = Hash(message)
  CHECK_C (Params_hash_to_exponent(params, m, message, messagelen));
  do {
    // Generate nonce k using collaborative keygen, set st_out, pf_out
    // K = g^k
    CHECK_C (Keygen_run(params, k, K, st_out, ev_out));
    // K_x = x point of K
    // r = K_x mod n
    CHECK_C (extract_x_point(params, K, r));
    // s = k^-1 (m + sig->r.sk) mod q
    CHECK_C (BN_mod_mul(s, r, sk, Params_order(params),
                        Params_ctx(params)));
    CHECK_C (BN_mod_add(s, m, s, Params_order(params),
                        Params_ctx(params)));
    CHECK_A (k_inv = BN_mod_inverse(NULL, k, Params_order(params),
                                    Params_ctx(params)));
    CHECK_C (BN_mod_mul(s, s, k_inv , Params_order(params),
                        Params_ctx(params)));
    // Repeat until r != 0 and s > 0 (s != 0 for ECDSA, s > 0 to only allow
    // (r,s) and not (r,-s)).
  } while (BN_is_zero(r) || BN_cmp(s, zero) < 1);

  CHECK_C (ECDSA_SIG_set0(sig_out, r, s));

cleanup:
  if (m) BN_clear_free(m);
  if (k) BN_clear_free(k);
  if (K) EC_POINT_clear_free(K);
  if (k_inv) BN_clear_free(k_inv);
  if (zero) BN_clear_free(zero);
  return rv;
}

/* Check output of SanitizableEcdsa_sign (signature and proof). Check that nonce
 * contains randomness committed to by the device and randomness from the
 * entropy authority, and that the signature is correct. */
int
SanitizableEcdsa_verify(const_Params params, const uint8_t *message,
                        int messagelen, const EC_POINT *vk, const ECDSA_SIG *sig,

                        const_PedersenStatement st, const_PedersenEvidence ev)
{
  int rv = ERROR;
  BIGNUM *calc_r = NULL;
  BIGNUM *m = NULL;   // Hash of message
  BIGNUM *u1 = NULL;
  BIGNUM *u2 = NULL;
  EC_POINT *pt = NULL;
  EC_POINT *tmp = NULL;
  BIGNUM *pt_x = NULL;
  BIGNUM *s_inv = NULL;
  BIGNUM *zero = NULL;
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;

  CHECK_A (calc_r = BN_new());
  CHECK_A (m = BN_new());
  CHECK_A (u1 = BN_new());
  CHECK_A (u2 = BN_new());
  CHECK_A (pt = Params_point_new(params));
  CHECK_A (tmp = Params_point_new(params));
  CHECK_A (pt_x = BN_new());
  CHECK_A (zero = BN_new());

  ECDSA_SIG_get0(sig, &r, &s);

  // Check proof of nonce.
  CHECK_C (PedersenEvidence_verify(params, ev, st));

  // Check that nonce is used in signature.
  CHECK_C (extract_x_point(params, st->pk, calc_r));
  CHECK_C (!BN_cmp(r, calc_r));

  // Check that s > 0 to only allow signatures of the form (r,s) and not (r,-s).
  CHECK_C (BN_cmp(s, zero) > 0);

  // Verify signature.
  // m = Hash(message)
  CHECK_C (Params_hash_to_exponent(params, m, message, messagelen));

  // u1 = m / s mod q
  CHECK_A (s_inv = BN_mod_inverse(NULL, s, Params_order(params),
                                  Params_ctx(params)));
  CHECK_C (BN_mod_mul(u1, m, s_inv, Params_order(params),
                      Params_ctx(params)));

  // u2 = r / sig->s mod q
  CHECK_C (BN_mod_mul(u2, r, s_inv, Params_order(params),
                      Params_ctx(params)));

  // pt = g^u1.vk^u2
  // tmp = g^u1
  CHECK_C (Params_exp(params, tmp, u1));
  // pt = vk^u2
  CHECK_C (Params_exp_base(params, pt, vk, u2));
  // pt = g^u1.vk^u2
  CHECK_C (Params_mul(params, pt, pt, tmp));

  // r ?= pt_x mod q
  CHECK_C (extract_x_point(params, pt, pt_x));
  CHECK_C (!BN_cmp(r, pt_x));

cleanup:
  if (calc_r) BN_clear_free(calc_r);
  if (m) BN_clear_free(m);
  if (u1) BN_clear_free(u1);
  if (u2) BN_clear_free(u2);
  if (pt) EC_POINT_clear_free(pt);
  if (tmp) EC_POINT_clear_free(tmp);
  if (pt_x) BN_clear_free(pt_x);
  if (zero) BN_clear_free(zero);
  return rv;
}

/* Extract x coordinate from EC_POINT and return x mod q. */
int
extract_x_point(const_Params params, const EC_POINT *pt, BIGNUM *x_out)
{
  int rv = ERROR;
  BIGNUM *y = NULL;
  CHECK_A (y = BN_new());

  // extract coordinates (x,y)
  CHECK_C (EC_POINT_get_affine_coordinates_GFp(Params_group(params), pt, x_out,
                                               y, Params_ctx(params)));
  // x_out = x mod q
  CHECK_C (BN_mod(x_out, x_out, Params_order(params), Params_ctx(params)));

cleanup:
  if (y) BN_clear_free(y);
  return rv;
}
