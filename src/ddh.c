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
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common.h"
#include "ddh.h"

struct ddh_proof {
  BIGNUM *c;  // Challenge
  BIGNUM *v;  // Verifier's response
};

DDHProof 
DDHProof_new (void)
{
  int rv = ERROR;
  DDHProof pf = NULL;
  CHECK_A (pf = malloc (sizeof *pf));

  pf->c = NULL;
  pf->v = NULL;
  CHECK_A (pf->c = BN_new ());
  CHECK_A (pf->v = BN_new ());

cleanup:
  if (rv == ERROR) {
    DDHProof_free (pf);
    return NULL;
  }

  return pf;
}

void
DDHProof_free (DDHProof pf)
{
  if (pf->c) BN_clear_free (pf->c);
  if (pf->v) BN_clear_free (pf->v);
  free (pf);
}

static int
hash_point (Params p, EVP_MD_CTX *mdctx, const uint8_t *tag, int taglen, const EC_POINT *pt)
{
  int rv = ERROR;
  const EC_GROUP *group = Params_group (p);
  BN_CTX *ctx = Params_ctx (p);

  const size_t nlen = EC_POINT_point2oct (group, pt,
        POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
  uint8_t buf[nlen];
  const size_t wrote = EC_POINT_point2oct (group, pt,
        POINT_CONVERSION_COMPRESSED, buf, nlen, ctx);

  CHECK_C (EVP_DigestUpdate (mdctx, &taglen, sizeof taglen));
  CHECK_C (EVP_DigestUpdate (mdctx, tag, taglen));
  CHECK_C (EVP_DigestUpdate (mdctx, buf, wrote));

cleanup:
  return rv;
}

static int
compute_challenge (Params p, BIGNUM *chal,
    const DDHStatement *st, 
    const EC_POINT *R1, 
    const EC_POINT *R2)
{
  int rv = ERROR;
  const uint8_t tag_g[] = "g";
  const uint8_t tag_gx[] = "gx";
  const uint8_t tag_h[] = "h";
  const uint8_t tag_hx[] = "hx";
  const uint8_t tag_r1[] = "R1";
  const uint8_t tag_r2[] = "R2";

  uint8_t buf[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx = NULL; 

  CHECK_A (mdctx = EVP_MD_CTX_create());
  CHECK_C (EVP_DigestInit_ex (mdctx, EVP_sha256 (), NULL));
  CHECK_C (hash_point (p, mdctx, tag_g, sizeof tag_g, st->g));
  CHECK_C (hash_point (p, mdctx, tag_gx, sizeof tag_gx, st->gx));
  CHECK_C (hash_point (p, mdctx, tag_h, sizeof tag_h, st->h));
  CHECK_C (hash_point (p, mdctx, tag_hx, sizeof tag_hx, st->hx));
  CHECK_C (hash_point (p, mdctx, tag_r1, sizeof tag_r1, R1));
  CHECK_C (hash_point (p, mdctx, tag_r2, sizeof tag_r2, R2));
  CHECK_C (EVP_DigestFinal_ex (mdctx, buf, NULL));

  // The challenge should never need to be more than 256 bits.
  CHECK_C (BN_bin2bn (buf, SHA256_DIGEST_LENGTH, chal) != NULL);
  CHECK_C (BN_mod (chal, chal, Params_order (p), Params_ctx (p)));

cleanup:
  if (mdctx) EVP_MD_CTX_destroy (mdctx);
  return rv;
}

/******
 * To prove the statement, we use a three-move Sigma protocol.
 * Write the DDH tuple as 
 *    (g, g^x, h, h^x) = (g, X, h, X'). 
 * The prover proves knowledge of an x such that 
 *    X = g^x   AND   X' = g^x.
 * Let q be the order of the group.
 *
 * 1) Prover chooses random r in Z_q and sends to the verifier
 *        R = g^r   and    R' = h^r.
 * 2) Verifier chooses random c in Z_q and sends c to the prover.
 * 3) Prover responds with 
 *       v = r - cx    in Z_q.
 *
 * The verifier accepts if
 *      g^v == R/X^c    AND   h^v == R'/(X')^c.
 *
 * In the random-oracle model, the prover can just send the pair
 * (c, v) to the verifier, where c = Hash(g, X, X', R, R').
 * The verifier computes
 *      S = g^v . X^c  AND   S' = h^v . (X')^c
 * and accepts iff
 *      c == Hash(g, h, X, X', R, R').
 */
int 
DDHProve (Params p, DDHProof pf, const DDHStatement *st, const BIGNUM *x)
{
  int rv = ERROR;
  EC_POINT *R1 = NULL;
  EC_POINT *R2 = NULL;
  BIGNUM *r = NULL;

  const BIGNUM *order = Params_order (p);
  BN_CTX *ctx = Params_ctx (p);
  const EC_GROUP *group = Params_group (p);

  CHECK_A (R1 = EC_POINT_new (group));
  CHECK_A (R2 = EC_POINT_new (group));
  CHECK_A (r = BN_new ());

  // Sample a random r
  CHECK_C (Params_rand_exponent (p, r));

  // TODO: If one of the bases is the standard generator
  // for the curve, we can use Params_exp() to get a little
  // speed boost.
  
  // Compute R1 = g^r
  CHECK_C (Params_exp_base (p, R1, st->g, r));
  // Compute R2 = h^r
  CHECK_C (Params_exp_base (p, R2, st->h, r));

  // c = Hash(g, X, h, X', R1, R2)
  CHECK_C (compute_challenge (p, pf->c, st, R1, R2));

  // v = r - cx
  CHECK_C (BN_mod_mul (pf->v, pf->c, x, order, ctx));
  CHECK_C (BN_mod_sub (pf->v, r, pf->v, order, ctx));

cleanup:
  if (R1) EC_POINT_clear_free (R1);
  if (R2) EC_POINT_clear_free (R2);
  if (r) BN_clear_free (r);

  return rv;
}

int 
DDHVerify (Params p, const_DDHProof pf, const DDHStatement *st)
{
  int rv = ERROR;
  EC_POINT *R1 = NULL;
  EC_POINT *R2 = NULL;
  BIGNUM *c_test = NULL;

  const EC_GROUP *group = Params_group (p);

  CHECK_A (R1 = EC_POINT_new (group));
  CHECK_A (R2 = EC_POINT_new (group));
  CHECK_A (c_test = BN_new ());
  
  /*
   * The verifier computes
   *      S = g^v . X^c  AND   S' = h^v . (X')^c
   * and accepts iff
   *      c == Hash(g, h, X, X', R, R').
   */

  // Compute R1 = g^v . X^c
  CHECK_C (Params_exp_base2 (p, R1, st->g, pf->v, st->gx, pf->c));
  // Compute R2 = h^v . (X')^c
  CHECK_C (Params_exp_base2 (p, R2, st->h, pf->v, st->hx, pf->c));

  // c_test = Hash(g, X, h, X', R1, R2)
  CHECK_C (compute_challenge (p, c_test, st, R1, R2));

  // Accept proof iff c == c_test
  rv = !BN_cmp (pf->c, c_test);

cleanup:
  if (R1) EC_POINT_clear_free (R1);
  if (R2) EC_POINT_clear_free (R2);
  if (c_test) BN_clear_free (c_test);

  return rv;
}

