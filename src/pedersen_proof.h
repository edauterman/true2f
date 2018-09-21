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
#ifndef _PEDERSEN_PROOF_H
#define _PEDERSEN_PROOF_H

#include "params.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * Pedersen Proof is a NIZKPoK used to ensure that the device incorporates the
 * randomness from the entropy authority (x') and the randomness committed to
 * by the device (x). The device has also already chosen a random r and used
 * that value in its commitment.
 *
 * Given commitment C_x = g^x.h^r and pk = g^{x+x'}, checks that:
 *      C_x.g^x' / pk = h^r
 *    = g^x.h^r.g^x' / g^{x+x'} = h^r
 *
 * r cannot be sent from the prover to the verifier directly, and so we use the
 * Schnorr protocol to prove that R = h^r without revealing r. We make the
 * Schnorr protocol non-interactive by choosing a challenge that is the hash of
 * generators g and h and points h^r and h^v.
 *
 * Using publicly known generators g,h of order q
 *
 * Prover(g,h,r)                          Verifier(g,h,C_x,pk)
 * ------                                 --------
 * R = h^r
 * random v
 * V = h^v
 * c = Hash(g,h,R,V)
 * z = v + cr (mod q)
 *                   c,z,R
 *        ------------------------------>
 *                                        V* = h^z / R^c
 *                                        c ?= Hash(g,h,R,V*)
 *                                        C*g^x' / pk ?= R
 */

struct pedersen_statement {
  // Randomness contributed by entropy authority.
  BIGNUM *x_prime;
  // Commitment to randomness from device.
  EC_POINT *commit_x;
  // Public key generated, g^{x+x'}.
  EC_POINT *pk;
};

/* Statement to be proven. */
typedef struct pedersen_statement *PedersenStatement;
typedef const struct pedersen_statement *const_PedersenStatement;

/* Proof of statement. */
typedef struct pedersen_evidence *PedersenEvidence;
typedef const struct pedersen_evidence *const_PedersenEvidence;

PedersenStatement PedersenStatement_new();
void PedersenStatement_free(PedersenStatement st);

PedersenEvidence PedersenEvidence_new(const_Params params);
void PedersenEvidence_free(PedersenEvidence ev);

/* Populate statement. */
int PedersenStatement_generate(const_Params params, const BIGNUM
                               *x_prime, const EC_POINT *commit_x,
                               const EC_POINT *pk, PedersenStatement
                               st_out);

/* Completed by prover. */
int PedersenEvidence_prove(const_Params params, const BIGNUM *r,
                        PedersenEvidence ev_out);
/* Completed by verifier. */
int PedersenEvidence_verify(const_Params params, const_PedersenEvidence ev,
                         const_PedersenStatement st);

#ifdef __cplusplus
}
#endif
#endif

