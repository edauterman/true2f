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
#ifndef _KEYGEN_H
#define _KEYGEN_H

#include "params.h"
#include "pedersen_proof.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * Runs collaborative DSA key generation protocol between device and entropy
 * authority.
 *
 * Using generators g,h of order q (where discrete log relation between g and h
 * is unknown).
 *
 * Device                                  Entropy Authority
 * --------                                -----------------
 * random x, r
 * C_x = g^x.h^r
 *                   C_x
 *          ------------------------->
 *                                        random x'
 *                    x'
 *          <-------------------------
 * sk = x + x' mod q
 * pk = g^{x+x'}
 * pf = PedProve(g,h,r)
 *                   sk,pk,pf
 *          ------------------------->   PedVerify(pf,x',C_x,pk)
 */

int Keygen_run(const_Params params, BIGNUM *sk_out, EC_POINT *pk_out,
               PedersenStatement st_out, PedersenEvidence ev_out);

/* Device generates entropy request to send to entropy authority, sampling
 * a random x and r and outputting a commitment to x. */
int Keygen_entropy_req(const_Params params, BIGNUM *x_out,
                EC_POINT *commit_x_out, BIGNUM *r_out);

/* Entropy authority sends entropy response to device, sampling a random x'
 * and outputting the value directly. */
int Keygen_entropy_resp(const_Params params, BIGNUM *x_prime_out);

/* Device uses randomness from entropy authority and itself to generate DSA
 * keypair. Outputs ev that public key is generated using randomness from
 * entropy authority and randomness committed to by device. */
int Keygen_gen_keypair_with_ev(const_Params params, const BIGNUM *x,
                const BIGNUM *x_prime, const BIGNUM *r, BIGNUM *sk_out,
                EC_POINT *pk_out, PedersenEvidence ev_out);

#ifdef __cplusplus
}
#endif
#endif

