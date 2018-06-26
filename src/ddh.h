#ifndef _DDH_H
#define _DDH_H

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

#include <openssl/ec.h>
#include "params.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef struct {
  const EC_POINT *g;    // generator g
  const EC_POINT *gx;   // g^x
  const EC_POINT *h;    // h    = g^y
  const EC_POINT *hx;   // h^x  = g^{xy}
} DDHStatement;

typedef struct ddh_proof *DDHProof;
typedef const struct ddh_proof *const_DDHProof;

DDHProof DDHProof_new (void);
void DDHProof_free (DDHProof pf);

// Prove that four-tuple of points passed in is of the form
//    (g, g^x, g^y, g^{xy}).
// To prove this, the prover needs to know the secret exponent x.
int DDHProof_prove (const_Params p, DDHProof pf, const DDHStatement *st, const BIGNUM *x);

int DDHProof_verify (const_Params p, const_DDHProof pf, const DDHStatement *st);

#ifdef __cplusplus
}
#endif

#endif

