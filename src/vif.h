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
#ifndef _VIF_H
#define _VIF_H

#include <openssl/ec.h>
#include "params.h"
#include "vrf.h"

#ifdef __cplusplus
extern "C"{
#endif

struct vif_proof {
  BIGNUM *val;
  VRFProof vrf_proof;
};

typedef struct vif_proof *VIFProof;
typedef const struct vif_proof *const_VIFProof;

VIFProof VIFProof_new(const_Params params);
void VIFProof_free(VIFProof proof);

int VIF_eval (const_Params params, const BIGNUM *msk, const BIGNUM *sk_vrf,
    const uint8_t *input, int inputlen, BIGNUM *sk_out,
    EC_POINT *pk_out, VIFProof proof_out);

int VIF_verify (const_Params params,
    const EC_POINT *mpk, const EC_POINT *pk_vrf, const uint8_t *input, int inputlen,
    const EC_POINT *pk, const_VIFProof proof);

#ifdef __cplusplus
}
#endif
#endif

