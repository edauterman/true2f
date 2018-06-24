#ifndef _VRF_H
#define _VRF_H

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

typedef struct public_key* PublicKey;
typedef const struct public_key* const_PublicKey;
typedef struct secret_key* SecretKey;
typedef const struct secret_key* const_SecretKey;
typedef struct vrf_proof* VRFProof;
typedef const struct vrf_proof* const_VRFProof;

PublicKey PublicKey_new (Params params);
void PublicKey_free (PublicKey key);

SecretKey SecretKey_new (void);
void SecretKey_free (SecretKey key);

int VRF_keygen (Params params, PublicKey pk_out, SecretKey sk_out);

int VRF_eval (Params params, const_SecretKey master_sk, 
    const uint8_t *input, int inputlen,
    PublicKey output_pk, SecretKey output_sk, VRFProof proof);

int VRF_verify (Params params,
    const_PublicKey mpk, const uint8_t *input, int inputlen,
    const_PublicKey output_pk, const_VRFProof proof);

#ifdef __cplusplus
}
#endif
#endif

