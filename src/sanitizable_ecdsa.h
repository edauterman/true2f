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
#ifndef _SANITIZABLE_ECDSA_H
#define _SANITIZABLE_ECDSA_H

#include <openssl/ecdsa.h>
#include "params.h"
#include "pedersen_proof.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * Sanitizable ECDSA signatures are ECDSA signatures that also have a proof that
 * signature cannot be used as a covert channel. We do this by using the
 * collaborative key generation protocol to choose a nonce that incorporates
 * randomness committed to by the device and randomness from an entropy
 * authority such that if at least one of the sources of randomness is truly
 * random, the nonce is truly random. The verifier can then check this proof to
 * verify that the nonce has been correctly generated (in addition to verifying
 * the ECDSA signature using the public key).
 */

/* Sanitizable ECDSA operations. */
int SanitizableEcdsa_keygen(const_Params params, BIGNUM *sk_out,
                            EC_POINT *vk_out);
int SanitizableEcdsa_sign(const_Params params, const uint8_t *message, int
                          messagelen, const BIGNUM *sk, ECDSA_SIG *sig_out,
                          PedersenStatement st_out, PedersenEvidence ev_out);
int SanitizableEcdsa_verify(const_Params params, const uint8_t *message, int
                            messagelen, const EC_POINT *vk, const ECDSA_SIG
                            *sig, const_PedersenStatement st,
                            const_PedersenEvidence ev);

#ifdef __cplusplus
}
#endif
#endif

