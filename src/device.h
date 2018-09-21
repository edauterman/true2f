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
#ifndef _DEVICE_H
#define _DEVICE_H

#include "params.h"
#include "pedersen_proof.h"
#include "sanitizable_ecdsa.h"
#include "vif.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * Models a U2F device that supports 3 actions: initialization, registration,
 * and authentication. Registration and authentication are defined in the U2F
 * spec, but initialization is a new step that allows the device to operate
 * deterministically from a fixed seed. Initialization can be done
 * deterministically (by directly loading a master keypair) or randomly (by
 * collaboratively generating the keypair such that the master keypair is known
 * only by the device). Registration and authentication produce the same
 * output as defined in the U2F spec with additional proofs to allow the agent
 * to audit the device. Note that batch signatures are not included (intend to
 * remove entirely) and test of user presence is not implemented.
 */

typedef struct device *Device;
typedef const struct device *const_Device;

Device Device_new(const_Params params, X509 *attestation_cert);
void Device_free(Device d);

/* Initialize device deterministically by directly loading master keypair. */
int Device_initializeDeterministic(Device d, const BIGNUM *msk, const BIGNUM *sk_vrf,
                                   uint64_t *ctr_out,
                                   X509 **attestation_cert_out);
/* Initialize device using collaborative randomness keygen protocol. */
int Device_initializeRandomized(Device d, EC_POINT *mpk_out, PedersenStatement
                                st_mpk_out, PedersenEvidence ev_mpk_out, EC_POINT *pk_vrf_out,
                                PedersenStatement st_vrf_out, PedersenEvidence ev_vrf_out, uint64_t
                                *ctr_out, X509 **attestation_cert_out);

/* Complete registration using provided key handle and output proof that public
 * key was generated using master keypair. */
int Device_register(Device d, const uint8_t *key_handle, EC_POINT *pk_out,
                    VIFProof proof_out, X509 **attestation_cert_out);
/* Complete authentication on device using sanitizable signature. */
int Device_authenticate(Device d, const uint8_t *key_handle, const uint8_t
                        *challenge, const uint8_t *app_id, ECDSA_SIG *sig_out,
                        PedersenStatement st_out, PedersenEvidence ev_out,
                        uint64_t *ctr_out);

/* Helper functions for testing. */
int Device_setMasterSecretKey(Device d, const BIGNUM *msk, const BIGNUM *sk_vrf);
void Device_setCtr(Device d, uint64_t ctr);

#ifdef __cplusplus
}
#endif
#endif

