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
#ifndef _AGENT_H
#define _AGENT_H

#include "device.h"
#include "params.h"
#include "pedersen_proof.h"
#include "sanitizable_ecdsa.h"

/**
 * Models a local agent that audits a U2F device. The agent proxies all requests
 * to the device from the browser, and checks that the device's behavior using
 * the fixed seed set at initialization. Registration and authentication are
 * defined in the U2F spec, but initialization is a new step that allows the
 * device to operate deterministically from a fixed seed. Registration and
 * authentication produce the same output as defined in the U2F spec with
 * additional proofs that allow the agent to audit the device. */

/* All constants in terms of bytes. */
#define APP_ID_LEN 32       // Defined in U2F spec, length of appID field.
#define CHALLENGE_LEN 32    // Defined in U2F spec, length of challenge.
#define KEY_HANDLE_LEN 128  // According to U2F spec, key handle length can be
                            // between 0 and 128 bytes. We choose 128 bytes for
                            // all key handles.
#define KEY_HANDLE_NUM_RAND_BYTES KEY_HANDLE_LEN - APP_ID_LEN

typedef struct agent *Agent;
typedef const struct agent *const_Agent;

Agent Agent_new(const_Params params);
void Agent_free(Agent a);

/* Initialize device deterministically by directly loading master keypair. */
int Agent_initializeDeterministic(Agent a, Device d, const BIGNUM *msk, const
                                  EC_POINT *mpk, const BIGNUM *sk_vrf, const
                                  EC_POINT *pk_vrf);
/* Initialize device using collaborative randomness keygen protocol. */
int Agent_initializeRandomized(Agent a, Device d);

/* Complete registration with device, auditing behavior. */
int Agent_register(Agent a, Device d, const uint8_t *app_id, EC_POINT *pk_out,
                   uint8_t *key_handle_out, X509 **attestation_cert_out);
/* Complete authentication with device, auditing behavior. */
int Agent_authenticate(Agent a, Device d, const uint8_t *key_handle, const
                       uint8_t *challenge, const uint8_t *app_id, ECDSA_SIG
                       *sig_out, uint64_t *ctr_out);

/* Helper function for testing. */
int Agent_setPks(Agent a, EC_POINT *mpk, EC_POINT *pk_vrf);

#endif

