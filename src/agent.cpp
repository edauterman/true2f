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
#include <string.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <map>

#include "agent.h"
#include "common.h"
#include "device.h"
#include "vrf.h"

using namespace std;

/* Wrapper for storing key handles in a map. Allows lookup in map by key handle
 * value instead of by address of pointer. */
class KeyHandle {
  uint8_t data[KEY_HANDLE_LEN];

  public:
  KeyHandle(const uint8_t *data)
  {
    memcpy(this->data, data, KEY_HANDLE_LEN);
  }
  bool operator<(const KeyHandle &src) const
  {
    return memcmp(this->data, src.data, KEY_HANDLE_LEN);
  }
};

struct agent {
  const_Params params;
  EC_POINT *mpk;          // Master public key.
  EC_POINT *pk_vrf;
  X509 *attestation_cert; // Device attestation certificate.
  uint64_t ctr;           // State of counter on device.
  map<KeyHandle, EC_POINT*> *pk_map;  // Map of key handles to public keys.
};

int generate_key_handle(const uint8_t *app_id, uint8_t *key_handle_out);

Agent
Agent_new(const_Params params)
{
  int rv = ERROR;
  Agent a = (Agent) malloc(sizeof *a);
  if (!a)
    return NULL;

  CHECK_A (a->mpk = Params_point_new(params));
  CHECK_A (a->pk_vrf = Params_point_new(params));
  a->params = params;
  a->pk_map = new map<KeyHandle, EC_POINT*>;

cleanup:
  if (rv == ERROR) Agent_free(a);
  return rv == OKAY ? a : NULL;
}

void
Agent_free(Agent a)
{
  // Free all public keys stored in map.
  map<KeyHandle, EC_POINT*>::iterator it;
  for (it = a->pk_map->begin(); it != a->pk_map->end(); it++) {
    EC_POINT_clear_free(it->second);
  }
  // Free map.
  delete a->pk_map;

  if (a->mpk) EC_POINT_clear_free(a->mpk);
  if (a->pk_vrf) EC_POINT_clear_free(a->pk_vrf);
  free(a);
}

/* Initialize device deterministically by directly loading master keypair. */
int
Agent_initializeDeterministic(Agent a, Device d, const BIGNUM *msk, const
                              EC_POINT *mpk, const BIGNUM *sk_vrf, const
                              EC_POINT *pk_vrf)
{
  int rv = ERROR;
  CHECK_C (Device_initializeDeterministic(d, msk, sk_vrf, &a->ctr,
                                          &a->attestation_cert));
  if (a->mpk) EC_POINT_clear_free(a->mpk);
  if (a->pk_vrf) EC_POINT_clear_free(a->pk_vrf);
  CHECK_A (a->mpk = EC_POINT_dup(mpk, Params_group(a->params)));
  CHECK_A (a->pk_vrf = EC_POINT_dup(pk_vrf, Params_group(a->params)));

cleanup:
  return rv;
}

/* Initialize device using collaborative randomness keygen protocol. */
int
Agent_initializeRandomized(Agent a, Device d)
{
  int rv = ERROR;
  PedersenStatement st_mpk = NULL;
  PedersenEvidence ev_mpk = NULL;
  PedersenStatement st_vrf = NULL;
  PedersenEvidence ev_vrf = NULL;

  CHECK_A (st_mpk = PedersenStatement_new());
  CHECK_A (ev_mpk = PedersenEvidence_new(a->params));
  CHECK_A (st_vrf = PedersenStatement_new());
  CHECK_A (ev_vrf = PedersenEvidence_new(a->params));

  CHECK_C (Device_initializeRandomized(d, a->mpk, st_mpk, ev_mpk, a->pk_vrf, st_vrf, ev_vrf, &a->ctr,
                                       &a->attestation_cert));
  // Verify proof.
  CHECK_C (PedersenEvidence_verify(a->params, ev_mpk, st_mpk));
  CHECK_C (PedersenEvidence_verify(a->params, ev_vrf, st_vrf));

cleanup:
  if (st_mpk) PedersenStatement_free(st_mpk);
  if (ev_mpk) PedersenEvidence_free(ev_mpk);
  if (st_vrf) PedersenStatement_free(st_vrf);
  if (ev_vrf) PedersenEvidence_free(ev_vrf);
  return rv;
}

/* Register device, checking that public key was generated with master
 * keypair. */
int
Agent_register(Agent a, Device d, const uint8_t *app_id, EC_POINT *pk_out,
               uint8_t *key_handle_out, X509 **attestation_cert_out)
{
  int rv = ERROR;
  EC_POINT *pk_store = NULL;
  VIFProof proof = NULL;
  KeyHandle *kh_store;

  CHECK_A (proof = VIFProof_new(a->params));

  CHECK_C (generate_key_handle(app_id, key_handle_out));
  CHECK_C (Device_register(d, key_handle_out, pk_out, proof,
                           attestation_cert_out));

  // Check that attestation cert matches.
  CHECK_C (!X509_cmp(*attestation_cert_out, a->attestation_cert));

  // Check that public key is correctly generated.
  CHECK_C (VIF_verify(a->params, a->mpk, a->pk_vrf, key_handle_out, KEY_HANDLE_LEN, pk_out,
                      proof));

  // Save pk with key handle.
  kh_store = new KeyHandle(key_handle_out);
  CHECK_A (pk_store = EC_POINT_dup(pk_out, Params_group(a->params)));
  (*a->pk_map)[KeyHandle(key_handle_out)] = pk_store;

cleanup:
  if (proof) VIFProof_free(proof);
  if (rv == ERROR) {
    if (pk_store) EC_POINT_clear_free(pk_store);
  }
  return rv;
}

/* Authenticate using device, checking sanitizable ECDSA signature. */
int
Agent_authenticate(Agent a, Device d, const uint8_t *key_handle,
                   const uint8_t *challenge, const uint8_t *app_id,
                   ECDSA_SIG *sig_out, uint64_t *ctr_out)
{
  int rv = ERROR;
  PedersenStatement st = NULL;
  PedersenEvidence ev = NULL;
  map<KeyHandle, EC_POINT*>::iterator it;

  size_t message_len = CHALLENGE_LEN + APP_ID_LEN + sizeof(uint64_t);
  uint8_t message[message_len];

  CHECK_A (st = PedersenStatement_new());
  CHECK_A (ev = PedersenEvidence_new(a->params));

  CHECK_C (Device_authenticate(d, key_handle, challenge, app_id, sig_out, st,
                               ev, ctr_out));

  memcpy(message, challenge, CHALLENGE_LEN);
  memcpy(message + CHALLENGE_LEN, app_id, APP_ID_LEN);
  memcpy(message + CHALLENGE_LEN + APP_ID_LEN, ctr_out, sizeof(uint64_t));

  // Check that agent recognizes key handle.
  it = a->pk_map->find(KeyHandle(key_handle));
  CHECK_C (it != a->pk_map->end());

  // Verify sanitizable signature.
  CHECK_C (SanitizableEcdsa_verify(a->params, message, message_len,
                                   (*a->pk_map)[KeyHandle(key_handle)], sig_out,
                                   st, ev));

  // Check counter.
  CHECK_C (a->ctr++ == *ctr_out);

cleanup:
  if (st) PedersenStatement_free(st);
  if (ev) PedersenEvidence_free(ev);
  return rv;
}

/* Set master public key. Used only for testing. */
int
Agent_setPks(Agent a, EC_POINT *mpk, EC_POINT *pk_vrf)
{
  int rv = ERROR;
  if (a->mpk) EC_POINT_clear_free(a->mpk);
  CHECK_A (a->mpk = EC_POINT_dup(mpk, Params_group(a->params)));
  if (a->pk_vrf) EC_POINT_clear_free(a->pk_vrf);
  CHECK_A (a->pk_vrf = EC_POINT_dup(pk_vrf, Params_group(a->params)));

cleanup:
  return rv;
}

/* Generate key handle using app_id and randomness. */
int
generate_key_handle(const uint8_t *app_id, uint8_t *key_handle_out)
{
  int rv = ERROR;
  memcpy(key_handle_out, app_id, APP_ID_LEN);
  CHECK_C (RAND_bytes(key_handle_out + APP_ID_LEN, KEY_HANDLE_NUM_RAND_BYTES));

cleanup:
  return rv;
}
