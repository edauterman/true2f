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
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "common.h"
#include "device.h"
#include "keygen.h"
#include "params.h"
#include "vrf.h"

/* Models U2F device. */
struct device {
  const_Params params;
  BIGNUM *msk;              // Master secret key.
  BIGNUM *sk_vrf;
  X509 *attestation_cert;   // Device attestation certificate.
  uint64_t ctr;             // Global counter.
};

Device
Device_new(const_Params params, X509 *attestation_cert)
{
  int rv = ERROR;
  Device d = malloc(sizeof *d);
  if (!d)
    return NULL;

  CHECK_A (d->msk = BN_new());
  CHECK_A (d->sk_vrf = BN_new());

  d->params = params;
  d->attestation_cert = X509_dup(attestation_cert);
  d->ctr = 0;

cleanup:
  if (rv == ERROR) Device_free(d);
  return rv == OKAY ? d : NULL;
}

void
Device_free(Device d)
{
  if (d->msk) BN_clear_free(d->msk);
  if (d->sk_vrf) BN_clear_free(d->sk_vrf);
  free(d);
}

/* Initialize device by directly loading master keypair. */
int
Device_initializeDeterministic(Device d, const BIGNUM *msk, const BIGNUM *sk_vrf, uint64_t *ctr_out,
                               X509 **attestation_cert_out)
{
  int rv = ERROR;

  CHECK_C (Device_setMasterSecretKey(d, msk, sk_vrf));
  CHECK_A (*attestation_cert_out = X509_dup(d->attestation_cert));
  *ctr_out = d->ctr;

cleanup:
  return rv;
}

/* Initialize device using collaborative randomness keygen. */
int
Device_initializeRandomized(Device d, EC_POINT *mpk_out, PedersenStatement
                            st_mpk_out, PedersenEvidence ev_mpk_out, EC_POINT *pk_vrf_out,
                            PedersenStatement st_vrf_out, PedersenEvidence ev_vrf_out,
                            uint64_t *ctr_out, X509 **attestation_cert_out)
{
  int rv = ERROR;
  CHECK_C (Keygen_run(d->params, d->msk, mpk_out, st_mpk_out, ev_mpk_out));
  CHECK_C (Keygen_run(d->params, d->sk_vrf, pk_vrf_out, st_vrf_out, ev_vrf_out));
  CHECK_A (*attestation_cert_out = X509_dup(d->attestation_cert));
  *ctr_out = d->ctr;

cleanup:
  return rv;
}

/* Complete registration phase as defined by U2F spec (not including batch
 * signatures). Generate user keypair from key handle and output proof that it
 * was generated using master keypair. */
int
Device_register(Device d, const uint8_t *key_handle, EC_POINT *pk_out, VIFProof
                proof_out, X509 **attestation_cert_out)
{
  int rv = ERROR;
  BIGNUM *sk_discard = NULL;
  CHECK_A (sk_discard = BN_new());

  // Generate user key pair.
  CHECK_C (VIF_eval(d->params, d->msk, d->sk_vrf, key_handle, KEY_HANDLE_LEN, sk_discard, pk_out,
                    proof_out));
  CHECK_A (*attestation_cert_out = X509_dup(d->attestation_cert));

cleanup:
  if (sk_discard) BN_clear_free(sk_discard);
  return rv;
}

/* Complete authentication phase as defined by U2F spec (not including test of
 * user presence). Use sanitizable ECDSA signatures that can be checked by
 * agent. */
int
Device_authenticate(Device d, const uint8_t *key_handle, const uint8_t
                    *challenge, const uint8_t *app_id, ECDSA_SIG *sig_out,
                    PedersenStatement st_out, PedersenEvidence ev_out,
                    uint64_t *ctr_out)
{
  int rv = ERROR;
  BIGNUM *sk = NULL;
  EC_POINT *pk_discard = NULL;
  VIFProof pf_discard = NULL;

  // message = challenge || appId || ctr || presenceBit
  size_t message_len = CHALLENGE_LEN + APP_ID_LEN + sizeof(uint64_t);
  uint8_t message[message_len];
  memcpy(message, challenge, CHALLENGE_LEN);
  memcpy(message + CHALLENGE_LEN, app_id, APP_ID_LEN);
  memcpy(message + CHALLENGE_LEN + APP_ID_LEN, &d->ctr, sizeof(uint64_t));

  CHECK_A (sk = BN_new());
  CHECK_A (pk_discard = Params_point_new(d->params));
  CHECK_A (pf_discard = VIFProof_new(d->params));

  // Recover user key pair associated with key handle.
  CHECK_C (VIF_eval(d->params, d->msk, d->sk_vrf, key_handle, KEY_HANDLE_LEN, sk,
                    pk_discard, pf_discard));
  // Sign message.
  CHECK_C (SanitizableEcdsa_sign(d->params, message, message_len, sk, sig_out,
                                 st_out, ev_out));
  // Increment ctr and return.
  *ctr_out = d->ctr++;

cleanup:
  if (sk) BN_clear_free(sk);
  if (pk_discard) EC_POINT_clear_free(pk_discard);
  if (pf_discard) VIFProof_free(pf_discard);
  return rv;
}

/* Directly load master secret key onto device. Not initialization, only for
 * testing. */
int
Device_setMasterSecretKey(Device d, const BIGNUM *msk, const BIGNUM *sk_vrf)
{
  int rv = ERROR;
  if (d->msk) BN_clear_free(d->msk);
  if (d->sk_vrf) BN_clear_free(d->sk_vrf);
  CHECK_A (d->msk = BN_dup(msk));
  CHECK_A (d->sk_vrf = BN_dup(sk_vrf));

cleanup:
  return rv;
}

/* Directly set counter. Only for testing. */
void
Device_setCtr(Device d, uint64_t ctr)
{
  d->ctr = ctr;
}
