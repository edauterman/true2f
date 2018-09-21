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
#include <gtest/gtest.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/ec.h>

#include "src/agent.h"
#include "src/common.h"
#include "src/device.h"
#include "src/params.h"
#include "src/sanitizable_ecdsa.h"

/* Test initialization, registration, and authentication between device and
 * agent. */

int set_test_cert(const_Params params, X509 *cert);

/* Test deterministic and randomized initialization of device. */
TEST(U2F, Initialization) {
  int rv;
  Params params = NULL;
  Device d = NULL;
  Agent a = NULL;
  BIGNUM *msk = NULL;
  EC_POINT *mpk = NULL;
  BIGNUM *sk_vrf = NULL;
  EC_POINT *pk_vrf = NULL;
  X509 *attestation_cert = NULL;

  CHECK_A (params = Params_new(P256));
  CHECK_A (attestation_cert = X509_new());
  CHECK_C (set_test_cert(params, attestation_cert));
  CHECK_A (d = Device_new(params, attestation_cert));
  CHECK_A (a = Agent_new(params));
  CHECK_A (msk = BN_new());
  CHECK_A (mpk = Params_point_new(params));
  CHECK_A (sk_vrf = BN_new());
  CHECK_A (pk_vrf = Params_point_new(params));

  // Deterministic initialization.
  EXPECT_EQ (Agent_initializeDeterministic(a, d, msk, mpk, sk_vrf, pk_vrf), OKAY);

  // Randomized initialization.
  EXPECT_EQ (Agent_initializeRandomized(a, d), OKAY);

cleanup:
  if (params) Params_free(params);
  if (d) Device_free(d);
  if (a) Agent_free(a);
  if (msk) BN_clear_free(msk);
  if (mpk) EC_POINT_clear_free(mpk);
  EXPECT_TRUE (rv == OKAY);
}

/* Test correct registration and authentication. */
TEST(U2F, Basic) {
  int rv;
  Params params = NULL;
  Device d = NULL;
  Agent a = NULL;
  BIGNUM *msk = NULL;
  EC_POINT *mpk = NULL;
  BIGNUM *sk_vrf = NULL;
  EC_POINT *pk_vrf = NULL;
  uint8_t app_id[APP_ID_LEN];
  uint8_t key_handle[KEY_HANDLE_LEN];
  X509 *attestation_cert = NULL;
  EC_POINT *pk = NULL;
  uint8_t challenge[CHALLENGE_LEN];
  ECDSA_SIG *sig = NULL;
  uint64_t ctr;

  CHECK_A (params = Params_new(P256));
  CHECK_A (attestation_cert = X509_new());
  CHECK_C (set_test_cert(params, attestation_cert));
  CHECK_A (d = Device_new(params, attestation_cert));
  CHECK_A (a = Agent_new(params));
  CHECK_A (msk = BN_new());
  CHECK_A (mpk = Params_point_new(params));
  CHECK_A (sk_vrf = BN_new());
  CHECK_A (pk_vrf = Params_point_new(params));
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (sig = ECDSA_SIG_new());

  CHECK_C (RAND_bytes(app_id, APP_ID_LEN));
  CHECK_C (RAND_bytes(challenge, CHALLENGE_LEN));
  CHECK_C (Params_rand_point_exp(params, mpk, msk));
  CHECK_C (Params_rand_point_exp(params, pk_vrf, sk_vrf));

  // Deterministic initialization.
  EXPECT_EQ (Agent_initializeDeterministic(a, d, msk, mpk, sk_vrf, pk_vrf), OKAY);

  // Register.
  EXPECT_EQ (Agent_register(a, d, app_id, pk, key_handle, &attestation_cert),
             OKAY);

  // Authenticate.
  EXPECT_EQ (Agent_authenticate(a, d, key_handle, challenge, app_id, sig, &ctr),
             OKAY);

cleanup:
  if (params) Params_free(params);
  if (d) Device_free(d);
  if (a) Agent_free(a);
  if (msk) BN_clear_free(msk);
  if (mpk) EC_POINT_clear_free(mpk);
  if (sk_vrf) BN_clear_free(sk_vrf);
  if (pk_vrf) EC_POINT_clear_free(pk_vrf);
  if (attestation_cert) X509_free(attestation_cert);
  if (pk) EC_POINT_clear_free(pk);
  if (sig) ECDSA_SIG_free(sig);
  EXPECT_TRUE (rv == OKAY);
}

/* Test trying to authenticate with a key handle not registered. */
TEST(U2F, BadKeyHandle) {
  int rv;
  Params params = NULL;
  Device d = NULL;
  Agent a = NULL;
  BIGNUM *msk = NULL;
  EC_POINT *mpk = NULL;
  BIGNUM *sk_vrf = NULL;
  EC_POINT *pk_vrf = NULL;
  uint8_t app_id[APP_ID_LEN];
  uint8_t key_handle[KEY_HANDLE_LEN];
  X509 *attestation_cert = NULL;
  EC_POINT *pk = NULL;
  uint8_t challenge[CHALLENGE_LEN];
  ECDSA_SIG *sig = NULL;
  uint64_t ctr = 0;

  CHECK_A (params = Params_new(P256));
  CHECK_A (attestation_cert = X509_new());
  CHECK_C (set_test_cert(params, attestation_cert));
  CHECK_A (d = Device_new(params, attestation_cert));
  CHECK_A (a = Agent_new(params));
  CHECK_A (msk = BN_new());
  CHECK_A (mpk = Params_point_new(params));
  CHECK_A (sk_vrf = BN_new());
  CHECK_A (pk_vrf = Params_point_new(params));
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (sig = ECDSA_SIG_new());

  CHECK_C (RAND_bytes(app_id, APP_ID_LEN));
  CHECK_C (RAND_bytes(challenge, CHALLENGE_LEN));
  CHECK_C (Params_rand_point_exp(params, mpk, msk));
  CHECK_C (Params_rand_point_exp(params, pk_vrf, sk_vrf));

  // Deterministic initialization.
  EXPECT_EQ (Agent_initializeDeterministic(a, d, msk, mpk, sk_vrf, pk_vrf), OKAY);

  // Register.
  EXPECT_EQ (Agent_register(a, d, app_id, pk, key_handle, &attestation_cert),
             OKAY);

  // Fill key handle with random bytes so key handle not recognized.
  CHECK_C (RAND_bytes(key_handle, KEY_HANDLE_LEN));

  // Authenticate.
  EXPECT_EQ (Agent_authenticate(a, d, key_handle, challenge, app_id, sig, &ctr),
             ERROR);

cleanup:
  if (params) Params_free(params);
  if (d) Device_free(d);
  if (a) Agent_free(a);
  if (msk) BN_clear_free(msk);
  if (mpk) EC_POINT_clear_free(mpk);
  if (sk_vrf) BN_clear_free(sk_vrf);
  if (pk_vrf) EC_POINT_clear_free(pk_vrf);
  if (attestation_cert) X509_free(attestation_cert);
  if (pk) EC_POINT_clear_free(pk);
  if (sig) ECDSA_SIG_free(sig);
  EXPECT_TRUE (rv == OKAY);
}

/* Test that agent correctly tracks the counter by changing the device counter
 * to a bad value. */
TEST(U2F, BadCounter) {
  int rv;
  Params params = NULL;
  Device d = NULL;
  Agent a = NULL;
  BIGNUM *msk = NULL;
  EC_POINT *mpk = NULL;
  BIGNUM *sk_vrf = NULL;
  EC_POINT *pk_vrf = NULL;
  uint8_t app_id[APP_ID_LEN];
  uint8_t key_handle[KEY_HANDLE_LEN];
  X509 *attestation_cert = NULL;
  EC_POINT *pk = NULL;
  uint8_t challenge[CHALLENGE_LEN];
  ECDSA_SIG *sig = NULL;
  uint64_t ctr = 0;

  CHECK_A (params = Params_new(P256));
  CHECK_A (attestation_cert = X509_new());
  CHECK_C (set_test_cert(params, attestation_cert));
  CHECK_A (d = Device_new(params, attestation_cert));
  CHECK_A (a = Agent_new(params));
  CHECK_A (msk = BN_new());
  CHECK_A (mpk = Params_point_new(params));
  CHECK_A (sk_vrf = BN_new());
  CHECK_A (pk_vrf = Params_point_new(params));
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (sig = ECDSA_SIG_new());

  CHECK_C (RAND_bytes(app_id, APP_ID_LEN));
  CHECK_C (RAND_bytes(challenge, CHALLENGE_LEN));
  CHECK_C (Params_rand_point_exp(params, mpk, msk));
  CHECK_C (Params_rand_point_exp(params, pk_vrf, sk_vrf));

  // Deterministic initialization.
  EXPECT_EQ (Agent_initializeDeterministic(a, d, msk, mpk, sk_vrf, pk_vrf), OKAY);

  // Register.
  EXPECT_EQ (Agent_register(a, d, app_id, pk, key_handle, &attestation_cert),
             OKAY);

  // Set device counter to bad value.
  Device_setCtr(d, 100);

  // Authenticate. Agent should catch change in counter.
  EXPECT_EQ (Agent_authenticate(a, d, key_handle, challenge, app_id, sig, &ctr),
             ERROR);

cleanup:
  if (params) Params_free(params);
  if (d) Device_free(d);
  if (a) Agent_free(a);
  if (msk) BN_clear_free(msk);
  if (mpk) EC_POINT_clear_free(mpk);
  if (sk_vrf) BN_clear_free(sk_vrf);
  if (pk_vrf) EC_POINT_clear_free(pk_vrf);
  if (attestation_cert) X509_free(attestation_cert);
  if (pk) EC_POINT_clear_free(pk);
  if (sig) ECDSA_SIG_free(sig);
  EXPECT_TRUE (rv == OKAY);
}

/* Test device changing its master key pair after initialization. Agent should
 * catch change in registration. */
TEST(U2F, BadMpkAtDevice) {
  int rv;
  Params params = NULL;
  Device d = NULL;
  Agent a = NULL;
  BIGNUM *msk = NULL;
  EC_POINT *mpk = NULL;
  BIGNUM *sk_vrf = NULL;
  EC_POINT *pk_vrf = NULL;
  uint8_t app_id[APP_ID_LEN];
  uint8_t key_handle[KEY_HANDLE_LEN];
  X509 *attestation_cert = NULL;;
  EC_POINT *pk = NULL;;
  uint8_t challenge[CHALLENGE_LEN];
  ECDSA_SIG *sig = NULL;;
  uint64_t ctr = 0;
  BIGNUM *bad_msk = NULL;
  BIGNUM *bad_sk_vrf = NULL;

  CHECK_A (params = Params_new(P256));
  CHECK_A (attestation_cert = X509_new());
  CHECK_C (set_test_cert(params, attestation_cert));
  CHECK_A (d = Device_new(params, attestation_cert));
  CHECK_A (a = Agent_new(params));
  CHECK_A (msk = BN_new());
  CHECK_A (mpk = Params_point_new(params));
  CHECK_A (sk_vrf = BN_new());
  CHECK_A (pk_vrf = Params_point_new(params));
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (sig = ECDSA_SIG_new());
  CHECK_A (bad_msk = BN_new());
  CHECK_A (bad_sk_vrf = BN_new());

  CHECK_C (RAND_bytes(app_id, APP_ID_LEN));
  CHECK_C (RAND_bytes(challenge, CHALLENGE_LEN));
  CHECK_C (Params_rand_point_exp(params, mpk, msk));
  CHECK_C (Params_rand_point_exp(params, pk_vrf, sk_vrf));

  // Deterministic initialization.
  EXPECT_EQ (Agent_initializeDeterministic(a, d, msk, mpk, sk_vrf, pk_vrf), OKAY);

  // Change master key pair on device without agent knowing.
  CHECK_C (Params_rand_exponent(params, bad_msk));
  CHECK_C (Params_rand_exponent(params, bad_sk_vrf));
  CHECK_C (Device_setMasterSecretKey(d, bad_msk, bad_sk_vrf));

  // Register.
  EXPECT_EQ (Agent_register(a, d, app_id, pk, key_handle, &attestation_cert),
             ERROR);

cleanup:
  if (params) Params_free(params);
  if (d) Device_free(d);
  if (a) Agent_free(a);
  if (msk) BN_clear_free(msk);
  if (mpk) EC_POINT_clear_free(mpk);
  if (sk_vrf) BN_clear_free(sk_vrf);
  if (pk_vrf) EC_POINT_clear_free(pk_vrf);
  if (attestation_cert) X509_free(attestation_cert);
  if (pk) EC_POINT_clear_free(pk);
  if (sig) ECDSA_SIG_free(sig);
  if (bad_msk) BN_clear_free(bad_msk);
  if (bad_sk_vrf) BN_clear_free(bad_sk_vrf);
  EXPECT_TRUE (rv == OKAY);
}

/* Test changing the master public key at the agent. Should cause an error at
 * registration. */
TEST(U2F, BadMpkAtAgent) {
  int rv;
  Params params = NULL;
  Device d = NULL;
  Agent a = NULL;
  BIGNUM *msk = NULL;
  EC_POINT *mpk = NULL;
  BIGNUM *sk_vrf = NULL;
  EC_POINT *pk_vrf = NULL;
  uint8_t app_id[APP_ID_LEN];
  uint8_t key_handle[KEY_HANDLE_LEN];
  X509 *attestation_cert = NULL;;
  EC_POINT *pk = NULL;;
  uint8_t challenge[CHALLENGE_LEN];
  ECDSA_SIG *sig = NULL;;
  uint64_t ctr = 0;
  EC_POINT *bad_mpk = NULL;
  EC_POINT *bad_pk_vrf = NULL;

  CHECK_A (params = Params_new(P256));
  CHECK_A (attestation_cert = X509_new());
  CHECK_C (set_test_cert(params, attestation_cert));
  CHECK_A (d = Device_new(params, attestation_cert));
  CHECK_A (a = Agent_new(params));
  CHECK_A (msk = BN_new());
  CHECK_A (mpk = Params_point_new(params));
  CHECK_A (sk_vrf = BN_new());
  CHECK_A (pk_vrf = Params_point_new(params));
  CHECK_A (pk = Params_point_new(params));
  CHECK_A (sig = ECDSA_SIG_new());
  CHECK_A (bad_mpk = Params_point_new(params));
  CHECK_A (bad_pk_vrf = Params_point_new(params));

  CHECK_C (RAND_bytes(app_id, APP_ID_LEN));
  CHECK_C (RAND_bytes(challenge, CHALLENGE_LEN));
  CHECK_C (Params_rand_point_exp(params, mpk, msk));
  CHECK_C (Params_rand_point_exp(params, pk_vrf, sk_vrf));

  // Deterministic initialization.
  EXPECT_EQ (Agent_initializeDeterministic(a, d, msk, mpk, sk_vrf, pk_vrf), OKAY);

  // Set mpk to random value.
  CHECK_C (Params_rand_point(params, bad_mpk));
  CHECK_C (Params_rand_point(params, bad_pk_vrf));
  CHECK_C (Agent_setPks(a, bad_mpk, bad_pk_vrf));

  // Register.
  EXPECT_EQ (Agent_register(a, d, app_id, pk, key_handle, &attestation_cert),
             ERROR);

cleanup:
  if (params) Params_free(params);
  if (d) Device_free(d);
  if (a) Agent_free(a);
  if (msk) BN_clear_free(msk);
  if (mpk) EC_POINT_clear_free(mpk);
  if (sk_vrf) BN_clear_free(sk_vrf);
  if (pk_vrf) EC_POINT_clear_free(pk_vrf);
  if (attestation_cert) X509_free(attestation_cert);
  if (pk) EC_POINT_clear_free(pk);
  if (sig) ECDSA_SIG_free(sig);
  if (bad_mpk) EC_POINT_clear_free(bad_mpk);
  if (bad_pk_vrf) EC_POINT_clear_free(bad_pk_vrf);
  EXPECT_TRUE (rv == OKAY);
}

/* Set fields in X509 certificate for testing. */
int
set_test_cert(const_Params params, X509 *cert)
{
  int rv = ERROR;
  EVP_PKEY *pk = NULL;
  EC_KEY *key = NULL;

  CHECK_A (pk = EVP_PKEY_new());
  CHECK_A (key = EC_KEY_new());

  CHECK_C (EC_KEY_set_group(key, Params_group(params)));
  CHECK_C (EC_KEY_generate_key(key));
  CHECK_A (EC_KEY_get0_public_key(key));
  CHECK_C (EVP_PKEY_set1_EC_KEY(pk, key));
  CHECK_C (X509_set_pubkey(cert, pk));
  X509_sign(cert, pk, EVP_sha1());

  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 365*24*60*60);

cleanup:
  if (pk) EVP_PKEY_free(pk);
  if (key) EC_KEY_free(key);
  return rv;
}
