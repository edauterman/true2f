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

#include <stdlib.h>
#include "vrf.h"

struct public_key {
  EC_POINT *gx;
};

struct secret_key {
  BIGNUM *x;
};


PublicKey 
PublicKey_new (void)
{
  PublicKey pk = NULL;
  pk = malloc (sizeof *pk);
  if (!pk)
    return NULL;

  return pk;
}

void 
PublicKey_free (PublicKey key)
{
  free (key);
}


SecretKey 
SecretKey_new (void)
{
  SecretKey sk = NULL;
  sk = malloc (sizeof *sk);
  if (!sk)
    return NULL;

  return sk;
}

void 
SecretKey_free (SecretKey key)
{
  free (key);
}
