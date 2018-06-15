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
#include "params.h"

#define NID_P256 714
#define NID_P384 715
#define NID_P521 716

struct params {
  EC_GROUP *group;
};

static int
curve_name_to_nid (CurveName c) 
{
  switch (c) {
    case P256:
      return NID_P256;
    case P384:
      return NID_P384;
    case P521:
      return NID_P521;
  }
  return 0;
}

Params 
Params_new (CurveName c)
{
  Params p = NULL;
  p->group = NULL;

  int nid = curve_name_to_nid (c);
  if (!nid)
    return NULL;

  p = malloc (sizeof *p);
  if (!p)
    return NULL;

  p->group = EC_GROUP_new_by_curve_name (nid);
  if (!p->group) {
    Params_free (p);
    return NULL;
  }

  return p;
}

void 
Params_free (Params p)
{
  if (p->group) 
    EC_GROUP_clear_free (p->group);
  free (p);
}


