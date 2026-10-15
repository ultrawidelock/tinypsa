/* SPDX-License-Identifier: ISC */
/* The shim against tinypsa. */
#include <psa/crypto.h>

#define SHIM(name) tps_##name
#include "shim.inc"
