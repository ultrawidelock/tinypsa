/* SPDX-License-Identifier: Apache-2.0 */
/* The shim against Mbed TLS, whose entry points rename.h moved to ref_psa_*. */
#include <psa/crypto.h>

#define SHIM(name) ref_##name
#include "shim.inc"
