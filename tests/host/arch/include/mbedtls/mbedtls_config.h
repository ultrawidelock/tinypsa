/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Found ahead of Mbed TLS's own when psa-arch-tests compiles without an
 * MBEDTLS_CONFIG_FILE: it selects tinypsa's configuration instead.
 */
#define TINYPSA_PSA_WANT_FILE "host_psa_want.h"
#include "tinypsa_mbedtls_config.h"
