/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * MBEDTLS_CONFIG_FILE for tinypsa: Mbed TLS supplies only the public PSA
 * headers, viewed in client mode, with tinypsa's own operation structs.
 */
#ifndef TINYPSA_MBEDTLS_CONFIG_H
#define TINYPSA_MBEDTLS_CONFIG_H

#define MBEDTLS_PSA_CRYPTO_CLIENT
#define MBEDTLS_PSA_CRYPTO_CONFIG
#ifndef TINYPSA_PSA_WANT_FILE
#define TINYPSA_PSA_WANT_FILE "config-psa.h"
#endif
#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE TINYPSA_PSA_WANT_FILE
#define MBEDTLS_PSA_CRYPTO_STRUCT_FILE "tinypsa/crypto_struct.h"
#define MBEDTLS_ASN1_PARSE_C
/* No deprecated compatibility API: nothing here calls it. */
#define MBEDTLS_DEPRECATED_REMOVED

#endif
