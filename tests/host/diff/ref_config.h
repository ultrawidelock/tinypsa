/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Mbed TLS for the host: the legacy primitives the test backend wraps, and
 * a full PSA implementation, limited to tinypsa's PSA_WANT set, as the
 * reference the differential test compares against.
 */
#ifndef TINYPSA_DIFF_REF_CONFIG_H
#define TINYPSA_DIFF_REF_CONFIG_H

#include "rename.h"

/* Legacy primitives for the test backend. */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CCM_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CMAC_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDSA_DETERMINISTIC
#define MBEDTLS_ECDH_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

/* The PSA reference, with persistent keys in files under the working directory. */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CONFIG
#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "host_psa_want.h"
#define MBEDTLS_PSA_CRYPTO_STORAGE_C
#define MBEDTLS_PSA_ITS_FILE_C
#define MBEDTLS_FS_IO
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_PLATFORM_C

#endif
