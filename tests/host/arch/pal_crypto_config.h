/* SPDX-License-Identifier: Apache-2.0 */
/* psa-arch-tests feature set for tinypsa: P-256, AES-CCM/GCM/CMAC/ECB, SHA-256, HMAC, HKDF, PBKDF2. */
#ifndef _PAL_CRYPTO_CONFIG_H_
#define _PAL_CRYPTO_CONFIG_H_

#define ARCH_TEST_ECC
#define ARCH_TEST_ECC_CURVE_SECP256R1
#define ARCH_TEST_AES
#define ARCH_TEST_AES_128
#define ARCH_TEST_AES_192
#define ARCH_TEST_AES_256
#define ARCH_TEST_RAW
#define ARCH_TEST_HASH
#define ARCH_TEST_HMAC
#define ARCH_TEST_SHA256
#define ARCH_TEST_HKDF
#define ARCH_TEST_CMAC
#define ARCH_TEST_CCM
#define ARCH_TEST_GCM
#define ARCH_TEST_TRUNCATED_MAC
#define ARCH_TEST_ECDH
#define ARCH_TEST_ECDSA
#define ARCH_TEST_DETERMINISTIC_ECDSA
#define ARCH_TEST_PBKDF2

#include "pal_crypto_config_check.h"

#endif
