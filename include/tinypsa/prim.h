/* SPDX-License-Identifier: ISC */
/*
 * tinypsa's primitives without the PSA layer, for code that holds its own
 * key bytes: the backend's operations (tinypsa/backend.h), whose contexts
 * the caller sizes from tinypsa_backend_ctx.h, plus the compositions below.
 * psa_crypto_init must have run once first, to seed the DRBG.
 */
#ifndef TINYPSA_PRIM_H
#define TINYPSA_PRIM_H

#include <stddef.h>
#include <stdint.h>

#include <tinypsa/backend.h>
#include <tinypsa_backend_ctx.h>

/* Functions that return int give 0 on success. */
int tinypsa_random(uint8_t *out, size_t len);

/* A fresh P-256 key pair: sk uniform in [1, n-1], pk = x || y. */
int tinypsa_p256_keygen(uint8_t sk[32], uint8_t pk[64]);

/* ECDSA over a 32-byte hash with a fresh per-signature secret. */
int tinypsa_p256_sign_hash(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32]);

/* ECDSA with the per-signature secret of RFC 6979, HMAC-SHA-256. */
void tinypsa_p256_sign_hash_det(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32]);

#endif
