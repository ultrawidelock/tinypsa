/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/* The compositions in tinypsa/prim.h, over the DRBG and the backend. */
#include <string.h>

#include <tinypsa/prim.h>

#include "internal.h"

int tinypsa_random(uint8_t *out, size_t len)
{
	return tp_random(out, len) == PSA_SUCCESS ? 0 : -1;
}

int tinypsa_p256_keygen(uint8_t sk[32], uint8_t pk[64])
{
	/* Rejection sampling keeps the scalar uniform in [1, n-1]. */
	do {
		if (tinypsa_random(sk, 32)) {
			return -1;
		}
	} while (tp_be_p256_sk_check(sk));
	return tp_be_p256_public_key(pk, sk);
}

int tinypsa_p256_sign_hash(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32])
{
	uint8_t ek[32];
	int ret;

	do {
		ret = tinypsa_random(ek, sizeof(ek));
	} while (!ret && tp_be_p256_sign_hash(sig, hash, sk, ek));
	tp_wipe(ek, sizeof(ek));
	return ret;
}

/*
 * RFC 6979 section 3.2: HMAC_DRBG instantiated with int2octets(x) ||
 * bits2octets(h1). Each draw is one 32-byte output, and the update that
 * ends a generate is the "K = HMAC_K(V || 0x00), V = HMAC_K(V)" of step h.3.
 */
void tinypsa_p256_sign_hash_det(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32])
{
	struct tp_drbg d;
	uint8_t seed[64], k[32];

	memcpy(seed, sk, 32);
	tp_be_p256_reduce(&seed[32], hash, 32);
	tp_drbg_seed(&d, seed, sizeof(seed));
	do {
		tp_drbg_generate(&d, k, sizeof(k));
	} while (tp_be_p256_sign_hash(sig, hash, sk, k));
	tp_wipe(&d, sizeof(d));
	tp_wipe(seed, sizeof(seed));
	tp_wipe(k, sizeof(k));
}
