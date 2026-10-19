/* SPDX-License-Identifier: Apache-2.0 */
#ifndef TINYPSA_INTERNAL_H
#define TINYPSA_INTERNAL_H

#include <psa/crypto.h>
#include <stdbool.h>

#include "backend.h"
#include "port.h"

#if defined(CONFIG_TINYPSA_KEY_SLOTS)
#define TP_KEY_SLOTS CONFIG_TINYPSA_KEY_SLOTS
#elif !defined(TP_KEY_SLOTS)
#define TP_KEY_SLOTS 16
#endif

/* 65 holds an uncompressed P-256 point, the largest key any caller uses. */
#if defined(CONFIG_TINYPSA_KEY_MAX_SIZE)
#define TP_KEY_MAX CONFIG_TINYPSA_KEY_MAX_SIZE
#elif !defined(TP_KEY_MAX)
#define TP_KEY_MAX 65
#endif

#if defined(CONFIG_TINYPSA_DRBG_RESEED_INTERVAL)
#define TP_DRBG_RESEED_INTERVAL CONFIG_TINYPSA_DRBG_RESEED_INTERVAL
#elif !defined(TP_DRBG_RESEED_INTERVAL)
#define TP_DRBG_RESEED_INTERVAL 4096
#endif

#if defined(CONFIG_TINYPSA_PERSISTENT_KEYS)
#define TP_PERSISTENT 1
#elif !defined(TP_PERSISTENT)
#define TP_PERSISTENT 0
#endif

#define TP_P256_PAIR PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)
#define TP_P256_PUB  PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)

/* A key copied out of the table, so no lock is held while it is used. */
struct tp_key {
	psa_key_type_t type;
	psa_key_usage_t usage;
	size_t bits;
	size_t len;
	uint8_t data[TP_KEY_MAX];
};

void tp_wipe(void *p, size_t n);
psa_status_t tp_check_init(void);

/*
 * Copies key id out after checking that its policy grants every bit of
 * usage and permits alg. A wildcard alg is an invalid request; alg 0 skips
 * the policy check, as in Mbed TLS, leaving the caller's own checks to
 * reject it.
 */
psa_status_t tp_key_get(mbedtls_svc_key_id_t id, psa_key_usage_t usage, psa_algorithm_t alg,
			struct tp_key *k);
/* The same with no usage or algorithm to check. */
psa_status_t tp_key_get_any(mbedtls_svc_key_id_t id, struct tp_key *k);

/* The x || y point of a P-256 key pair or public key. */
psa_status_t tp_key_p256_point(const struct tp_key *k, uint8_t pk[64]);

/* Random bytes from the DRBG; psa_crypto_init must have run. */
psa_status_t tp_random(uint8_t *out, size_t len);

/* HMAC_DRBG (SP 800-90A, HMAC-SHA-256), exposed for its known-answer tests. */
struct tp_drbg {
	uint8_t k[32];
	uint8_t v[32];
	uint32_t uses;
};
void tp_drbg_seed(struct tp_drbg *d, const uint8_t *seed, size_t len);
void tp_drbg_reseed(struct tp_drbg *d, const uint8_t *seed, size_t len);
void tp_drbg_generate(struct tp_drbg *d, uint8_t *out, size_t len);

/* AES-CMAC (SP 800-38B), shared by the MAC API and PBKDF2. */
void tp_cmac_start(struct tinypsa_cmac_ctx *c, const uint8_t *key, size_t key_len);
void tp_cmac_update(struct tinypsa_cmac_ctx *c, const uint8_t *in, size_t len);
void tp_cmac_finish(struct tinypsa_cmac_ctx *c, uint8_t tag[16]);
/* K1, the subkey that finishes a message ending on a whole block. */
void tp_cmac_subkey(struct tinypsa_cmac_ctx *c, uint8_t k1[16]);

/* Whether a MAC algorithm suits a key type at all, supported or not. */
bool tp_mac_can_do(psa_algorithm_t alg, psa_key_type_t type);

#endif
