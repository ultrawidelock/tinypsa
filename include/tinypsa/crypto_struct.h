/* SPDX-License-Identifier: ISC */
/*
 * tinypsa's replacement for Mbed TLS's psa/crypto_struct.h, selected through
 * MBEDTLS_PSA_CRYPTO_STRUCT_FILE. Operation objects carry their backend
 * context inline, sized by the backend's tinypsa_backend_ctx.h, so callers
 * own the storage the way the PSA API intends and no pool can run dry.
 *
 * Field names go through MBEDTLS_PRIVATE() where Mbed TLS's own headers
 * reach into them (crypto_extra.h reads policy.alg2), and stay plain where
 * only tinypsa does.
 */
#ifndef TINYPSA_CRYPTO_STRUCT_H
#define TINYPSA_CRYPTO_STRUCT_H

/*
 * Claim Mbed TLS's guard too: the Bluetooth host includes
 * <psa/crypto_struct.h> by name, which must then add nothing.
 */
#define PSA_CRYPTO_STRUCT_H

#include "mbedtls/private_access.h"
#include "psa/build_info.h"
#include "tinypsa_backend_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TINYPSA_STORAGE(size) union { uint64_t align; uint8_t b[size]; }

#define TINYPSA_MAX2(a, b) ((a) > (b) ? (a) : (b))

struct tinypsa_cmac_ctx {
	TINYPSA_STORAGE(TINYPSA_AES_CTX_SIZE) aes;
	uint8_t x[16];
	uint8_t buf[16];
	uint8_t n;
};

struct psa_hash_operation_s {
	psa_algorithm_t alg;
	TINYPSA_STORAGE(TINYPSA_SHA256_CTX_SIZE) ctx;
};
#define PSA_HASH_OPERATION_INIT { 0, { 0 } }
static inline struct psa_hash_operation_s psa_hash_operation_init(void)
{
	const struct psa_hash_operation_s v = PSA_HASH_OPERATION_INIT;
	return v;
}

/* Only one-shot psa_cipher_encrypt() is provided; the type must still exist. */
struct psa_cipher_operation_s {
	psa_algorithm_t alg;
};
#define PSA_CIPHER_OPERATION_INIT { 0 }
static inline struct psa_cipher_operation_s psa_cipher_operation_init(void)
{
	const struct psa_cipher_operation_s v = PSA_CIPHER_OPERATION_INIT;
	return v;
}

struct psa_mac_operation_s {
	psa_algorithm_t alg;
	uint8_t mac_len;
	union {
		uint64_t align;
		uint8_t hmac[TINYPSA_HMAC_SHA256_CTX_SIZE];
		struct tinypsa_cmac_ctx cmac;
	} ctx;
};
#define PSA_MAC_OPERATION_INIT { 0, 0, { 0 } }
static inline struct psa_mac_operation_s psa_mac_operation_init(void)
{
	const struct psa_mac_operation_s v = PSA_MAC_OPERATION_INIT;
	return v;
}

struct psa_aead_operation_s {
	psa_algorithm_t alg;
	uint8_t state;
	uint8_t tag_len;
	uint8_t key_len;
	uint8_t nonce_len;
	uint8_t nonce[13];
	size_t ad_left;
	size_t body_left;
	TINYPSA_STORAGE(TINYPSA_MAX2(TINYPSA_CCM_CTX_SIZE, TINYPSA_GCM_CTX_SIZE)) ctx;
};
#define PSA_AEAD_OPERATION_INIT { 0, 0, 0, 0, 0, { 0 }, 0, 0, { 0 } }
static inline struct psa_aead_operation_s psa_aead_operation_init(void)
{
	const struct psa_aead_operation_s v = PSA_AEAD_OPERATION_INIT;
	return v;
}

#ifndef TINYPSA_KDF_INPUT_MAX
#if defined(CONFIG_TINYPSA_KDF_INPUT_MAX)
#define TINYPSA_KDF_INPUT_MAX CONFIG_TINYPSA_KDF_INPUT_MAX
#else
#define TINYPSA_KDF_INPUT_MAX 64
#endif
#endif

struct psa_key_derivation_s {
	psa_algorithm_t alg;
	uint8_t steps;
	uint8_t blk_used;
	uint8_t salt_len;
	uint8_t info_len;
	uint32_t counter;
	uint32_t cost;
	size_t capacity;
	uint8_t key[32];
	uint8_t blk[32];
	uint8_t buf[TINYPSA_KDF_INPUT_MAX];
};
#define PSA_KEY_DERIVATION_OPERATION_INIT { 0, 0, 0, 0, 0, 0, 0, 0, { 0 }, { 0 }, { 0 } }
static inline struct psa_key_derivation_s psa_key_derivation_operation_init(void)
{
	const struct psa_key_derivation_s v = PSA_KEY_DERIVATION_OPERATION_INIT;
	return v;
}

struct psa_custom_key_parameters_s {
	uint32_t flags;
};
#define PSA_CUSTOM_KEY_PARAMETERS_INIT { 0 }

struct psa_key_production_parameters_s {
	uint32_t flags;
	uint8_t data[];
};
#define PSA_KEY_PRODUCTION_PARAMETERS_INIT { 0 }

struct psa_key_policy_s {
	psa_key_usage_t MBEDTLS_PRIVATE(usage);
	psa_algorithm_t MBEDTLS_PRIVATE(alg);
	psa_algorithm_t MBEDTLS_PRIVATE(alg2);
};
typedef struct psa_key_policy_s psa_key_policy_t;
#define PSA_KEY_POLICY_INIT { 0, 0, 0 }

typedef uint16_t psa_key_bits_t;
#define PSA_KEY_BITS_TOO_LARGE ((psa_key_bits_t)-1)
#define PSA_MAX_KEY_BITS 0xfff8

struct psa_key_attributes_s {
	psa_key_type_t MBEDTLS_PRIVATE(type);
	psa_key_bits_t MBEDTLS_PRIVATE(bits);
	psa_key_lifetime_t MBEDTLS_PRIVATE(lifetime);
	psa_key_policy_t MBEDTLS_PRIVATE(policy);
	mbedtls_svc_key_id_t MBEDTLS_PRIVATE(id);
};
#define PSA_KEY_ATTRIBUTES_INIT \
	{ PSA_KEY_TYPE_NONE, 0, PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_POLICY_INIT, 0 }

static inline struct psa_key_attributes_s psa_key_attributes_init(void)
{
	const struct psa_key_attributes_s v = PSA_KEY_ATTRIBUTES_INIT;
	return v;
}

/* Giving a key an id makes it persistent, keeping its location. */
static inline void psa_set_key_id(psa_key_attributes_t *a, mbedtls_svc_key_id_t key)
{
	psa_key_lifetime_t lifetime = a->MBEDTLS_PRIVATE(lifetime);

	a->MBEDTLS_PRIVATE(id) = key;
	if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
		a->MBEDTLS_PRIVATE(lifetime) = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
			PSA_KEY_LIFETIME_PERSISTENT, PSA_KEY_LIFETIME_GET_LOCATION(lifetime));
	}
}

static inline mbedtls_svc_key_id_t psa_get_key_id(const psa_key_attributes_t *a)
{
	return a->MBEDTLS_PRIVATE(id);
}

/* Making a key volatile drops its id. */
static inline void psa_set_key_lifetime(psa_key_attributes_t *a, psa_key_lifetime_t lifetime)
{
	a->MBEDTLS_PRIVATE(lifetime) = lifetime;
	if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
		a->MBEDTLS_PRIVATE(id) = 0;
	}
}

static inline psa_key_lifetime_t psa_get_key_lifetime(const psa_key_attributes_t *a)
{
	return a->MBEDTLS_PRIVATE(lifetime);
}

/* A hash-signing permission also permits signing the message itself. */
static inline void psa_extend_key_usage_flags(psa_key_usage_t *usage)
{
	if (*usage & PSA_KEY_USAGE_SIGN_HASH) {
		*usage |= PSA_KEY_USAGE_SIGN_MESSAGE;
	}
	if (*usage & PSA_KEY_USAGE_VERIFY_HASH) {
		*usage |= PSA_KEY_USAGE_VERIFY_MESSAGE;
	}
}

static inline void psa_set_key_usage_flags(psa_key_attributes_t *a, psa_key_usage_t usage)
{
	psa_extend_key_usage_flags(&usage);
	a->MBEDTLS_PRIVATE(policy).MBEDTLS_PRIVATE(usage) = usage;
}

static inline psa_key_usage_t psa_get_key_usage_flags(const psa_key_attributes_t *a)
{
	return a->MBEDTLS_PRIVATE(policy).MBEDTLS_PRIVATE(usage);
}

static inline void psa_set_key_algorithm(psa_key_attributes_t *a, psa_algorithm_t alg)
{
	a->MBEDTLS_PRIVATE(policy).MBEDTLS_PRIVATE(alg) = alg;
}

static inline psa_algorithm_t psa_get_key_algorithm(const psa_key_attributes_t *a)
{
	return a->MBEDTLS_PRIVATE(policy).MBEDTLS_PRIVATE(alg);
}

static inline void psa_set_key_type(psa_key_attributes_t *a, psa_key_type_t type)
{
	a->MBEDTLS_PRIVATE(type) = type;
}

static inline psa_key_type_t psa_get_key_type(const psa_key_attributes_t *a)
{
	return a->MBEDTLS_PRIVATE(type);
}

static inline void psa_set_key_bits(psa_key_attributes_t *a, size_t bits)
{
	a->MBEDTLS_PRIVATE(bits) =
		bits > PSA_MAX_KEY_BITS ? PSA_KEY_BITS_TOO_LARGE : (psa_key_bits_t)bits;
}

static inline size_t psa_get_key_bits(const psa_key_attributes_t *a)
{
	return a->MBEDTLS_PRIVATE(bits);
}

/* Interruptible signing is not provided; the types must still exist. */
struct psa_sign_hash_interruptible_operation_s {
	uint32_t unused;
};
#define PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
static inline struct psa_sign_hash_interruptible_operation_s
psa_sign_hash_interruptible_operation_init(void)
{
	const struct psa_sign_hash_interruptible_operation_s v =
		PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT;
	return v;
}

struct psa_verify_hash_interruptible_operation_s {
	uint32_t unused;
};
#define PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
static inline struct psa_verify_hash_interruptible_operation_s
psa_verify_hash_interruptible_operation_init(void)
{
	const struct psa_verify_hash_interruptible_operation_s v =
		PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT;
	return v;
}

#ifdef __cplusplus
}
#endif

#endif /* TINYPSA_CRYPTO_STRUCT_H */
