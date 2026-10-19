/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The key table, key policy, and key management. Keys live in a fixed array
 * of slots. Operations copy a key out under the lock and compute without it,
 * so a slow signature never blocks another thread's lookup. Persistent keys
 * are written through to the port's store and cached in slots, from which
 * they can be evicted at any time.
 */
#include <string.h>

#include "internal.h"

struct slot {
	psa_key_id_t id; /* 0: free */
	psa_key_lifetime_t lifetime;
	psa_key_usage_t usage;
	psa_algorithm_t alg;
	psa_key_type_t type;
	psa_key_bits_t bits;
	uint8_t len;
	uint8_t data[TP_KEY_MAX];
};

_Static_assert(TP_KEY_MAX <= 255, "slot length is one byte");

static struct slot slots[TP_KEY_SLOTS];
static psa_key_id_t next_volatile = PSA_KEY_ID_VENDOR_MIN;

void tp_wipe(void *p, size_t n)
{
	volatile uint8_t *b = p;

	while (n--) {
		*b++ = 0;
	}
}

static bool is_user_id(psa_key_id_t id)
{
	return id >= PSA_KEY_ID_USER_MIN && id <= PSA_KEY_ID_USER_MAX;
}

static struct slot *find(psa_key_id_t id)
{
	for (size_t i = 0; i < TP_KEY_SLOTS; i++) {
		if (id != 0 && slots[i].id == id) {
			return &slots[i];
		}
	}
	return NULL;
}

/* A free slot, else a persistent key's cached copy, which the store still holds. */
static struct slot *alloc(void)
{
	struct slot *cached = NULL;

	for (size_t i = 0; i < TP_KEY_SLOTS; i++) {
		if (slots[i].id == 0) {
			return &slots[i];
		}
		if (!cached && !PSA_KEY_LIFETIME_IS_VOLATILE(slots[i].lifetime)) {
			cached = &slots[i];
		}
	}
	if (cached) {
		tp_wipe(cached, sizeof(*cached));
	}
	return cached;
}

/* ---- persistent records --------------------------------------------------
 * version, len, type (2), bits (2), lifetime (4), usage (4), alg (4), data.
 * Little-endian. Version bumps when the layout changes.
 */
#define REC_VERSION 1
#define REC_HEADER  18

#if TP_PERSISTENT
static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

static uint32_t get32(const uint8_t *p)
{
	return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static psa_status_t store(const struct slot *s)
{
	uint8_t rec[REC_HEADER + TP_KEY_MAX];
	int err;

	rec[0] = REC_VERSION;
	rec[1] = s->len;
	rec[2] = s->type;
	rec[3] = s->type >> 8;
	rec[4] = s->bits;
	rec[5] = s->bits >> 8;
	put32(&rec[6], s->lifetime);
	put32(&rec[10], s->usage);
	put32(&rec[14], s->alg);
	memcpy(&rec[REC_HEADER], s->data, s->len);
	err = tp_store_write(s->id, rec, REC_HEADER + s->len);
	tp_wipe(rec, sizeof(rec));
	return err ? PSA_ERROR_STORAGE_FAILURE : PSA_SUCCESS;
}

/* Loads persistent key id into a slot. Lock held. */
static psa_status_t load(psa_key_id_t id, struct slot **out)
{
	uint8_t rec[REC_HEADER + TP_KEY_MAX];
	struct slot *s;
	int n;

	n = tp_store_read(id, rec, sizeof(rec));
	if (n == -1) {
		return PSA_ERROR_INVALID_HANDLE;
	}
	if (n < REC_HEADER || rec[0] != REC_VERSION || n != REC_HEADER + rec[1]) {
		tp_wipe(rec, sizeof(rec));
		return n < 0 ? PSA_ERROR_STORAGE_FAILURE : PSA_ERROR_DATA_CORRUPT;
	}
	s = alloc();
	if (!s) {
		tp_wipe(rec, sizeof(rec));
		return PSA_ERROR_INSUFFICIENT_MEMORY;
	}
	s->id = id;
	s->len = rec[1];
	s->type = rec[2] | rec[3] << 8;
	s->bits = rec[4] | rec[5] << 8;
	s->lifetime = get32(&rec[6]);
	s->usage = get32(&rec[10]);
	s->alg = get32(&rec[14]);
	memcpy(s->data, &rec[REC_HEADER], s->len);
	tp_wipe(rec, sizeof(rec));
	*out = s;
	return PSA_SUCCESS;
}

static bool stored(psa_key_id_t id)
{
	uint8_t rec[REC_HEADER + TP_KEY_MAX];
	int n = tp_store_read(id, rec, sizeof(rec));

	tp_wipe(rec, sizeof(rec));
	return n != -1;
}
#endif /* TP_PERSISTENT */

/* The slot holding id, loading it from the store if needed. Lock held. */
static psa_status_t lookup(mbedtls_svc_key_id_t id, struct slot **out)
{
	*out = find(id);
	if (*out) {
		return PSA_SUCCESS;
	}
#if TP_PERSISTENT
	if (is_user_id(id)) {
		return load(id, out);
	}
#endif
	return PSA_ERROR_INVALID_HANDLE;
}

/* ---- policy ---------------------------------------------------------------- */

bool tp_mac_can_do(psa_algorithm_t alg, psa_key_type_t type)
{
	if (PSA_ALG_IS_HMAC(alg)) {
		return type == PSA_KEY_TYPE_HMAC;
	}
	/* Block-cipher MACs need a block cipher: a symmetric type with blocks over a byte. */
	return PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) &&
	       (type & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_SYMMETRIC &&
	       PSA_BLOCK_CIPHER_BLOCK_LENGTH(type) > 1;
}

static bool alg_permits(psa_key_type_t type, psa_algorithm_t policy, psa_algorithm_t req)
{
	if (req == policy) {
		return true;
	}
	/* A hash-and-sign policy with a wildcard hash permits any hash. */
	if (PSA_ALG_IS_SIGN_HASH(req) && PSA_ALG_SIGN_GET_HASH(policy) == PSA_ALG_ANY_HASH) {
		return (policy & ~PSA_ALG_HASH_MASK) == (req & ~PSA_ALG_HASH_MASK);
	}
	/* An at-least-this-length AEAD policy permits longer tags. */
	if (PSA_ALG_IS_AEAD(policy) && PSA_ALG_IS_AEAD(req) &&
	    PSA_ALG_AEAD_WITH_SHORTENED_TAG(policy, 0) == PSA_ALG_AEAD_WITH_SHORTENED_TAG(req, 0) &&
	    (policy & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG)) {
		return PSA_ALG_AEAD_GET_TAG_LENGTH(policy) <= PSA_ALG_AEAD_GET_TAG_LENGTH(req);
	}
	/* MACs of one base: compare the lengths each one actually produces. */
	if (PSA_ALG_IS_MAC(policy) && PSA_ALG_IS_MAC(req) &&
	    PSA_ALG_FULL_LENGTH_MAC(policy) == PSA_ALG_FULL_LENGTH_MAC(req)) {
		size_t full = PSA_MAC_LENGTH(type, 0, PSA_ALG_FULL_LENGTH_MAC(req));
		size_t pol = PSA_MAC_TRUNCATED_LENGTH(policy);
		size_t want = PSA_MAC_LENGTH(type, 0, req);

		if (!tp_mac_can_do(policy, type)) {
			return false;
		}
		if (pol == 0) {
			return want == full;
		}
		if (PSA_MAC_TRUNCATED_LENGTH(req) == 0 && pol == full) {
			return true;
		}
		if (policy & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) {
			return pol <= want;
		}
		return false;
	}
	/* A raw key agreement policy permits that agreement feeding a KDF. */
	if (PSA_ALG_IS_RAW_KEY_AGREEMENT(policy) && PSA_ALG_IS_KEY_AGREEMENT(req)) {
		return PSA_ALG_KEY_AGREEMENT_GET_BASE(req) == policy;
	}
	return false;
}

static psa_status_t get(mbedtls_svc_key_id_t id, psa_key_usage_t usage, psa_algorithm_t alg,
			bool check_alg, struct tp_key *k)
{
	struct slot *s;
	psa_status_t st;

	st = tp_check_init();
	if (st != PSA_SUCCESS) {
		return st;
	}
	tp_port_lock();
	st = lookup(id, &s);
	if (st == PSA_SUCCESS && (s->usage & usage) != usage) {
		st = PSA_ERROR_NOT_PERMITTED;
	}
	if (st == PSA_SUCCESS && check_alg) {
		if (alg == 0) {
			/* nothing to check */
		} else if (PSA_ALG_IS_WILDCARD(alg)) {
			st = PSA_ERROR_INVALID_ARGUMENT;
		} else if (!alg_permits(s->type, s->alg, alg)) {
			st = PSA_ERROR_NOT_PERMITTED;
		}
	}
	if (st == PSA_SUCCESS) {
		k->type = s->type;
		k->bits = s->bits;
		k->usage = s->usage;
		k->len = s->len;
		memcpy(k->data, s->data, s->len);
	}
	tp_port_unlock();
	return st;
}

psa_status_t tp_key_get(mbedtls_svc_key_id_t id, psa_key_usage_t usage, psa_algorithm_t alg,
			struct tp_key *k)
{
	return get(id, usage, alg, true, k);
}

psa_status_t tp_key_get_any(mbedtls_svc_key_id_t id, struct tp_key *k)
{
	return get(id, 0, 0, false, k);
}

psa_status_t tp_key_p256_point(const struct tp_key *k, uint8_t pk[64])
{
	if (k->type == TP_P256_PAIR) {
		return tp_be_p256_public_key(pk, k->data) ? PSA_ERROR_CORRUPTION_DETECTED
							  : PSA_SUCCESS;
	}
	if (k->type == TP_P256_PUB) {
		memcpy(pk, &k->data[1], 64);
		return PSA_SUCCESS;
	}
	return PSA_ERROR_INVALID_ARGUMENT;
}

/* ---- key creation ------------------------------------------------------------ */

static psa_status_t check_lifetime(const psa_key_attributes_t *a)
{
	psa_key_lifetime_t lifetime = psa_get_key_lifetime(a);
	psa_key_id_t id = psa_get_key_id(a);

	if (PSA_KEY_LIFETIME_GET_LOCATION(lifetime) != PSA_KEY_LOCATION_LOCAL_STORAGE) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
		return id == 0 ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
	}
	if (!TP_PERSISTENT) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	if (PSA_KEY_LIFETIME_IS_READ_ONLY(lifetime) || !is_user_id(id)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return PSA_SUCCESS;
}

/* A private scalar must lie in [1, n-1]. Zero is ruled out here because not
 * every backend's check does (ocrypto accepts it). */
static bool p256_sk_valid(const uint8_t sk[32])
{
	uint8_t any = 0;

	for (size_t i = 0; i < 32; i++) {
		any |= sk[i];
	}
	return any != 0 && tp_be_p256_sk_check(sk) == 0;
}

/*
 * Curve sizes PSA names for each family, in bits. A size outside this list
 * is malformed; a listed one tinypsa lacks is merely unsupported.
 */
static bool ecc_size_known(psa_ecc_family_t family, size_t *bits)
{
	switch (family) {
	case PSA_ECC_FAMILY_SECP_R1:
		if (*bits == 528) {
			*bits = 521;
		}
		return *bits == 192 || *bits == 224 || *bits == 256 || *bits == 384 ||
		       *bits == 521;
	case PSA_ECC_FAMILY_SECP_K1:
		return *bits == 192 || *bits == 256;
	case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
		return *bits == 160 || *bits == 192 || *bits == 224 || *bits == 256 ||
		       *bits == 320 || *bits == 384 || *bits == 512;
	case PSA_ECC_FAMILY_MONTGOMERY:
		if (*bits == 256) {
			*bits = 255;
		}
		return *bits == 255 || *bits == 448;
	default:
		return false;
	}
}

/* ECC material: a big-endian scalar, or 0x04 || x || y for a Weierstrass public key. */
static psa_status_t check_ecc(psa_key_type_t type, const uint8_t *data, size_t len,
			      size_t want_bits, size_t *bits)
{
	psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(type);
	bool pub = PSA_KEY_TYPE_IS_PUBLIC_KEY(type);
	size_t curve_bytes = len;

	if (pub && family != PSA_ECC_FAMILY_MONTGOMERY) {
		if (len % 2 == 0) {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
		curve_bytes = len / 2;
	}
	if (want_bits && curve_bytes != PSA_BITS_TO_BYTES(want_bits)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	*bits = want_bits ? want_bits : 8 * curve_bytes;
	if (!ecc_size_known(family, bits)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (family != PSA_ECC_FAMILY_SECP_R1 || *bits != 256) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	if (!pub) {
		return p256_sk_valid(data) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
	}
	/* At this length only the uncompressed form 0x04 || x || y is well formed. */
	if (data[0] != 0x04 || tp_be_p256_pk_check(&data[1])) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return PSA_SUCCESS;
}

/* Checks material against its type; sets *bits from the material. */
static psa_status_t check_material(psa_key_type_t type, const uint8_t *data, size_t len,
				   size_t want_bits, size_t *bits)
{
	if (len == 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (PSA_KEY_TYPE_IS_ECC(type)) {
		return check_ecc(type, data, len, want_bits, bits);
	}
	switch (type) {
	case PSA_KEY_TYPE_AES:
		if (len != 16 && len != 24 && len != 32) {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
		break;
	case PSA_KEY_TYPE_HMAC:
	case PSA_KEY_TYPE_RAW_DATA:
	case PSA_KEY_TYPE_DERIVE:
	case PSA_KEY_TYPE_PASSWORD:
	case PSA_KEY_TYPE_PASSWORD_HASH:
		break;
	default:
		return PSA_ERROR_NOT_SUPPORTED;
	}
	*bits = 8 * len;
	if (want_bits && want_bits != *bits) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	return len > TP_KEY_MAX ? PSA_ERROR_NOT_SUPPORTED : PSA_SUCCESS;
}

static psa_status_t create(const psa_key_attributes_t *a, const uint8_t *data, size_t len,
			   size_t bits, mbedtls_svc_key_id_t *key)
{
	psa_key_lifetime_t lifetime = psa_get_key_lifetime(a);
	psa_key_id_t id = psa_get_key_id(a);
	psa_status_t st = PSA_SUCCESS;
	struct slot *s;

	tp_port_lock();
	if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
		do {
			id = next_volatile;
			next_volatile = id == PSA_KEY_ID_VENDOR_MAX ? PSA_KEY_ID_VENDOR_MIN : id + 1;
		} while (find(id));
	} else if (find(id)) {
		st = PSA_ERROR_ALREADY_EXISTS;
	}
#if TP_PERSISTENT
	else if (stored(id)) {
		st = PSA_ERROR_ALREADY_EXISTS;
	}
#endif
	s = st == PSA_SUCCESS ? alloc() : NULL;
	if (st == PSA_SUCCESS && !s) {
		st = PSA_ERROR_INSUFFICIENT_MEMORY;
	}
	if (st == PSA_SUCCESS) {
		s->id = id;
		s->lifetime = lifetime;
		s->usage = psa_get_key_usage_flags(a);
		s->alg = psa_get_key_algorithm(a);
		s->type = psa_get_key_type(a);
		s->bits = bits;
		s->len = len;
		memcpy(s->data, data, len);
#if TP_PERSISTENT
		if (!PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
			st = store(s);
			if (st != PSA_SUCCESS) {
				tp_wipe(s, sizeof(*s));
			}
		}
#endif
	}
	tp_port_unlock();
	*key = st == PSA_SUCCESS ? id : 0;
	return st;
}

#define USAGE_ALL                                                                         \
	(PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_ENCRYPT |               \
	 PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | \
	 PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_DERIVE |       \
	 PSA_KEY_USAGE_VERIFY_DERIVATION)

static psa_status_t check_attributes(const psa_key_attributes_t *a)
{
	psa_status_t st = check_lifetime(a);

	if (st != PSA_SUCCESS) {
		return st;
	}
	if (psa_get_key_usage_flags(a) & ~USAGE_ALL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_get_key_bits(a) > PSA_MAX_KEY_BITS ||
	    psa_get_key_enrollment_algorithm(a) != 0) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	return PSA_SUCCESS;
}

psa_status_t psa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data,
			    size_t data_length, mbedtls_svc_key_id_t *key)
{
	size_t bits = 0;
	psa_status_t st;

	*key = 0;
	st = tp_check_init();
	if (st == PSA_SUCCESS && data_length == 0) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	}
	if (st == PSA_SUCCESS) {
		st = check_attributes(attributes);
	}
	if (st == PSA_SUCCESS) {
		st = check_material(psa_get_key_type(attributes), data, data_length,
				    psa_get_key_bits(attributes), &bits);
	}
	if (st == PSA_SUCCESS && psa_get_key_bits(attributes) != 0 &&
	    psa_get_key_bits(attributes) != bits) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	}
	if (st == PSA_SUCCESS) {
		st = create(attributes, data, data_length, bits, key);
	}
	return st;
}

psa_status_t psa_generate_key(const psa_key_attributes_t *attributes, mbedtls_svc_key_id_t *key)
{
	psa_key_type_t type = psa_get_key_type(attributes);
	size_t bits = psa_get_key_bits(attributes);
	uint8_t buf[TP_KEY_MAX];
	size_t len = bits / 8;
	psa_status_t st;

	*key = 0;
	st = tp_check_init();
	if (st != PSA_SUCCESS) {
		return st;
	}
	if (bits == 0 || PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	st = check_attributes(attributes);
	if (st != PSA_SUCCESS) {
		return st;
	}
	switch (type) {
	case PSA_KEY_TYPE_AES:
		if (bits != 128 && bits != 192 && bits != 256) {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
		break;
	case PSA_KEY_TYPE_HMAC:
	case PSA_KEY_TYPE_RAW_DATA:
	case PSA_KEY_TYPE_DERIVE:
	case PSA_KEY_TYPE_PASSWORD:
	case PSA_KEY_TYPE_PASSWORD_HASH:
		if (bits % 8) {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
		if (len > sizeof(buf)) {
			return PSA_ERROR_NOT_SUPPORTED; /* larger than a slot */
		}
		break;
	case TP_P256_PAIR:
		if (bits != 256) {
			return PSA_ERROR_NOT_SUPPORTED;
		}
		break;
	default:
		return PSA_ERROR_NOT_SUPPORTED;
	}
	/* Rejection sampling keeps the scalar uniform in [1, n-1]. */
	do {
		st = tp_random(buf, len);
	} while (st == PSA_SUCCESS && type == TP_P256_PAIR && !p256_sk_valid(buf));
	if (st == PSA_SUCCESS) {
		st = create(attributes, buf, len, bits, key);
	}
	tp_wipe(buf, sizeof(buf));
	return st;
}

/* ---- key use ---------------------------------------------------------------- */

psa_status_t psa_export_key(mbedtls_svc_key_id_t key, uint8_t *data, size_t data_size,
			    size_t *data_length)
{
	struct tp_key k;
	psa_status_t st;

	*data_length = 0;
	if (data_size == 0) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}
	st = tp_key_get_any(key, &k);
	/* Public keys are always exportable; everything else needs EXPORT. */
	if (st == PSA_SUCCESS && !PSA_KEY_TYPE_IS_PUBLIC_KEY(k.type) &&
	    !(k.usage & PSA_KEY_USAGE_EXPORT)) {
		st = PSA_ERROR_NOT_PERMITTED;
	}
	if (st == PSA_SUCCESS && data_size < k.len) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	}
	if (st == PSA_SUCCESS) {
		memcpy(data, k.data, k.len);
		*data_length = k.len;
	}
	tp_wipe(&k, sizeof(k));
	return st;
}

psa_status_t psa_export_public_key(mbedtls_svc_key_id_t key, uint8_t *data, size_t data_size,
				   size_t *data_length)
{
	struct tp_key k;
	psa_status_t st;

	*data_length = 0;
	if (data_size == 0) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}
	st = tp_key_get_any(key, &k);
	if (st == PSA_SUCCESS && !PSA_KEY_TYPE_IS_ASYMMETRIC(k.type)) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	}
	if (st == PSA_SUCCESS && data_size < 65) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	}
	if (st == PSA_SUCCESS) {
		st = tp_key_p256_point(&k, &data[1]);
	}
	if (st == PSA_SUCCESS) {
		data[0] = 0x04;
		*data_length = 65;
	}
	tp_wipe(&k, sizeof(k));
	return st;
}

psa_status_t psa_destroy_key(mbedtls_svc_key_id_t key)
{
	psa_status_t st = PSA_SUCCESS;
	struct slot *s;

	if (key == 0) {
		return PSA_SUCCESS;
	}
	st = tp_check_init();
	if (st != PSA_SUCCESS) {
		return st;
	}
	tp_port_lock();
	s = find(key);
	if (!s) {
		st = PSA_ERROR_INVALID_HANDLE;
	}
#if TP_PERSISTENT
	/* A persistent key need not be cached to be destroyed. */
	if (!s && is_user_id(key) && stored(key)) {
		st = PSA_SUCCESS;
	}
	if (st == PSA_SUCCESS && is_user_id(key) && tp_store_erase(key)) {
		st = PSA_ERROR_STORAGE_FAILURE;
	}
#endif
	if (st == PSA_SUCCESS && s) {
		tp_wipe(s, sizeof(*s));
	}
	tp_port_unlock();
	return st;
}

psa_status_t psa_get_key_attributes(mbedtls_svc_key_id_t key, psa_key_attributes_t *attributes)
{
	struct slot *s;
	psa_status_t st;

	psa_reset_key_attributes(attributes);
	st = tp_check_init();
	if (st != PSA_SUCCESS) {
		return st;
	}
	tp_port_lock();
	st = lookup(key, &s);
	if (st == PSA_SUCCESS) {
		psa_set_key_type(attributes, s->type);
		psa_set_key_bits(attributes, s->bits);
		psa_set_key_lifetime(attributes, s->lifetime);
		psa_set_key_usage_flags(attributes, s->usage);
		psa_set_key_algorithm(attributes, s->alg);
		attributes->MBEDTLS_PRIVATE(id) = s->id;
	}
	tp_port_unlock();
	return st;
}

void psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
	*attributes = psa_key_attributes_init();
}
