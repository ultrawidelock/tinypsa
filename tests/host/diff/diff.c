/* SPDX-License-Identifier: ISC */
/*
 * Differential test: random call sequences against tinypsa and Mbed TLS 3.6
 * PSA, comparing every status and every deterministic output.
 *
 *   tinypsa_diff [seed] [steps]
 *
 * Keys are created in both. A generated key cannot match across the two, so
 * when it is exportable its material is copied into the reference, and when
 * it is not, only statuses are compared for it. Divergences tinypsa makes on
 * purpose are listed in allowed() with their reason.
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Values only: the PSA macros without either implementation's structs. */
#include <psa/crypto_types.h>
#include <psa/crypto_values.h>
#include <psa/crypto_sizes.h>

#include "shim.h"

#define KEYS     10
#define BUF      320
#define KEY_MAX  65 /* tinypsa's default TP_KEY_MAX */
#define KDF_MAX  64 /* tinypsa's default TINYPSA_KDF_INPUT_MAX */

static uint64_t rng_state;
static long step_no, mismatches, compared;
static const char *op_name;

static uint32_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return (uint32_t)(rng_state >> 16);
}

static uint32_t below(uint32_t n)
{
	return n ? rnd() % n : 0;
}

static bool chance(int percent)
{
	return below(100) < (uint32_t)percent;
}

#define PICK(arr) ((arr)[below(sizeof(arr) / sizeof((arr)[0]))])

static void fill(uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		b[i] = rnd();
	}
}

/* Lengths biased to the edges that break things. */
static size_t rlen(size_t max)
{
	static const size_t edges[] = { 0, 1, 4, 7, 8, 12, 13, 15, 16, 17, 31, 32, 33, 48, 64, 65 };
	size_t n = chance(60) ? PICK(edges) : below(max + 1);

	return n > max ? max : n;
}

/* ---- the vocabulary --------------------------------------------------------- */

static uint32_t r_alg(void)
{
	static const uint32_t algs[] = {
		0,
		PSA_ALG_SHA_256,
		PSA_ALG_SHA_1,
		PSA_ALG_HMAC(PSA_ALG_SHA_256),
		PSA_ALG_HMAC(PSA_ALG_SHA_1),
		PSA_ALG_CMAC,
		PSA_ALG_CBC_MAC,
		PSA_ALG_ECB_NO_PADDING,
		PSA_ALG_CBC_NO_PADDING,
		PSA_ALG_CTR,
		PSA_ALG_CCM,
		PSA_ALG_GCM,
		PSA_ALG_CHACHA20_POLY1305,
		PSA_ALG_ECDSA(PSA_ALG_SHA_256),
		PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
		PSA_ALG_ECDSA_ANY,
		PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
		PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_ANY_HASH),
		PSA_ALG_ECDSA(PSA_ALG_SHA_1),
		PSA_ALG_ECDH,
		PSA_ALG_FFDH,
		PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256)),
		PSA_ALG_HKDF(PSA_ALG_SHA_256),
		PSA_ALG_HKDF(PSA_ALG_SHA_1),
		PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256),
		PSA_ALG_PBKDF2_AES_CMAC_PRF_128,
		PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
	};
	uint32_t a = PICK(algs);

	if (PSA_ALG_IS_MAC(a) && chance(30)) {
		a = chance(50) ? PSA_ALG_TRUNCATED_MAC(a, below(34))
			       : PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(a, below(34));
	} else if (PSA_ALG_IS_AEAD(a) && chance(40)) {
		a = chance(70) ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(a, below(18))
			       : PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(a, below(18));
	}
	return chance(2) ? rnd() : a;
}

static uint16_t r_type(void)
{
	static const uint16_t types[] = {
		PSA_KEY_TYPE_AES,
		PSA_KEY_TYPE_AES,
		PSA_KEY_TYPE_HMAC,
		PSA_KEY_TYPE_RAW_DATA,
		PSA_KEY_TYPE_DERIVE,
		PSA_KEY_TYPE_PASSWORD,
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
		PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1),
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1),
		PSA_KEY_TYPE_CHACHA20,
		PSA_KEY_TYPE_NONE,
	};

	return PICK(types);
}

static uint32_t r_usage(void)
{
	static const uint32_t bits[] = {
		PSA_KEY_USAGE_EXPORT,       PSA_KEY_USAGE_COPY,         PSA_KEY_USAGE_ENCRYPT,
		PSA_KEY_USAGE_DECRYPT,      PSA_KEY_USAGE_SIGN_MESSAGE, PSA_KEY_USAGE_VERIFY_MESSAGE,
		PSA_KEY_USAGE_SIGN_HASH,    PSA_KEY_USAGE_VERIFY_HASH,  PSA_KEY_USAGE_DERIVE,
		PSA_KEY_USAGE_VERIFY_DERIVATION,
	};
	uint32_t u = 0;

	for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
		if (chance(45)) {
			u |= bits[i];
		}
	}
	return u;
}

struct pair {
	bool live;
	bool synced; /* identical material in both */
	uint32_t tp, ref;
	struct dkey attr;
};

static struct pair keys[KEYS];
static uint8_t last_pub[65]; /* a valid P-256 point for agreement and import */
static bool have_pub;

/* Attribute triples the callers actually use, so success paths get exercised. */
static void coherent(struct dkey *a)
{
	static const struct {
		uint16_t type, bits;
		uint32_t usage, alg;
	} combos[] = {
		{ PSA_KEY_TYPE_AES, 128, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, PSA_ALG_CCM },
		{ PSA_KEY_TYPE_AES, 128, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT,
		  PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8) },
		{ PSA_KEY_TYPE_AES, 256, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, PSA_ALG_GCM },
		{ PSA_KEY_TYPE_AES, 256, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT,
		  PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_GCM, 12) },
		{ PSA_KEY_TYPE_AES, 128, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_ECB_NO_PADDING },
		{ PSA_KEY_TYPE_AES, 128, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE,
		  PSA_ALG_CMAC },
		{ PSA_KEY_TYPE_HMAC, 0, PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_HMAC(PSA_ALG_SHA_256) },
		{ PSA_KEY_TYPE_HMAC, 0, PSA_KEY_USAGE_SIGN_HASH,
		  PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16) },
		{ PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
		  PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
		  PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256) },
		{ PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
		  PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE,
		  PSA_ALG_ECDSA(PSA_ALG_SHA_256) },
		{ PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
		  PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH,
		  PSA_ALG_ECDSA(PSA_ALG_ANY_HASH) },
		{ PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
		  PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT, PSA_ALG_ECDH },
		{ PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1), 256,
		  PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE,
		  PSA_ALG_ECDSA(PSA_ALG_SHA_256) },
		{ PSA_KEY_TYPE_PASSWORD, 0, PSA_KEY_USAGE_DERIVE, PSA_ALG_PBKDF2_AES_CMAC_PRF_128 },
		{ PSA_KEY_TYPE_DERIVE, 0, PSA_KEY_USAGE_DERIVE, PSA_ALG_HKDF(PSA_ALG_SHA_256) },
		{ PSA_KEY_TYPE_RAW_DATA, 0, PSA_KEY_USAGE_DERIVE, PSA_ALG_HKDF(PSA_ALG_SHA_256) },
	};
	int i = below(sizeof(combos) / sizeof(combos[0]));

	a->type = combos[i].type;
	a->bits = combos[i].bits;
	a->usage = combos[i].usage;
	a->alg = combos[i].alg;
}

/* A live key whose type passes test, else any slot. */
static struct pair *key_where(bool (*test)(uint16_t type))
{
	int start = below(KEYS);

	if (chance(80)) {
		for (int i = 0; i < KEYS; i++) {
			struct pair *k = &keys[(start + i) % KEYS];

			if (k->live && test(k->attr.type)) {
				return k;
			}
		}
	}
	return &keys[below(KEYS)];
}

static bool is_aes(uint16_t t)
{
	return t == PSA_KEY_TYPE_AES;
}

static bool is_mac_key(uint16_t t)
{
	return t == PSA_KEY_TYPE_AES || t == PSA_KEY_TYPE_HMAC;
}

static bool is_ecc(uint16_t t)
{
	return PSA_KEY_TYPE_IS_ECC(t);
}

static bool is_pair(uint16_t t)
{
	return t == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
}

static bool is_kdf_key(uint16_t t)
{
	return t == PSA_KEY_TYPE_DERIVE || t == PSA_KEY_TYPE_PASSWORD || t == PSA_KEY_TYPE_RAW_DATA;
}

static const uint8_t p256_n[32] = {
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};

/* ---- keys ------------------------------------------------------------------- */


static int verbose = 40; /* mismatches printed in full */
static char desc[240];    /* the current call's parameters */
static const char *sub = ""; /* which call within an op */

#define DESC(...) snprintf(desc, sizeof(desc), __VA_ARGS__)

static void mismatch(const char *what, int32_t tp, int32_t ref)
{
	mismatches++;
	if (verbose < 0) {
		printf("M %s%s %s %" PRId32 " %" PRId32 " | %s\n", op_name, sub, what, tp, ref, desc);
	} else if (mismatches <= verbose) {
		printf("step %ld %s: %s tp=%" PRId32 " ref=%" PRId32 " | %s\n", step_no, op_name,
		       what, tp, ref, desc);
	}
}

/*
 * Divergences tinypsa makes on purpose are handled where they arise, each
 * with its reason, by by_design(): the reference is put back in step and
 * the call is counted, not compared.
 */
static long by_design_count;

static bool by_design(bool cond)
{
	by_design_count += cond;
	return cond;
}

/* Whether each multipart slot was set up with a key both sides hold identically. */
static bool mac_synced[N_OPS], aead_synced[N_OPS], kdf_synced[N_OPS];

static long ok_count[16];
static int op_index;

static void cmp_status(int32_t tp, int32_t ref)
{
	compared++;
	ok_count[op_index] += tp == 0 && ref == 0;
	if (tp != ref) {
		mismatch("status", tp, ref);
	}
}

static void cmp_bytes(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
	compared++;
	if (an != bn || memcmp(a, b, an)) {
		mismatch("output", (int32_t)an, (int32_t)bn);
	}
}

static struct pair *any_key(void)
{
	struct pair *k = &keys[below(KEYS)];

	return k;
}

/* A dead slot names the same missing key in both: 0 or a never-issued id. */
static uint32_t tps_id(const struct pair *k)
{
	size_t i = k - keys;

	return k->live ? k->tp : (i % 2 ? 0 : 0x7fff0000u + (uint32_t)i);
}

static uint32_t ref_id(const struct pair *k)
{
	return k->live ? k->ref : tps_id(k);
}

static void drop(struct pair *k)
{
	if (k->live) {
		tps_destroy(k->tp);
		ref_destroy(k->ref);
	}
	memset(k, 0, sizeof(*k));
}

static size_t key_material(const struct dkey *a, uint8_t *d)
{
	switch (a->type) {
	case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
		if (chance(90)) {
			fill(d, 32);
			d[0] &= 0x7f; /* below n */
			if (chance(5)) {
				memset(d, 0, 32);
			}
			return 32;
		}
		if (chance(50)) {
			memcpy(d, p256_n, 32);
			return 32;
		}
		break;
	case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
		if (have_pub && chance(85)) {
			memcpy(d, last_pub, 65);
			if (chance(10)) {
				d[1 + below(64)] ^= 1;
			}
			return 65;
		}
		break;
	case PSA_KEY_TYPE_AES:
		if (chance(85)) {
			size_t n = a->bits ? a->bits / 8 : 16 + 8 * below(3);

			fill(d, n);
			return n;
		}
		break;
	default:
		break;
	}
	size_t n = rlen(80);

	fill(d, n);
	return n;
}

static void op_import(void)
{
	struct pair *k = any_key();
	struct dkey a = { r_type(), 0, r_usage(), r_alg(), PSA_KEY_LIFETIME_VOLATILE, 0 };
	uint8_t d[BUF];
	size_t n;
	int32_t st, sr;

	drop(k);
	if (chance(50)) {
		coherent(&a);
	}
	if (chance(15)) {
		a.lifetime = chance(80) ? PSA_KEY_LIFETIME_PERSISTENT : below(0x300);
		a.id = chance(85) ? 1 + below(4) : (chance(50) ? 0 : PSA_KEY_ID_VENDOR_MIN);
	}
	n = key_material(&a, d);
	if (chance(10)) {
		a.bits = chance(50) ? 8 * n : 8 * below(40);
	}
	DESC("type %#x bits %u usage %#x alg %#x life %#x id %#x len %zu", a.type, a.bits, a.usage,
	     a.alg, a.lifetime, a.id, n);
	st = tps_import(&a, d, n, &k->tp);
	sr = ref_import(&a, d, n, &k->ref);
	/* Keys over tinypsa's table size are refused by design, before any later check. */
	if (by_design(st == PSA_ERROR_NOT_SUPPORTED && n > KEY_MAX &&
		      !PSA_KEY_TYPE_IS_ECC(a.type))) {
		if (sr == PSA_SUCCESS) {
			ref_destroy(k->ref);
		}
		return;
	}
	cmp_status(st, sr);
	if (st == PSA_SUCCESS && sr == PSA_SUCCESS) {
		k->live = k->synced = true;
		k->attr = a;
		if (a.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
			size_t pn;

			have_pub = tps_export_public(k->tp, last_pub, sizeof(last_pub), &pn) == 0;
		}
	} else {
		if (st == PSA_SUCCESS) {
			tps_destroy(k->tp);
		}
		if (sr == PSA_SUCCESS) {
			ref_destroy(k->ref);
		}
	}
}

static void op_generate(void)
{
	struct pair *k = any_key();
	struct dkey a = { r_type(), 0, r_usage(), r_alg(), PSA_KEY_LIFETIME_VOLATILE, 0 };
	static const uint16_t sizes[] = { 0, 8, 128, 192, 256, 255, 384, 512, 520 };
	int32_t st, sr;

	drop(k);
	a.bits = PICK(sizes);
	if (chance(50)) {
		coherent(&a);
		if (a.bits == 0) {
			a.bits = 256;
		}
	}
	DESC("type %#x bits %u usage %#x alg %#x", a.type, a.bits, a.usage, a.alg);
	st = tps_generate(&a, &k->tp);
	sr = ref_generate(&a, &k->ref);
	/* Keys over tinypsa's table size are refused by design. */
	if (by_design(st == PSA_ERROR_NOT_SUPPORTED && sr == PSA_SUCCESS && a.bits / 8 > KEY_MAX)) {
		ref_destroy(k->ref);
		return;
	}
	cmp_status(st, sr);
	if (st != PSA_SUCCESS || sr != PSA_SUCCESS) {
		if (st == PSA_SUCCESS) {
			tps_destroy(k->tp);
		}
		if (sr == PSA_SUCCESS) {
			ref_destroy(k->ref);
		}
		return;
	}
	k->live = true;
	k->attr = a;
	/* Copy tinypsa's material into the reference so outputs can be compared. */
	uint8_t d[BUF];
	size_t n;

	if (tps_export(k->tp, d, sizeof(d), &n) == PSA_SUCCESS) {
		ref_destroy(k->ref);
		k->synced = ref_import(&a, d, n, &k->ref) == PSA_SUCCESS;
		if (!k->synced) {
			mismatch("re-import of generated key", 0, -1);
			k->live = false;
			tps_destroy(k->tp);
		}
	}
}

static void op_destroy(void)
{
	struct pair *k = any_key();

	DESC("live %d tp %#x ref %#x life %#x", k->live, tps_id(k), ref_id(k), k->attr.lifetime);
	cmp_status(tps_destroy(tps_id(k)), ref_destroy(ref_id(k)));
	memset(k, 0, sizeof(*k));
}

static void op_attrs(void)
{
	struct pair *k = any_key();
	struct dkey x, y;
	int32_t st = tps_get_attrs(tps_id(k), &x), sr = ref_get_attrs(ref_id(k), &y);

	cmp_status(st, sr);
	if (st == 0 && sr == 0) {
		/* Volatile ids are each implementation's own choice. */
		if (PSA_KEY_LIFETIME_IS_VOLATILE(x.lifetime)) {
			x.id = y.id = 0;
		}
		cmp_bytes((uint8_t *)&x, sizeof(x), (uint8_t *)&y, sizeof(y));
	}
}

static void op_export(void)
{
	struct pair *k = any_key();
	uint8_t a[BUF], b[BUF];
	size_t an = 0, bn = 0, size = chance(70) ? BUF : rlen(70);
	bool pub = chance(50);
	int32_t st = pub ? tps_export_public(tps_id(k), a, size, &an)
			 : tps_export(tps_id(k), a, size, &an);
	int32_t sr = pub ? ref_export_public(ref_id(k), b, size, &bn)
			 : ref_export(ref_id(k), b, size, &bn);

	cmp_status(st, sr);
	if (st == 0 && sr == 0 && k->synced) {
		cmp_bytes(a, an, b, bn);
	}
}

static void op_random(void)
{
	uint8_t a[BUF], b[BUF];
	size_t n = rlen(BUF);

	cmp_status(tps_random(a, n), ref_random(b, n));
}

static void op_hash(void)
{
	uint8_t in[BUF], a[64], b[64];
	size_t n = rlen(BUF), an = 0, bn = 0, size = chance(80) ? 64 : rlen(40);
	uint32_t alg = r_alg();
	int s = below(N_OPS);
	int32_t st, sr;

	fill(in, n);
	DESC("slot %d alg %#x n %zu size %zu", s, alg, n, size);
	switch (below(5)) {
	case 0:
		sub = ".compute";
		st = tps_hash_compute(alg, in, n, a, size, &an);
		sr = ref_hash_compute(alg, in, n, b, size, &bn);
		break;
	case 1:
		sub = ".setup";
		st = tps_hash_setup(s, alg);
		sr = ref_hash_setup(s, alg);
		break;
	case 2:
		sub = ".update";
		st = tps_hash_update(s, in, n);
		sr = ref_hash_update(s, in, n);
		break;
	case 3:
		sub = ".finish";
		st = tps_hash_finish(s, a, size, &an);
		sr = ref_hash_finish(s, b, size, &bn);
		break;
	default:
		sub = ".abort";
		st = tps_hash_abort(s);
		sr = ref_hash_abort(s);
		break;
	}
	cmp_status(st, sr);
	if (st == 0 && sr == 0) {
		cmp_bytes(a, an, b, bn);
	}
}

static void op_mac(void)
{
	struct pair *k = key_where(is_mac_key);
	uint8_t in[BUF], a[64], b[64];
	size_t n = rlen(BUF), an = 0, bn = 0, size = chance(80) ? 64 : rlen(40);
	uint32_t alg = chance(50) && k->live ? k->attr.alg : r_alg();
	int s = below(N_OPS);
	int32_t st, sr;

	fill(in, n);
	DESC("slot %d key %s type %#x kalg %#x usage %#x alg %#x n %zu size %zu", s,
	     k->live ? "live" : "none", k->attr.type, k->attr.alg, k->attr.usage, alg, n, size);
	switch (below(5)) {
	case 0:
		sub = ".compute";
		st = tps_mac_compute(tps_id(k), alg, in, n, a, size, &an);
		sr = ref_mac_compute(ref_id(k), alg, in, n, b, size, &bn);
		break;
	case 1:
		sub = ".setup";
		st = tps_mac_setup(s, tps_id(k), alg);
		sr = ref_mac_setup(s, ref_id(k), alg);
		mac_synced[s] = k->synced;
		break;
	case 2:
		sub = ".update";
		st = tps_mac_update(s, in, n);
		sr = ref_mac_update(s, in, n);
		break;
	case 3:
		sub = ".finish";
		st = tps_mac_finish(s, a, size, &an);
		sr = ref_mac_finish(s, b, size, &bn);
		break;
	default:
		sub = ".abort";
		st = tps_mac_abort(s);
		sr = ref_mac_abort(s);
		break;
	}
	cmp_status(st, sr);
	if (st == 0 && sr == 0 && (*sub == '.' && sub[1] == 'c' ? k->synced : mac_synced[s])) {
		cmp_bytes(a, an, b, bn);
	}
}

static void op_cipher(void)
{
	struct pair *k = key_where(is_aes);
	uint8_t in[BUF], a[BUF], b[BUF];
	size_t n = chance(70) ? 16 * below(4) : rlen(80), an = 0, bn = 0;
	size_t size = chance(80) ? BUF : rlen(80);
	uint32_t alg = chance(60) && k->live ? k->attr.alg : r_alg();

	fill(in, n);
	DESC("key %s type %#x kalg %#x usage %#x alg %#x n %zu size %zu", k->live ? "live" : "none",
	     k->attr.type, k->attr.alg, k->attr.usage, alg, n, size);
	int32_t st = tps_cipher_encrypt(tps_id(k), alg, in, n, a, size, &an);
	int32_t sr = ref_cipher_encrypt(ref_id(k), alg, in, n, b, size, &bn);

	cmp_status(st, sr);
	if (st == 0 && sr == 0 && k->synced) {
		cmp_bytes(a, an, b, bn);
	}
}

static uint8_t sealed[BUF];
static size_t sealed_len;

static void op_aead(void)
{
	struct pair *k = key_where(is_aes);
	uint8_t nonce[20], ad[BUF], in[BUF], a[BUF], b[BUF];
	size_t nn = chance(70) ? (chance(50) ? 12 : 7 + below(7)) : rlen(20);
	size_t an_ = rlen(100), n = rlen(200), alen = 0, blen = 0;
	size_t size = chance(80) ? BUF : rlen(BUF);
	uint32_t alg = chance(60) && k->live ? k->attr.alg : r_alg();
	int s = below(N_OPS), enc = chance(50);
	int32_t st, sr;

	fill(nonce, nn);
	fill(ad, an_);
	fill(in, n);
	if (!enc && sealed_len && chance(60)) {
		/* Decrypt something real, sometimes tampered. */
		memcpy(in, sealed, sealed_len);
		n = sealed_len;
		if (chance(30)) {
			in[below(n)] ^= 1;
		}
	}
	DESC("slot %d enc %d key %s type %#x kalg %#x usage %#x alg %#x nn %zu an %zu n %zu size %zu",
	     s, enc, k->live ? "live" : "none", k->attr.type, k->attr.alg, k->attr.usage, alg, nn,
	     an_, n, size);
	switch (below(10)) {
	case 0:
	case 1:
	case 2:
		sub = ".oneshot";
		st = tps_aead_oneshot(enc, tps_id(k), alg, nonce, nn, ad, an_, in, n, a, size, &alen);
		sr = ref_aead_oneshot(enc, ref_id(k), alg, nonce, nn, ad, an_, in, n, b, size,
				      &blen);
		/*
		 * GCM tags of 5-7 and 9-11 bytes are outside PSA's set; Mbed TLS
		 * refuses them only in multipart setup, tinypsa everywhere.
		 */
		if (by_design(st == PSA_ERROR_INVALID_ARGUMENT && st != sr &&
			      PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg) == PSA_ALG_GCM &&
			      PSA_ALG_AEAD_GET_TAG_LENGTH(alg) > 4 &&
			      PSA_ALG_AEAD_GET_TAG_LENGTH(alg) < 12 &&
			      PSA_ALG_AEAD_GET_TAG_LENGTH(alg) != 8)) {
			return;
		}
		if (st == 0 && enc) {
			memcpy(sealed, a, alen);
			sealed_len = alen;
		}
		break;
	case 3:
		sub = ".setup";
		st = tps_aead_setup(s, enc, tps_id(k), alg);
		sr = ref_aead_setup(s, enc, ref_id(k), alg);
		aead_synced[s] = k->synced;
		break;
	case 4:
		sub = ".nonce";
		st = tps_aead_set_nonce(s, nonce, nn);
		sr = ref_aead_set_nonce(s, nonce, nn);
		break;
	case 5:
		an_ = rlen(40);
		n = rlen(80);
		sub = ".lengths";
		st = tps_aead_set_lengths(s, an_, n);
		sr = ref_aead_set_lengths(s, an_, n);
		break;
	case 6:
		an_ = rlen(40);
		sub = ".ad";
		st = tps_aead_update_ad(s, ad, an_);
		sr = ref_aead_update_ad(s, ad, an_);
		break;
	case 7:
		n = rlen(80);
		sub = ".update";
		st = tps_aead_update(s, in, n, a, size, &alen);
		sr = ref_aead_update(s, in, n, b, size, &blen);
		break;
	case 8:
		n = chance(80) ? 16 : rlen(16);
		sub = ".finish";
		st = tps_aead_finish(s, a, n, &alen);
		sr = ref_aead_finish(s, b, n, &blen);
		break;
	default:
		n = chance(80) ? 16 : rlen(17);
		sub = ".verify";
		st = tps_aead_verify(s, in, n);
		sr = ref_aead_verify(s, in, n);
		break;
	}
	if (getenv("DIFF_TRACE_AEAD")) {
		printf("T %ld slot %d %s %" PRId32 " %" PRId32 " | %s\n", step_no, s, sub, st, sr, desc);
	}
	cmp_status(st, sr);
	if (st == 0 && sr == 0 && (strcmp(sub, ".oneshot") ? aead_synced[s] : k->synced)) {
		cmp_bytes(a, alen, b, blen);
	}
}

/*
 * A whole multipart AEAD run, in order, chunked at random. Decryption runs
 * over tinypsa's own sealing of the same inputs, sometimes tampered with.
 */
static void op_aead_flow(void)
{
	struct pair *k = key_where(is_aes);
	uint32_t alg = k->live && chance(85) ? k->attr.alg : r_alg();
	bool ccm = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg) == PSA_ALG_CCM;
	uint8_t nonce[16], ad[80], pt[160], sealed_[200], a[200], b[200], *in;
	size_t nn = ccm ? 7 + below(7) : (chance(80) ? 12 : 1 + below(16));
	size_t an = rlen(sizeof(ad)), n = rlen(sizeof(pt)), alen, blen, done;
	int s = below(N_OPS), enc = chance(50);
	bool lengths = ccm || chance(50), synced = k->synced;
	int32_t st, sr;

	fill(nonce, nn);
	fill(ad, an);
	fill(pt, n);
	in = pt;
	if (!enc) {
		/* Only a key both sides share can open the other's sealing. */
		if (!synced) {
			return;
		}
		if (tps_aead_oneshot(1, tps_id(k), alg, nonce, nn, ad, an, pt, n, sealed_,
				     sizeof(sealed_), &alen) != PSA_SUCCESS) {
			return;
		}
		if (chance(25)) {
			sealed_[below(alen)] ^= 1;
		}
		in = sealed_;
		n = alen - PSA_ALG_AEAD_GET_TAG_LENGTH(alg);
	}
	DESC("flow enc %d alg %#x nn %zu an %zu n %zu lengths %d", enc, alg, nn, an, n, lengths);
#define STEP(name, call_tp, call_ref)       \
	do {                                \
		sub = name;                 \
		st = call_tp;               \
		sr = call_ref;              \
		if (getenv("DIFF_TRACE_AEAD")) \
			printf("T %ld slot %d flow%s %d %d | %s\n", step_no, s, sub, st, sr, desc); \
		cmp_status(st, sr);         \
		if (st || sr) {             \
			tps_aead_abort(s);  \
			ref_aead_abort(s);  \
			return;             \
		}                           \
	} while (0)
	STEP(".setup", tps_aead_setup(s, enc, tps_id(k), alg), ref_aead_setup(s, enc, ref_id(k), alg));
	if (lengths && chance(50)) {
		STEP(".lengths", tps_aead_set_lengths(s, an, n), ref_aead_set_lengths(s, an, n));
		lengths = false;
	}
	STEP(".nonce", tps_aead_set_nonce(s, nonce, nn), ref_aead_set_nonce(s, nonce, nn));
	if (lengths) {
		STEP(".lengths", tps_aead_set_lengths(s, an, n), ref_aead_set_lengths(s, an, n));
	}
	for (done = 0; done < an;) {
		size_t c = 1 + below(an - done);

		STEP(".ad", tps_aead_update_ad(s, &ad[done], c), ref_aead_update_ad(s, &ad[done], c));
		done += c;
	}
	for (done = 0; done < n;) {
		size_t c = 1 + below(n - done);

		STEP(".update", tps_aead_update(s, &in[done], c, a, sizeof(a), &alen),
		     ref_aead_update(s, &in[done], c, b, sizeof(b), &blen));
		if (synced) {
			cmp_bytes(a, alen, b, blen);
		}
		done += c;
	}
	if (enc) {
		STEP(".finish", tps_aead_finish(s, a, 16, &alen), ref_aead_finish(s, b, 16, &blen));
		if (synced) {
			cmp_bytes(a, alen, b, blen);
		}
	} else {
		size_t tag = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

		sub = ".verify";
		cmp_status(tps_aead_verify(s, &in[n], tag), ref_aead_verify(s, &in[n], tag));
	}
#undef STEP
}

static uint8_t last_sig[64];

static void op_sign(void)
{
	struct pair *k = key_where(is_ecc);
	uint8_t in[BUF], a[80], b[80];
	size_t n = chance(50) ? 32 : rlen(80), an = 0, bn = 0, size = chance(85) ? 80 : rlen(70);
	uint32_t alg = chance(70) && k->live ? k->attr.alg : r_alg();
	int message = chance(40);
	int32_t st, sr;

	fill(in, n);
	DESC("msg %d key %s type %#x kalg %#x usage %#x alg %#x n %zu size %zu", message,
	     k->live ? "live" : "none", k->attr.type, k->attr.alg, k->attr.usage, alg, n, size);
	if (chance(50)) {
		st = tps_sign(message, tps_id(k), alg, in, n, a, size, &an);
		sr = ref_sign(message, ref_id(k), alg, in, n, b, size, &bn);
		cmp_status(st, sr);
		if (st == 0 && sr == 0 && k->synced) {
			if (PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
				cmp_bytes(a, an, b, bn);
			} else {
				/* Each must accept the other's randomized signature. */
				cmp_status(tps_verify(message, tps_id(k), alg, in, n, b, bn),
					   ref_verify(message, ref_id(k), alg, in, n, a, an));
			}
		}
		if (st == 0 && an == 64) {
			memcpy(last_sig, a, 64);
		}
		return;
	}
	memcpy(a, last_sig, 64);
	an = chance(85) ? 64 : rlen(70);
	if (chance(30)) {
		a[below(64)] ^= 1;
	}
	cmp_status(tps_verify(message, tps_id(k), alg, in, n, a, an),
		   ref_verify(message, ref_id(k), alg, in, n, a, an));
}

static void op_agree(void)
{
	struct pair *k = key_where(is_pair);
	uint8_t peer[80], a[64], b[64];
	size_t pn = 65, an = 0, bn = 0, size = chance(85) ? 64 : rlen(40);
	uint32_t alg = chance(70) ? PSA_ALG_ECDH : r_alg();

	if (have_pub && chance(85)) {
		memcpy(peer, last_pub, 65);
		if (chance(15)) {
			peer[below(65)] ^= 1;
		}
	} else {
		pn = rlen(80);
		fill(peer, pn);
	}
	DESC("key %s type %#x kalg %#x usage %#x alg %#x pn %zu size %zu", k->live ? "live" : "none",
	     k->attr.type, k->attr.alg, k->attr.usage, alg, pn, size);
	int32_t st = tps_agree(alg, tps_id(k), peer, pn, a, size, &an);
	int32_t sr = ref_agree(alg, ref_id(k), peer, pn, b, size, &bn);

	cmp_status(st, sr);
	if (st == 0 && sr == 0 && k->synced) {
		cmp_bytes(a, an, b, bn);
	}
}

static void op_kdf(void)
{
	static const uint32_t steps[] = {
		PSA_KEY_DERIVATION_INPUT_SECRET, PSA_KEY_DERIVATION_INPUT_SALT,
		PSA_KEY_DERIVATION_INPUT_INFO,   PSA_KEY_DERIVATION_INPUT_PASSWORD,
		PSA_KEY_DERIVATION_INPUT_COST,   PSA_KEY_DERIVATION_INPUT_LABEL,
	};
	struct pair *k = key_where(is_kdf_key);
	uint8_t in[BUF], a[BUF], b[BUF];
	size_t n = rlen(KDF_MAX);
	uint32_t step = PICK(steps);
	int s = below(N_OPS);
	int32_t st, sr;

	fill(in, n);
	DESC("slot %d step %#x n %zu key %s type %#x kalg %#x usage %#x", s, step, n,
	     k->live ? "live" : "none", k->attr.type, k->attr.alg, k->attr.usage);
	switch (below(6)) {
	case 0: {
		uint32_t alg = chance(80) ? (chance(50) ? PSA_ALG_HKDF(PSA_ALG_SHA_256)
							: PSA_ALG_PBKDF2_AES_CMAC_PRF_128)
					  : r_alg();

		sub = ".setup";
		DESC("slot %d alg %#x", s, alg);
		st = tps_kdf_setup(s, alg);
		sr = ref_kdf_setup(s, alg);
		kdf_synced[s] = true;
		/* Key agreement feeding a KDF is not provided: no caller uses it. */
		if (by_design(st == PSA_ERROR_NOT_SUPPORTED && sr == PSA_SUCCESS &&
			      PSA_ALG_IS_KEY_AGREEMENT(alg))) {
			ref_kdf_abort(s);
			return;
		}
		break;
	}
	case 1:
		sub = ".bytes";
		st = tps_kdf_bytes(s, step, in, n);
		sr = ref_kdf_bytes(s, step, in, n);
		/* Salt and info beyond TINYPSA_KDF_INPUT_MAX are refused by design. */
		if (by_design(st == PSA_ERROR_NOT_SUPPORTED && sr == PSA_SUCCESS &&
			      (step == PSA_KEY_DERIVATION_INPUT_SALT ||
			       step == PSA_KEY_DERIVATION_INPUT_INFO))) {
			ref_kdf_abort(s);
			return;
		}
		break;
	case 2: {
		/* Small costs keep PBKDF2 cheap; 0 and huge ones probe the limits. */
		uint64_t v = chance(85) ? 1 + below(40) : (chance(50) ? 0 : 1ull << 33);

		sub = ".integer";
		st = tps_kdf_integer(s, step, v);
		sr = ref_kdf_integer(s, step, v);
		break;
	}
	case 3:
		sub = ".key";
		st = tps_kdf_key(s, step, tps_id(k));
		sr = ref_kdf_key(s, step, ref_id(k));
		/* Material only one side holds makes every later output differ. */
		kdf_synced[s] &= k->synced || !k->live;
		/* The same buffer limit, reached through a key. */
		if (by_design(st == PSA_ERROR_NOT_SUPPORTED && sr == PSA_SUCCESS &&
			      (step == PSA_KEY_DERIVATION_INPUT_SALT ||
			       step == PSA_KEY_DERIVATION_INPUT_INFO))) {
			ref_kdf_abort(s);
			return;
		}
		break;
	case 4:
		n = rlen(BUF);
		sub = ".output";
		st = tps_kdf_output(s, a, n);
		sr = ref_kdf_output(s, b, n);
		if (st == 0 && sr == 0 && kdf_synced[s]) {
			cmp_bytes(a, n, b, n);
		}
		break;
	default:
		sub = ".abort";
		st = tps_kdf_abort(s);
		sr = ref_kdf_abort(s);
		break;
	}
	if (getenv("DIFF_TRACE_KDF")) {
		printf("T %ld slot %d %s %" PRId32 " %" PRId32 " | %s\n", step_no, s, sub, st, sr, desc);
	}
	cmp_status(st, sr);
}

static const struct {
	const char *name;
	void (*fn)(void);
	int weight;
} ops[] = {
	{ "import", op_import, 14 }, { "generate", op_generate, 6 }, { "destroy", op_destroy, 4 },
	{ "attrs", op_attrs, 4 },    { "export", op_export, 6 },     { "random", op_random, 2 },
	{ "hash", op_hash, 8 },      { "mac", op_mac, 10 },          { "cipher", op_cipher, 6 },
	{ "aead", op_aead, 10 },     { "aeadflow", op_aead_flow, 8 },     { "sign", op_sign, 10 },        { "agree", op_agree, 5 },
	{ "kdf", op_kdf, 12 },
};

int main(int argc, char **argv)
{
	uint64_t seed = argc > 1 ? strtoull(argv[1], NULL, 0) : 1;
	long steps = argc > 2 ? strtol(argv[2], NULL, 0) : 20000;
	int total = 0;

	if (argc > 3) {
		verbose = atoi(argv[3]);
	}

	rng_state = seed * 0x9e3779b97f4a7c15ull + 1;
	if (tps_init() || ref_init()) {
		printf("init failed\n");
		return 2;
	}
	for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
		total += ops[i].weight;
	}
	for (step_no = 0; step_no < steps; step_no++) {
		int r = below(total);

		sub = "";
		size_t i = 0;

		while (r >= ops[i].weight) {
			r -= ops[i].weight;
			i++;
		}
		op_name = ops[i].name;
		op_index = i;
		ops[i].fn();
	}
	for (int i = 0; i < KEYS; i++) {
		drop(&keys[i]);
	}
	if (getenv("DIFF_COVERAGE")) {
		for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
			printf("  %-8s %ld both succeeded\n", ops[i].name, ok_count[i]);
		}
	}
	printf("seed %" PRIu64 ": %ld steps, %ld comparisons, %ld by design, %ld mismatches\n",
	       seed, steps, compared, by_design_count, mismatches);
	return mismatches != 0;
}
