/* SPDX-License-Identifier: ISC */
/*
 * P-256 over the vendored P256-Cortex-M4, which works on little-endian
 * 32-bit words; the backend interface is big-endian bytes. Deterministic
 * signatures derive k per RFC 6979 with BearSSL's HMAC_DRBG, the same
 * construction BearSSL's own ECDSA uses.
 */
#include <stdbool.h>
#include <string.h>

#include <bearssl_hash.h>
#include <bearssl_rand.h>

#include "p256-cortex-m4.h"

#include "backend.h"

/* Exported by P256-Cortex-M4's assembly; declared only inside its .c file. */
bool P256_check_range_n(const uint32_t a[8]);
void P256_reduce_mod_n_32bytes(uint32_t res[8], const uint32_t a[8]);

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;

	while (n--) {
		*v++ = 0;
	}
}

static void words(uint32_t w[8], const uint8_t be[32])
{
	p256_convert_endianness(w, be, 32);
}

static void bytes(uint8_t be[32], const uint32_t w[8])
{
	p256_convert_endianness(be, w, 32);
}

int tp_be_p256_sk_check(const uint8_t sk[32])
{
	uint32_t d[8];
	bool ok;

	words(d, sk);
	ok = P256_check_range_n(d);
	wipe(d, sizeof(d));
	return ok ? 0 : -1;
}

int tp_be_p256_pk_check(const uint8_t pk[64])
{
	uint8_t oct[65];
	uint32_t x[8], y[8];

	oct[0] = 0x04;
	memcpy(&oct[1], pk, 64);
	return p256_octet_string_to_point(x, y, oct, sizeof(oct)) ? 0 : -1;
}

int tp_be_p256_public_key(uint8_t pk[64], const uint8_t sk[32])
{
	uint32_t d[8], x[8], y[8];
	bool ok;

	words(d, sk);
	ok = p256_keygen(x, y, d);
	wipe(d, sizeof(d));
	if (!ok) {
		return -1;
	}
	bytes(pk, x);
	bytes(&pk[32], y);
	return 0;
}

int tp_be_p256_ecdh(uint8_t z[32], const uint8_t sk[32], const uint8_t pk[64])
{
	uint32_t d[8], x[8], y[8];
	bool ok;

	words(d, sk);
	words(x, pk);
	words(y, &pk[32]);
	ok = p256_ecdh_calc_shared_secret(z, d, x, y);
	wipe(d, sizeof(d));
	return ok ? 0 : -1;
}

/* Fails, so the caller draws again, when k is outside [1, n-1] or r or s is 0. */
static bool sign(uint8_t sig[64], const uint8_t hash[32], const uint32_t d[8],
		 const uint32_t k[8])
{
	uint32_t r[8], s[8];

	if (!p256_sign(r, s, hash, 32, d, k)) {
		return false;
	}
	bytes(sig, r);
	bytes(&sig[32], s);
	return true;
}

int tp_be_p256_sign_hash(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32],
			 const uint8_t ek[32])
{
	uint32_t d[8], k[8];
	bool ok;

	words(d, sk);
	words(k, ek);
	ok = sign(sig, hash, d, k);
	wipe(d, sizeof(d));
	wipe(k, sizeof(k));
	return ok ? 0 : -1;
}

/*
 * RFC 6979 section 3.2: HMAC_DRBG instantiated with int2octets(x) ||
 * bits2octets(h1); each draw is one 32-byte output, and the generate
 * step's update is the "K = HMAC_K(V || 0x00), V = HMAC_K(V)" of step h.3.
 */
void tp_be_p256_sign_hash_det(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32])
{
	br_hmac_drbg_context drbg;
	uint8_t seed[64], kb[32];
	uint32_t d[8], k[8], h[8];

	words(d, sk);
	words(h, hash);
	P256_reduce_mod_n_32bytes(h, h);
	memcpy(seed, sk, 32);
	bytes(&seed[32], h);
	br_hmac_drbg_init(&drbg, &br_sha256_vtable, seed, sizeof(seed));
	do {
		br_hmac_drbg_generate(&drbg, kb, sizeof(kb));
		words(k, kb);
	} while (!sign(sig, hash, d, k));
	wipe(&drbg, sizeof(drbg));
	wipe(seed, sizeof(seed));
	wipe(kb, sizeof(kb));
	wipe(d, sizeof(d));
	wipe(k, sizeof(k));
}

int tp_be_p256_verify_hash(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pk[64])
{
	uint32_t x[8], y[8], r[8], s[8];

	words(x, pk);
	words(y, &pk[32]);
	words(r, sig);
	words(s, &sig[32]);
	return p256_verify(x, y, hash, 32, r, s) ? 0 : -1;
}
