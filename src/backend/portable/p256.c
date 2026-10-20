/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * P-256 over the vendored P256-Cortex-M4, which works on little-endian
 * 32-bit words; the backend interface is big-endian bytes. Deterministic
 * signatures derive k per RFC 6979 with BearSSL's HMAC_DRBG, the same
 * construction BearSSL's own ECDSA uses.
 */
#include <stdbool.h>
#include <string.h>

#include <bearssl_hash.h>

#include "p256-cortex-m4.h"

#include "backend.h"

/* Exported by P256-Cortex-M4's assembly; declared only inside its .c file. */
bool P256_check_range_n(const uint32_t a[8]);
void P256_reduce_mod_n_32bytes(uint32_t res[8], const uint32_t a[8]);
void P256_mul_mod_n(uint32_t res[8], const uint32_t a[8], const uint32_t b[8]);
void P256_add_mod_n(uint32_t res[8], const uint32_t a[8], const uint32_t b[8]);
void P256_to_montgomery(uint32_t aR[8], const uint32_t a[8]);
void P256_from_montgomery(uint32_t a[8], const uint32_t aR[8]);
void P256_jacobian_to_affine(uint32_t affine_mont_x[8], uint32_t affine_mont_y[8],
			     const uint32_t jacobian_mont[3][8]);
void P256_add_sub_j(uint32_t jacobian_point1[3][8], const uint32_t (*point2)[8], bool is_sub,
		    bool p2_is_affine);

/* 1 in Montgomery form, the Z of an affine point, as in p256-cortex-m4.c. */
static const uint32_t one_montgomery[8] = { 1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff,
					    0xfffffffe, 0 };

/* 2^256 mod n, so shifting a value up 32 bytes is one multiplication. */
static const uint32_t r256_mod_n[8] = { 0x039cdaaf, 0x0c46353d, 0x58e8617b, 0x43190552,
					0x00000000, 0x00000000, 0xffffffff, 0x00000000 };

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

int tp_be_p256_verify_hash(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pk[64])
{
	uint32_t x[8], y[8], r[8], s[8];

	words(x, pk);
	words(y, &pk[32]);
	words(r, sig);
	words(s, &sig[32]);
	return p256_verify(x, y, hash, 32, r, s) ? 0 : -1;
}

int tp_be_p256_mul(uint8_t r[64], const uint8_t k[32], const uint8_t p[64])
{
	uint32_t d[8], x[8], y[8], rx[8], ry[8];
	bool ok;

	words(d, k);
	words(x, p);
	words(y, &p[32]);
	ok = p256_scalarmult_generic(rx, ry, d, x, y);
	if (ok) {
		bytes(r, rx);
		bytes(&r[32], ry);
	}
	wipe(d, sizeof(d));
	wipe(rx, sizeof(rx));
	wipe(ry, sizeof(ry));
	return ok ? 0 : -1;
}

/* Converts an affine point to the Montgomery form P256_add_sub_j works in. */
static void to_mont(uint32_t mx[8], uint32_t my[8], const uint8_t p[64])
{
	uint32_t w[8];

	words(w, p);
	P256_to_montgomery(mx, w);
	words(w, &p[32]);
	P256_to_montgomery(my, w);
}

int tp_be_p256_add(uint8_t r[64], const uint8_t p[64], const uint8_t q[64], int sub)
{
	uint32_t j[3][8], a[2][8], w[8], z = 0;

	to_mont(j[0], j[1], p);
	memcpy(j[2], one_montgomery, sizeof(j[2]));
	to_mont(a[0], a[1], q);
	/* Handles P = Q; a result at infinity has Z = 0. */
	P256_add_sub_j(j, (const uint32_t(*)[8])a, sub, true);
	for (int i = 0; i < 8; i++) {
		z |= j[2][i];
	}
	if (z) {
		P256_jacobian_to_affine(a[0], a[1], (const uint32_t(*)[8])j);
		P256_from_montgomery(w, a[0]);
		bytes(r, w);
		P256_from_montgomery(w, a[1]);
		bytes(&r[32], w);
	}
	wipe(j, sizeof(j));
	wipe(a, sizeof(a));
	wipe(w, sizeof(w));
	return z ? 0 : -1;
}

/* Horner's rule over 32-byte chunks, most significant first, the first one short. */
void tp_be_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len)
{
	uint8_t chunk[32];
	uint32_t acc[8] = { 0 }, c[8];

	for (size_t i = 0, take; i < xs_len; i += take) {
		take = i ? 32 : (xs_len - 1) % 32 + 1;
		memset(chunk, 0, sizeof(chunk));
		memcpy(&chunk[32 - take], &xs[i], take);
		words(c, chunk);
		P256_mul_mod_n(acc, acc, r256_mod_n);
		P256_add_mod_n(acc, acc, c);
	}
	bytes(x, acc);
	wipe(chunk, sizeof(chunk));
	wipe(acc, sizeof(acc));
	wipe(c, sizeof(c));
}
