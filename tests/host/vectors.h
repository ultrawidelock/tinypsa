/* SPDX-License-Identifier: ISC */
/*
 * Shapes of the generated vector tables (gen_vectors.py writes vectors.c).
 * Byte strings are hex. expect: 1 valid, 0 invalid, -1 either is acceptable.
 */
#ifndef TINYPSA_VECTORS_H
#define TINYPSA_VECTORS_H

#include <stddef.h>

struct vec_hash {
	const char *id, *msg, *md;
};

/* tag_len shorter than the full MAC means a truncated MAC. */
struct vec_mac {
	const char *id;
	int cmac;
	const char *key, *msg, *tag;
	int expect;
};

struct vec_ecb {
	const char *id, *key, *pt, *ct;
};

struct vec_aead {
	const char *id;
	int ccm;
	const char *key, *iv, *aad, *pt, *ct, *tag;
	int expect;
};

/* msg is hashed with SHA-256 and verified as a message. sig is r || s. */
struct vec_ecdsa {
	const char *id, *pub, *msg, *sig;
	int expect;
};

/* A signature with a known per-signature secret k, checked at the backend. */
struct vec_siggen {
	const char *id, *d, *msg, *k, *r, *s;
};

struct vec_ecdh {
	const char *id, *priv, *pub, *shared;
	int expect;
};

struct vec_hkdf {
	const char *id, *ikm, *salt, *info, *okm;
	size_t size;
	int expect;
};

/* HMAC_DRBG with no additional input. reseed is empty for no-reseed runs. */
struct vec_drbg {
	const char *id, *entropy, *nonce, *pers, *reseed, *bits;
};

#define VEC_TABLE(type, name) \
	extern const struct type name[]; \
	extern const size_t name##_count;

VEC_TABLE(vec_hash, vec_sha256)
VEC_TABLE(vec_mac, vec_macs)
VEC_TABLE(vec_ecb, vec_ecbs)
VEC_TABLE(vec_aead, vec_aeads)
VEC_TABLE(vec_ecdsa, vec_ecdsas)
VEC_TABLE(vec_siggen, vec_siggens)
VEC_TABLE(vec_ecdh, vec_ecdhs)
VEC_TABLE(vec_hkdf, vec_hkdfs)
VEC_TABLE(vec_drbg, vec_drbgs)

#endif
