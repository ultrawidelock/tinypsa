/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * A plain-typed view of the PSA API, so the differential driver can call
 * two implementations whose headers cannot share a translation unit.
 * shim.inc implements it once; tp_shim.c and ref_shim.c compile it against
 * tinypsa and against Mbed TLS. Multipart operations live in the shim, in
 * N_OPS slots per kind.
 */
#ifndef TINYPSA_DIFF_SHIM_H
#define TINYPSA_DIFF_SHIM_H

#include <stddef.h>
#include <stdint.h>

#define N_OPS 2

struct dkey {
	uint16_t type;
	uint16_t bits;
	uint32_t usage;
	uint32_t alg;
	uint32_t lifetime;
	uint32_t id;
};

#define SHIM_DECLARE(p)                                                                      \
	int32_t p##_init(void);                                                              \
	int32_t p##_import(const struct dkey *a, const uint8_t *d, size_t n, uint32_t *id);  \
	int32_t p##_generate(const struct dkey *a, uint32_t *id);                            \
	int32_t p##_destroy(uint32_t id);                                                    \
	int32_t p##_get_attrs(uint32_t id, struct dkey *out);                                \
	int32_t p##_export(uint32_t id, uint8_t *o, size_t size, size_t *len);               \
	int32_t p##_export_public(uint32_t id, uint8_t *o, size_t size, size_t *len);        \
	int32_t p##_random(uint8_t *o, size_t n);                                            \
	int32_t p##_hash_compute(uint32_t alg, const uint8_t *in, size_t n, uint8_t *o,      \
				 size_t size, size_t *len);                                  \
	int32_t p##_hash_setup(int s, uint32_t alg);                                         \
	int32_t p##_hash_update(int s, const uint8_t *in, size_t n);                         \
	int32_t p##_hash_finish(int s, uint8_t *o, size_t size, size_t *len);                \
	int32_t p##_hash_abort(int s);                                                       \
	int32_t p##_mac_compute(uint32_t id, uint32_t alg, const uint8_t *in, size_t n,      \
				uint8_t *o, size_t size, size_t *len);                       \
	int32_t p##_mac_setup(int s, uint32_t id, uint32_t alg);                             \
	int32_t p##_mac_update(int s, const uint8_t *in, size_t n);                          \
	int32_t p##_mac_finish(int s, uint8_t *o, size_t size, size_t *len);                 \
	int32_t p##_mac_abort(int s);                                                        \
	int32_t p##_cipher_encrypt(uint32_t id, uint32_t alg, const uint8_t *in, size_t n,   \
				   uint8_t *o, size_t size, size_t *len);                    \
	int32_t p##_aead_oneshot(int enc, uint32_t id, uint32_t alg, const uint8_t *nonce,   \
				 size_t nn, const uint8_t *ad, size_t an, const uint8_t *in, \
				 size_t n, uint8_t *o, size_t size, size_t *len);            \
	int32_t p##_aead_setup(int s, int enc, uint32_t id, uint32_t alg);                   \
	int32_t p##_aead_set_nonce(int s, const uint8_t *nonce, size_t n);                   \
	int32_t p##_aead_set_lengths(int s, size_t ad, size_t pt);                           \
	int32_t p##_aead_update_ad(int s, const uint8_t *ad, size_t n);                      \
	int32_t p##_aead_update(int s, const uint8_t *in, size_t n, uint8_t *o, size_t size, \
				size_t *len);                                                \
	int32_t p##_aead_finish(int s, uint8_t *tag, size_t size, size_t *len);              \
	int32_t p##_aead_verify(int s, const uint8_t *tag, size_t n);                        \
	int32_t p##_aead_abort(int s);                                                       \
	int32_t p##_sign(int message, uint32_t id, uint32_t alg, const uint8_t *in,          \
			 size_t n, uint8_t *o, size_t size, size_t *len);                    \
	int32_t p##_verify(int message, uint32_t id, uint32_t alg, const uint8_t *in,        \
			   size_t n, const uint8_t *sig, size_t sn);                         \
	int32_t p##_agree(uint32_t alg, uint32_t id, const uint8_t *peer, size_t pn,         \
			  uint8_t *o, size_t size, size_t *len);                             \
	int32_t p##_kdf_setup(int s, uint32_t alg);                                          \
	int32_t p##_kdf_bytes(int s, uint32_t step, const uint8_t *d, size_t n);             \
	int32_t p##_kdf_integer(int s, uint32_t step, uint64_t v);                           \
	int32_t p##_kdf_key(int s, uint32_t step, uint32_t id);                              \
	int32_t p##_kdf_output(int s, uint8_t *o, size_t n);                                 \
	int32_t p##_kdf_abort(int s);

SHIM_DECLARE(tps)
SHIM_DECLARE(ref)

#endif
