/* SPDX-License-Identifier: ISC */
/*
 * The primitives a backend supplies. The core owns every PSA rule (policy,
 * state, lengths, formats); a backend only computes. Context pointers point
 * at storage sized by the backend's tinypsa_backend_ctx.h. Functions that
 * return int give 0 on success.
 */
#ifndef TINYPSA_BACKEND_H
#define TINYPSA_BACKEND_H

#include <stddef.h>
#include <stdint.h>

void tp_be_sha256_init(void *ctx);
void tp_be_sha256_update(void *ctx, const uint8_t *in, size_t len);
void tp_be_sha256_final(void *ctx, uint8_t out[32]);

void tp_be_hmac_sha256_init(void *ctx, const uint8_t *key, size_t key_len);
void tp_be_hmac_sha256_update(void *ctx, const uint8_t *in, size_t len);
void tp_be_hmac_sha256_final(void *ctx, uint8_t out[32]);

/* AES in the encrypt direction; key_len is 16, 24 or 32. len is a multiple of 16. */
void tp_be_aes_init(void *ctx, const uint8_t *key, size_t key_len);
void tp_be_aes_encrypt(void *ctx, uint8_t *out, const uint8_t *in, size_t len);

/*
 * AEAD. *_key sets the key alone; *_start supplies the direction and nonce
 * (and for CCM the lengths) once known. Updates produce exactly len bytes of output and
 * may run in place. final_dec returns 0 only for a matching tag.
 */
void tp_be_ccm_key(void *ctx, const uint8_t *key, size_t key_len);
void tp_be_ccm_start(void *ctx, int encrypt, size_t key_len, const uint8_t *nonce,
		     size_t nonce_len, size_t tag_len, size_t pt_len, size_t ad_len);
void tp_be_ccm_update_ad(void *ctx, const uint8_t *ad, size_t len);
void tp_be_ccm_update(void *ctx, int encrypt, uint8_t *out, const uint8_t *in, size_t len);
void tp_be_ccm_final_enc(void *ctx, uint8_t *tag, size_t tag_len);
int tp_be_ccm_final_dec(void *ctx, const uint8_t *tag, size_t tag_len);

void tp_be_gcm_key(void *ctx, const uint8_t *key, size_t key_len);
void tp_be_gcm_start(void *ctx, int encrypt, const uint8_t *iv, size_t iv_len);
void tp_be_gcm_update_ad(void *ctx, const uint8_t *ad, size_t len);
void tp_be_gcm_update(void *ctx, int encrypt, uint8_t *out, const uint8_t *in, size_t len);
void tp_be_gcm_final_enc(void *ctx, uint8_t *tag, size_t tag_len);
int tp_be_gcm_final_dec(void *ctx, const uint8_t *tag, size_t tag_len);

/* Releases anything a context holds beyond its storage. */
void tp_be_ctx_free(void *ctx, size_t size);

/*
 * P-256. Scalars are 32 bytes big-endian; points are x || y, 64 bytes,
 * without the 0x04 prefix. sk_check accepts 0 < sk < n; pk_check accepts a
 * point on the curve.
 */
int tp_be_p256_sk_check(const uint8_t sk[32]);
int tp_be_p256_pk_check(const uint8_t pk[64]);
int tp_be_p256_public_key(uint8_t pk[64], const uint8_t sk[32]);
int tp_be_p256_ecdh(uint8_t z[32], const uint8_t sk[32], const uint8_t pk[64]);
/* Fails when ek is not a valid per-signature secret; the caller draws again. */
int tp_be_p256_sign_hash(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32],
			 const uint8_t ek[32]);
/* RFC 6979 with HMAC-SHA-256. */
void tp_be_p256_sign_hash_det(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32]);
int tp_be_p256_verify_hash(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pk[64]);

/*
 * For SPAKE2+. mul gives r = k*P and fails unless 0 < k < n and P is on the
 * curve. add gives r = P + Q, or P - Q when sub, for P and Q on the curve,
 * and fails when that is the point at infinity. reduce gives x = xs mod n
 * for a big-endian xs of any length.
 */
int tp_be_p256_mul(uint8_t r[64], const uint8_t k[32], const uint8_t p[64]);
int tp_be_p256_add(uint8_t r[64], const uint8_t p[64], const uint8_t q[64], int sub);
void tp_be_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len);

#endif
