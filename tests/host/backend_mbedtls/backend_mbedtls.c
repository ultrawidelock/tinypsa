/* SPDX-License-Identifier: ISC */
/*
 * Test-only backend over Mbed TLS's legacy crypto, so the core runs on a
 * host: ocrypto exists only as Cortex-M archives. Never shipped. Built with
 * mbedtls_legacy_config.h, so this file must not include PSA headers.
 */
#include <stdlib.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/ccm.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>

#include "backend.h"
#include "tinypsa_backend_ctx.h"

struct hmac {
	mbedtls_sha256_context sha;
	uint8_t opad[64];
};

enum { KIND_CCM = 0x43434d, KIND_GCM = 0x47434d };

struct aead {
	int kind;
	int encrypt;
	union {
		mbedtls_ccm_context ccm;
		mbedtls_gcm_context gcm;
	} u;
};

_Static_assert(sizeof(mbedtls_sha256_context) <= TINYPSA_SHA256_CTX_SIZE, "sha256 ctx");
_Static_assert(sizeof(struct hmac) <= TINYPSA_HMAC_SHA256_CTX_SIZE, "hmac ctx");
_Static_assert(sizeof(mbedtls_aes_context) <= TINYPSA_AES_CTX_SIZE, "aes ctx");
_Static_assert(sizeof(struct aead) <= TINYPSA_CCM_CTX_SIZE, "ccm ctx");
_Static_assert(sizeof(struct aead) <= TINYPSA_GCM_CTX_SIZE, "gcm ctx");

void tp_be_sha256_init(void *ctx)
{
	mbedtls_sha256_init(ctx);
	mbedtls_sha256_starts(ctx, 0);
}

void tp_be_sha256_update(void *ctx, const uint8_t *in, size_t len)
{
	mbedtls_sha256_update(ctx, in, len);
}

void tp_be_sha256_final(void *ctx, uint8_t out[32])
{
	mbedtls_sha256_finish(ctx, out);
	mbedtls_sha256_free(ctx);
}

void tp_be_hmac_sha256_init(void *ctx, const uint8_t *key, size_t key_len)
{
	struct hmac *h = ctx;
	uint8_t k[64] = { 0 }, ipad[64];

	if (key_len > 64) {
		mbedtls_sha256(key, key_len, k, 0);
	} else if (key_len) {
		memcpy(k, key, key_len);
	}
	for (int i = 0; i < 64; i++) {
		ipad[i] = k[i] ^ 0x36;
		h->opad[i] = k[i] ^ 0x5c;
	}
	tp_be_sha256_init(&h->sha);
	mbedtls_sha256_update(&h->sha, ipad, sizeof(ipad));
}

void tp_be_hmac_sha256_update(void *ctx, const uint8_t *in, size_t len)
{
	mbedtls_sha256_update(&((struct hmac *)ctx)->sha, in, len);
}

void tp_be_hmac_sha256_final(void *ctx, uint8_t out[32])
{
	struct hmac *h = ctx;
	uint8_t inner[32];

	tp_be_sha256_final(&h->sha, inner);
	tp_be_sha256_init(&h->sha);
	mbedtls_sha256_update(&h->sha, h->opad, sizeof(h->opad));
	mbedtls_sha256_update(&h->sha, inner, sizeof(inner));
	tp_be_sha256_final(&h->sha, out);
}

void tp_be_aes_init(void *ctx, const uint8_t *key, size_t key_len)
{
	mbedtls_aes_init(ctx);
	mbedtls_aes_setkey_enc(ctx, key, 8 * key_len);
}

void tp_be_aes_encrypt(void *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
	for (size_t i = 0; i < len; i += 16) {
		mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, &in[i], &out[i]);
	}
}

void tp_be_ccm_key(void *ctx, const uint8_t *key, size_t key_len)
{
	struct aead *a = ctx;

	a->kind = KIND_CCM;
	mbedtls_ccm_init(&a->u.ccm);
	mbedtls_ccm_setkey(&a->u.ccm, MBEDTLS_CIPHER_ID_AES, key, 8 * key_len);
}

void tp_be_ccm_start(void *ctx, int encrypt, size_t key_len, const uint8_t *nonce,
		     size_t nonce_len, size_t tag_len, size_t pt_len, size_t ad_len)
{
	struct aead *a = ctx;

	(void)key_len;
	a->encrypt = encrypt;
	mbedtls_ccm_starts(&a->u.ccm, encrypt ? MBEDTLS_CCM_ENCRYPT : MBEDTLS_CCM_DECRYPT, nonce,
			   nonce_len);
	mbedtls_ccm_set_lengths(&a->u.ccm, ad_len, pt_len, tag_len);
}

void tp_be_ccm_update_ad(void *ctx, const uint8_t *ad, size_t len)
{
	mbedtls_ccm_update_ad(&((struct aead *)ctx)->u.ccm, ad, len);
}

void tp_be_ccm_update(void *ctx, int encrypt, uint8_t *out, const uint8_t *in, size_t len)
{
	size_t n;

	(void)encrypt;
	mbedtls_ccm_update(&((struct aead *)ctx)->u.ccm, in, len, out, len, &n);
}

void tp_be_ccm_final_enc(void *ctx, uint8_t *tag, size_t tag_len)
{
	mbedtls_ccm_finish(&((struct aead *)ctx)->u.ccm, tag, tag_len);
}

int tp_be_ccm_final_dec(void *ctx, const uint8_t *tag, size_t tag_len)
{
	uint8_t want[16];

	mbedtls_ccm_finish(&((struct aead *)ctx)->u.ccm, want, tag_len);
	return mbedtls_ct_memcmp(want, tag, tag_len) != 0;
}

void tp_be_gcm_key(void *ctx, const uint8_t *key, size_t key_len)
{
	struct aead *a = ctx;

	a->kind = KIND_GCM;
	mbedtls_gcm_init(&a->u.gcm);
	mbedtls_gcm_setkey(&a->u.gcm, MBEDTLS_CIPHER_ID_AES, key, 8 * key_len);
}

void tp_be_gcm_start(void *ctx, int encrypt, const uint8_t *iv, size_t iv_len)
{
	struct aead *a = ctx;

	a->encrypt = encrypt;
	mbedtls_gcm_starts(&a->u.gcm, encrypt ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT, iv,
			   iv_len);
}

void tp_be_gcm_update_ad(void *ctx, const uint8_t *ad, size_t len)
{
	mbedtls_gcm_update_ad(&((struct aead *)ctx)->u.gcm, ad, len);
}

void tp_be_gcm_update(void *ctx, int encrypt, uint8_t *out, const uint8_t *in, size_t len)
{
	size_t n;

	(void)encrypt;
	mbedtls_gcm_update(&((struct aead *)ctx)->u.gcm, in, len, out, len, &n);
}

void tp_be_gcm_final_enc(void *ctx, uint8_t *tag, size_t tag_len)
{
	size_t n;

	mbedtls_gcm_finish(&((struct aead *)ctx)->u.gcm, NULL, 0, &n, tag, tag_len);
}

int tp_be_gcm_final_dec(void *ctx, const uint8_t *tag, size_t tag_len)
{
	uint8_t want[16];
	size_t n;

	mbedtls_gcm_finish(&((struct aead *)ctx)->u.gcm, NULL, 0, &n, want, tag_len);
	return mbedtls_ct_memcmp(want, tag, tag_len) != 0;
}

void tp_be_ctx_free(void *ctx, size_t size)
{
	struct aead *a = ctx;

	(void)size;
	if (a->kind == KIND_CCM) {
		mbedtls_ccm_free(&a->u.ccm);
	} else if (a->kind == KIND_GCM) {
		mbedtls_gcm_free(&a->u.gcm);
	}
	a->kind = 0;
}

/* ---- P-256 ---------------------------------------------------------------- */

static int host_rng(void *p, unsigned char *out, size_t n)
{
	(void)p;
	arc4random_buf(out, n);
	return 0;
}

/* Hands back the caller's per-signature secret for every draw. */
static int fixed_rng(void *p, unsigned char *out, size_t n)
{
	memcpy(out, p, n < 32 ? n : 32);
	if (n > 32) {
		memset(&out[32], 0, n - 32);
	}
	return 0;
}

struct ec {
	mbedtls_ecp_group g;
	mbedtls_ecp_point q;
	mbedtls_mpi d, r, s;
};

static void ec_init(struct ec *e)
{
	mbedtls_ecp_group_init(&e->g);
	mbedtls_ecp_point_init(&e->q);
	mbedtls_mpi_init(&e->d);
	mbedtls_mpi_init(&e->r);
	mbedtls_mpi_init(&e->s);
	mbedtls_ecp_group_load(&e->g, MBEDTLS_ECP_DP_SECP256R1);
}

static int ec_free(struct ec *e, int ret)
{
	mbedtls_ecp_group_free(&e->g);
	mbedtls_ecp_point_free(&e->q);
	mbedtls_mpi_free(&e->d);
	mbedtls_mpi_free(&e->r);
	mbedtls_mpi_free(&e->s);
	return ret ? -1 : 0;
}

static int read_point(struct ec *e, const uint8_t pk[64])
{
	uint8_t buf[65] = { 0x04 };

	memcpy(&buf[1], pk, 64);
	return mbedtls_ecp_point_read_binary(&e->g, &e->q, buf, sizeof(buf));
}

int tp_be_p256_sk_check(const uint8_t sk[32])
{
	struct ec e;
	int ret;

	ec_init(&e);
	ret = mbedtls_mpi_read_binary(&e.d, sk, 32);
	ret = ret ? ret : mbedtls_ecp_check_privkey(&e.g, &e.d);
	return ec_free(&e, ret);
}

int tp_be_p256_pk_check(const uint8_t pk[64])
{
	struct ec e;
	int ret;

	ec_init(&e);
	ret = read_point(&e, pk);
	ret = ret ? ret : mbedtls_ecp_check_pubkey(&e.g, &e.q);
	return ec_free(&e, ret);
}

int tp_be_p256_public_key(uint8_t pk[64], const uint8_t sk[32])
{
	uint8_t buf[65];
	size_t n;
	struct ec e;
	int ret;

	ec_init(&e);
	ret = mbedtls_mpi_read_binary(&e.d, sk, 32);
	ret = ret ? ret : mbedtls_ecp_mul(&e.g, &e.q, &e.d, &e.g.G, host_rng, NULL);
	ret = ret ? ret
		  : mbedtls_ecp_point_write_binary(&e.g, &e.q, MBEDTLS_ECP_PF_UNCOMPRESSED, &n,
						   buf, sizeof(buf));
	if (!ret) {
		memcpy(pk, &buf[1], 64);
	}
	return ec_free(&e, ret);
}

int tp_be_p256_ecdh(uint8_t z[32], const uint8_t sk[32], const uint8_t pk[64])
{
	struct ec e;
	int ret;

	ec_init(&e);
	ret = mbedtls_mpi_read_binary(&e.d, sk, 32);
	ret = ret ? ret : read_point(&e, pk);
	ret = ret ? ret : mbedtls_ecdh_compute_shared(&e.g, &e.r, &e.q, &e.d, host_rng, NULL);
	ret = ret ? ret : mbedtls_mpi_write_binary(&e.r, z, 32);
	return ec_free(&e, ret);
}

int tp_be_p256_sign_hash(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32],
			 const uint8_t ek[32])
{
	struct ec e;
	int ret;

	ec_init(&e);
	ret = mbedtls_mpi_read_binary(&e.d, sk, 32);
	ret = ret ? ret
		  : mbedtls_ecdsa_sign(&e.g, &e.r, &e.s, &e.d, hash, 32, fixed_rng, (void *)ek);
	ret = ret ? ret : mbedtls_mpi_write_binary(&e.r, sig, 32);
	ret = ret ? ret : mbedtls_mpi_write_binary(&e.s, &sig[32], 32);
	return ec_free(&e, ret);
}

void tp_be_p256_sign_hash_det(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32])
{
	struct ec e;
	int ret;

	ec_init(&e);
	ret = mbedtls_mpi_read_binary(&e.d, sk, 32);
	ret = ret ? ret
		  : mbedtls_ecdsa_sign_det_ext(&e.g, &e.r, &e.s, &e.d, hash, 32,
					       MBEDTLS_MD_SHA256, host_rng, NULL);
	ret = ret ? ret : mbedtls_mpi_write_binary(&e.r, sig, 32);
	ret = ret ? ret : mbedtls_mpi_write_binary(&e.s, &sig[32], 32);
	if (ret) {
		abort();
	}
	ec_free(&e, ret);
}

int tp_be_p256_verify_hash(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pk[64])
{
	struct ec e;
	int ret;

	ec_init(&e);
	ret = read_point(&e, pk);
	ret = ret ? ret : mbedtls_mpi_read_binary(&e.r, sig, 32);
	ret = ret ? ret : mbedtls_mpi_read_binary(&e.s, &sig[32], 32);
	ret = ret ? ret : mbedtls_ecdsa_verify(&e.g, hash, 32, &e.q, &e.r, &e.s);
	return ec_free(&e, ret);
}
