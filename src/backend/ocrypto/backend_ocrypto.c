/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Backend over Nordic's ocrypto (nrf_oberon). Linked from the user's NCS
 * install, never vendored: its license limits use to Nordic chips.
 */
#include <string.h>

#include <ocrypto_aes_ccm.h>
#include <ocrypto_aes_ecb.h>
#include <ocrypto_aes_gcm.h>
#include <ocrypto_curve_p256.h>
#include <ocrypto_ecdh_p256.h>
#include <ocrypto_ecdsa_p256.h>
#include <ocrypto_ecdsa_p256_det_sign.h>
#include <ocrypto_hmac_sha256.h>
#include <ocrypto_sc_p256.h>
#include <ocrypto_sha256.h>
#include <ocrypto_spake2p_p256.h>

#include "backend.h"
#include "tinypsa_backend_ctx.h"

_Static_assert(sizeof(ocrypto_sha256_ctx) <= TINYPSA_SHA256_CTX_SIZE, "sha256 ctx");
_Static_assert(sizeof(ocrypto_hmac_sha256_ctx) <= TINYPSA_HMAC_SHA256_CTX_SIZE, "hmac ctx");
_Static_assert(sizeof(ocrypto_aes_ecb_ctx) <= TINYPSA_AES_CTX_SIZE, "aes ctx");
_Static_assert(sizeof(ocrypto_aes_ccm_ctx) <= TINYPSA_CCM_CTX_SIZE, "ccm ctx");
_Static_assert(sizeof(ocrypto_aes_gcm_ctx) <= TINYPSA_GCM_CTX_SIZE, "gcm ctx");

void tp_be_sha256_init(void *ctx)
{
	ocrypto_sha256_init(ctx);
}

void tp_be_sha256_update(void *ctx, const uint8_t *in, size_t len)
{
	ocrypto_sha256_update(ctx, in, len);
}

void tp_be_sha256_final(void *ctx, uint8_t out[32])
{
	ocrypto_sha256_final(ctx, out);
}

void tp_be_hmac_sha256_init(void *ctx, const uint8_t *key, size_t key_len)
{
	ocrypto_hmac_sha256_init(ctx, key, key_len);
}

void tp_be_hmac_sha256_update(void *ctx, const uint8_t *in, size_t len)
{
	ocrypto_hmac_sha256_update(ctx, in, len);
}

void tp_be_hmac_sha256_final(void *ctx, uint8_t out[32])
{
	ocrypto_hmac_sha256_final(ctx, out);
}

void tp_be_aes_init(void *ctx, const uint8_t *key, size_t key_len)
{
	ocrypto_aes_ecb_init_enc(ctx, key, key_len);
}

void tp_be_aes_encrypt(void *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
	ocrypto_aes_ecb_update_enc(ctx, out, in, len);
}

void tp_be_ccm_key(void *ctx, const uint8_t *key, size_t key_len)
{
	ocrypto_aes_ccm_init(ctx, key, key_len, NULL, 0, 0, 0, 0);
}

void tp_be_ccm_start(void *ctx, int encrypt, size_t key_len, const uint8_t *nonce,
		     size_t nonce_len, size_t tag_len, size_t pt_len, size_t ad_len)
{
	(void)encrypt;
	ocrypto_aes_ccm_init(ctx, NULL, key_len, nonce, nonce_len, tag_len, pt_len, ad_len);
}

void tp_be_ccm_update_ad(void *ctx, const uint8_t *ad, size_t len)
{
	ocrypto_aes_ccm_update_aad(ctx, ad, len);
}

void tp_be_ccm_update(void *ctx, int encrypt, uint8_t *out, const uint8_t *in, size_t len)
{
	if (encrypt) {
		ocrypto_aes_ccm_update_enc(ctx, out, in, len);
	} else {
		ocrypto_aes_ccm_update_dec(ctx, out, in, len);
	}
}

void tp_be_ccm_final_enc(void *ctx, uint8_t *tag, size_t tag_len)
{
	ocrypto_aes_ccm_final_enc(ctx, tag, tag_len);
}

int tp_be_ccm_final_dec(void *ctx, const uint8_t *tag, size_t tag_len)
{
	return ocrypto_aes_ccm_final_dec(ctx, tag, tag_len);
}

void tp_be_gcm_key(void *ctx, const uint8_t *key, size_t key_len)
{
	ocrypto_aes_gcm_init(ctx, key, key_len, NULL);
}

void tp_be_gcm_start(void *ctx, int encrypt, const uint8_t *iv, size_t iv_len)
{
	(void)encrypt;
	ocrypto_aes_gcm_init_iv(ctx, iv, iv_len);
}

void tp_be_gcm_update_ad(void *ctx, const uint8_t *ad, size_t len)
{
	ocrypto_aes_gcm_update_aad(ctx, ad, len);
}

void tp_be_gcm_update(void *ctx, int encrypt, uint8_t *out, const uint8_t *in, size_t len)
{
	if (encrypt) {
		ocrypto_aes_gcm_update_enc(ctx, out, in, len);
	} else {
		ocrypto_aes_gcm_update_dec(ctx, out, in, len);
	}
}

void tp_be_gcm_final_enc(void *ctx, uint8_t *tag, size_t tag_len)
{
	ocrypto_aes_gcm_final_enc(ctx, tag, tag_len);
}

int tp_be_gcm_final_dec(void *ctx, const uint8_t *tag, size_t tag_len)
{
	return ocrypto_aes_gcm_final_dec(ctx, tag, tag_len);
}

void tp_be_ctx_free(void *ctx, size_t size)
{
	(void)ctx;
	(void)size;
}

int tp_be_p256_sk_check(const uint8_t sk[32])
{
	return ocrypto_ecdh_p256_secret_key_check(sk);
}

int tp_be_p256_pk_check(const uint8_t pk[64])
{
	return ocrypto_ecdh_p256_public_key_check(pk);
}

int tp_be_p256_public_key(uint8_t pk[64], const uint8_t sk[32])
{
	return ocrypto_ecdh_p256_public_key(pk, sk);
}

int tp_be_p256_ecdh(uint8_t z[32], const uint8_t sk[32], const uint8_t pk[64])
{
	return ocrypto_ecdh_p256_common_secret(z, sk, pk);
}

int tp_be_p256_sign_hash(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32],
			 const uint8_t ek[32])
{
	return ocrypto_ecdsa_p256_sign_hash(sig, hash, sk, ek);
}

int tp_be_p256_verify_hash(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pk[64])
{
	return ocrypto_ecdsa_p256_verify_hash(sig, hash, pk);
}

int tp_be_p256_mul(uint8_t r[64], const uint8_t k[32], const uint8_t p[64])
{
	ocrypto_cp_p256 a, b;
	ocrypto_sc_p256 s;

	/* scalarmult fails for k = 0, from32bytes for k >= n. */
	if (ocrypto_curve_p256_from64bytes(&a, p) || ocrypto_sc_p256_from32bytes(&s, k) ||
	    ocrypto_curve_p256_scalarmult(&b, &a, &s)) {
		return -1;
	}
	ocrypto_curve_p256_to64bytes(r, &b);
	return 0;
}

/*
 * ocrypto declares no point addition, so this takes it from its SPAKE2+:
 * get_ZV gives Z = xy*(YX - w0*NM), here with xy = 1 and w0 = 1 for P - Q
 * or n - 1 for P + Q. Its V, with w1 = 1, is a spare copy of Z.
 */
int tp_be_p256_add(uint8_t r[64], const uint8_t p[64], const uint8_t q[64], int sub)
{
	static const uint8_t one[32] = { [31] = 1 };
	static const uint8_t n_minus_1[32] = {
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
		0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50,
	};
	uint8_t z[65], v[65], yx[65] = { 0x04 }, nm[65] = { 0x04 };

	memcpy(&yx[1], p, 64);
	memcpy(&nm[1], q, 64);
	if (ocrypto_spake2p_p256_get_ZV(z, v, sub ? one : n_minus_1, one, one, yx, nm, NULL)) {
		return -1;
	}
	memcpy(r, &z[1], 64);
	return 0;
}

void tp_be_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len)
{
	ocrypto_spake2p_p256_reduce(x, xs, xs_len);
}
