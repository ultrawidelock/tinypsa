/* SPDX-License-Identifier: ISC */
/*
 * What the portable backend still borrows from ocrypto: AES and P-256, until
 * their portable versions land. Same calls as backend_ocrypto.c.
 */
#include <ocrypto_aes_ccm.h>
#include <ocrypto_aes_ecb.h>
#include <ocrypto_aes_gcm.h>
#include <ocrypto_ecdh_p256.h>
#include <ocrypto_ecdsa_p256.h>
#include <ocrypto_ecdsa_p256_det_sign.h>

#include "backend.h"
#include "tinypsa_backend_ctx.h"

_Static_assert(sizeof(ocrypto_aes_ecb_ctx) <= TINYPSA_AES_CTX_SIZE, "aes ctx");
_Static_assert(sizeof(ocrypto_aes_ccm_ctx) <= TINYPSA_CCM_CTX_SIZE, "ccm ctx");
_Static_assert(sizeof(ocrypto_aes_gcm_ctx) <= TINYPSA_GCM_CTX_SIZE, "gcm ctx");

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

void tp_be_p256_sign_hash_det(uint8_t sig[64], const uint8_t hash[32], const uint8_t sk[32])
{
	ocrypto_ecdsa_p256_det_sign_hash(sig, hash, sk);
}

int tp_be_p256_verify_hash(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pk[64])
{
	return ocrypto_ecdsa_p256_verify_hash(sig, hash, pk);
}
