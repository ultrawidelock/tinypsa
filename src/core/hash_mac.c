/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Hashing (SHA-256 only), MAC signing (HMAC-SHA-256 and AES-CMAC), and the
 * one-shot AES-ECB cipher. Every error past setup aborts the operation, so a
 * caller that forgets psa_*_abort() leaves nothing half-done behind.
 */
#include <string.h>

#include "internal.h"

/* ---- hash ------------------------------------------------------------------ */

psa_status_t psa_hash_setup(psa_hash_operation_t *operation, psa_algorithm_t alg)
{
	/* Any setup error aborts, an operation already running included. */
	if (operation->alg != 0) {
		psa_hash_abort(operation);
		return PSA_ERROR_BAD_STATE;
	}
	if (alg != PSA_ALG_SHA_256) {
		return PSA_ALG_IS_HASH(alg) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT;
	}
	tp_be_sha256_init(operation->ctx.b);
	operation->alg = alg;
	return PSA_SUCCESS;
}

psa_status_t psa_hash_update(psa_hash_operation_t *operation, const uint8_t *input,
			     size_t input_length)
{
	if (operation->alg == 0) {
		return PSA_ERROR_BAD_STATE;
	}
	tp_be_sha256_update(operation->ctx.b, input, input_length);
	return PSA_SUCCESS;
}

psa_status_t psa_hash_finish(psa_hash_operation_t *operation, uint8_t *hash, size_t hash_size,
			     size_t *hash_length)
{
	psa_status_t st = PSA_SUCCESS;

	*hash_length = 0;
	if (operation->alg == 0) {
		return PSA_ERROR_BAD_STATE;
	}
	if (hash_size < 32) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	} else {
		tp_be_sha256_final(operation->ctx.b, hash);
		*hash_length = 32;
	}
	psa_hash_abort(operation);
	return st;
}

psa_status_t psa_hash_abort(psa_hash_operation_t *operation)
{
	tp_wipe(operation, sizeof(*operation));
	return PSA_SUCCESS;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length,
			      uint8_t *hash, size_t hash_size, size_t *hash_length)
{
	psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
	psa_status_t st;

	*hash_length = 0;
	st = psa_hash_setup(&op, alg);
	if (st == PSA_SUCCESS) {
		psa_hash_update(&op, input, input_length);
		st = psa_hash_finish(&op, hash, hash_size, hash_length);
	}
	return st;
}

/* ---- CMAC (SP 800-38B) --------------------------------------------------------- */

void tp_cmac_start(struct tinypsa_cmac_ctx *c, const uint8_t *key, size_t key_len)
{
	tp_be_aes_init(c->aes.b, key, key_len);
	memset(c->x, 0, sizeof(c->x));
	c->n = 0;
}

void tp_cmac_update(struct tinypsa_cmac_ctx *c, const uint8_t *in, size_t len)
{
	/* The last block is held back: finish treats it differently. */
	while (len) {
		if (c->n == 16) {
			for (int i = 0; i < 16; i++) {
				c->x[i] ^= c->buf[i];
			}
			tp_be_aes_encrypt(c->aes.b, c->x, c->x, 16);
			c->n = 0;
		}
		size_t take = 16 - c->n < len ? 16 - c->n : len;

		memcpy(&c->buf[c->n], in, take);
		c->n += take;
		in += take;
		len -= take;
	}
}

/* Doubling in GF(2^128), constant time. */
static void dbl(uint8_t out[16], const uint8_t in[16])
{
	uint8_t carry = in[0] >> 7;

	for (int i = 0; i < 15; i++) {
		out[i] = (in[i] << 1) | (in[i + 1] >> 7);
	}
	out[15] = (in[15] << 1) ^ (0x87 & -carry);
}

void tp_cmac_subkey(struct tinypsa_cmac_ctx *c, uint8_t k1[16])
{
	memset(k1, 0, 16);
	tp_be_aes_encrypt(c->aes.b, k1, k1, 16);
	dbl(k1, k1);
}

void tp_cmac_finish(struct tinypsa_cmac_ctx *c, uint8_t tag[16])
{
	uint8_t k[16];

	tp_cmac_subkey(c, k);
	if (c->n < 16) {
		dbl(k, k);
		c->buf[c->n] = 0x80;
		memset(&c->buf[c->n + 1], 0, 15 - c->n);
	}
	for (int i = 0; i < 16; i++) {
		c->x[i] ^= c->buf[i] ^ k[i];
	}
	tp_be_aes_encrypt(c->aes.b, tag, c->x, 16);
	tp_wipe(k, sizeof(k));
}

/* ---- MAC --------------------------------------------------------------------- */

/*
 * Key and policy first, then whether alg is a MAC that suits the key, then
 * its length, then (for a one-shot call) the output buffer, then whether
 * tinypsa implements it: the order Mbed TLS reports errors in.
 */
static psa_status_t mac_start(psa_mac_operation_t *op, mbedtls_svc_key_id_t key,
			      psa_algorithm_t alg, size_t out_size)
{
	psa_algorithm_t full_alg = PSA_ALG_FULL_LENGTH_MAC(alg);
	struct tp_key k;
	size_t full, len;
	psa_status_t st;

	st = tp_key_get(key, PSA_KEY_USAGE_SIGN_MESSAGE, alg, &k);
	if (st == PSA_SUCCESS && (!PSA_ALG_IS_MAC(alg) || !tp_mac_can_do(alg, k.type))) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	}
	if (st == PSA_SUCCESS) {
		full = PSA_MAC_LENGTH(k.type, k.bits, full_alg);
		len = PSA_MAC_LENGTH(k.type, k.bits, alg);
		if (len < 4) {
			st = PSA_ERROR_NOT_SUPPORTED;
		} else if (len > full) {
			st = PSA_ERROR_INVALID_ARGUMENT;
		} else if (out_size < len) {
			st = PSA_ERROR_BUFFER_TOO_SMALL;
		} else if (!(full_alg == PSA_ALG_HMAC(PSA_ALG_SHA_256)) &&
			   !(full_alg == PSA_ALG_CMAC && k.type == PSA_KEY_TYPE_AES)) {
			st = PSA_ERROR_NOT_SUPPORTED;
		}
	}
	if (st == PSA_SUCCESS) {
		op->alg = alg;
		op->mac_len = len;
		if (PSA_ALG_IS_HMAC(alg)) {
			tp_be_hmac_sha256_init(op->ctx.hmac, k.data, k.len);
		} else {
			tp_cmac_start(&op->ctx.cmac, k.data, k.len);
		}
	}
	tp_wipe(&k, sizeof(k));
	return st;
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation, mbedtls_svc_key_id_t key,
				psa_algorithm_t alg)
{
	if (operation->alg != 0) {
		psa_mac_abort(operation);
		return PSA_ERROR_BAD_STATE;
	}
	return mac_start(operation, key, alg, SIZE_MAX);
}

static bool is_hmac(const psa_mac_operation_t *op)
{
	return PSA_ALG_IS_HMAC(op->alg);
}

psa_status_t psa_mac_update(psa_mac_operation_t *operation, const uint8_t *input,
			    size_t input_length)
{
	if (operation->alg == 0) {
		return PSA_ERROR_BAD_STATE;
	}
	if (is_hmac(operation)) {
		tp_be_hmac_sha256_update(operation->ctx.hmac, input, input_length);
	} else {
		tp_cmac_update(&operation->ctx.cmac, input, input_length);
	}
	return PSA_SUCCESS;
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation, uint8_t *mac, size_t mac_size,
				 size_t *mac_length)
{
	uint8_t full[32];
	psa_status_t st = PSA_SUCCESS;

	*mac_length = 0;
	if (operation->alg == 0) {
		return PSA_ERROR_BAD_STATE;
	}
	if (mac_size < operation->mac_len) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	} else {
		if (is_hmac(operation)) {
			tp_be_hmac_sha256_final(operation->ctx.hmac, full);
		} else {
			tp_cmac_finish(&operation->ctx.cmac, full);
		}
		memcpy(mac, full, operation->mac_len);
		*mac_length = operation->mac_len;
		tp_wipe(full, sizeof(full));
	}
	psa_mac_abort(operation);
	return st;
}

psa_status_t psa_mac_abort(psa_mac_operation_t *operation)
{
	tp_wipe(operation, sizeof(*operation));
	return PSA_SUCCESS;
}

psa_status_t psa_mac_compute(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
			     size_t input_length, uint8_t *mac, size_t mac_size, size_t *mac_length)
{
	psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
	psa_status_t st;

	*mac_length = 0;
	st = mac_start(&op, key, alg, mac_size);
	if (st == PSA_SUCCESS) {
		psa_mac_update(&op, input, input_length);
		st = psa_mac_sign_finish(&op, mac, mac_size, mac_length);
	}
	return st;
}

/* ---- cipher ------------------------------------------------------------------ */

psa_status_t psa_cipher_encrypt(mbedtls_svc_key_id_t key, psa_algorithm_t alg,
				const uint8_t *input, size_t input_length, uint8_t *output,
				size_t output_size, size_t *output_length)
{
	uint8_t ctx[TINYPSA_AES_CTX_SIZE] __attribute__((aligned(8)));
	size_t iv_len, whole = input_length - input_length % 16;
	struct tp_key k;
	psa_status_t st;

	*output_length = 0;
	if (!PSA_ALG_IS_CIPHER(alg)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	st = tp_key_get(key, PSA_KEY_USAGE_ENCRYPT, alg, &k);
	if (st == PSA_SUCCESS) {
		/* An IV-based mode would write its IV first. */
		iv_len = PSA_CIPHER_IV_LENGTH(k.type, alg);
		if (iv_len > 0 && output_size < iv_len) {
			st = PSA_ERROR_BUFFER_TOO_SMALL;
		} else if (alg != PSA_ALG_ECB_NO_PADDING || k.type != PSA_KEY_TYPE_AES) {
			st = PSA_ERROR_NOT_SUPPORTED;
		} else if (output_size < whole) {
			st = PSA_ERROR_BUFFER_TOO_SMALL;
		} else if (whole != input_length) {
			st = PSA_ERROR_INVALID_ARGUMENT;
		}
	}
	if (st == PSA_SUCCESS) {
		tp_be_aes_init(ctx, k.data, k.len);
		tp_be_aes_encrypt(ctx, output, input, input_length);
		*output_length = input_length;
		tp_wipe(ctx, sizeof(ctx));
	}
	tp_wipe(&k, sizeof(k));
	return st;
}
