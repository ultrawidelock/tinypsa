/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * AES-CCM and AES-GCM, multipart and one-shot. The one-shot calls run the
 * multipart path so there is one implementation of the rules: CCM needs its
 * lengths before data, a nonce is set once, AD precedes the body, and the
 * declared lengths are met exactly.
 */
#include <string.h>

#include "internal.h"

enum {
	ST_ACTIVE = 1 << 0,
	ST_ENCRYPT = 1 << 1,
	ST_NONCE = 1 << 2,
	ST_LENGTHS = 1 << 3,
	ST_STARTED = 1 << 4, /* the backend has its nonce */
	ST_AD = 1 << 5,
	ST_BODY = 1 << 6,
};

static bool is_ccm(const psa_aead_operation_t *op)
{
	return PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(op->alg) == PSA_ALG_CCM;
}

static psa_status_t fail(psa_aead_operation_t *op, psa_status_t st)
{
	psa_aead_abort(op);
	return st;
}

/* The algorithm check made before anything else. */
static psa_status_t check_alg(psa_algorithm_t alg)
{
	return !PSA_ALG_IS_AEAD(alg) || PSA_ALG_IS_WILDCARD(alg) ? PSA_ERROR_INVALID_ARGUMENT
								 : PSA_SUCCESS;
}

static psa_status_t check_tag(psa_algorithm_t alg)
{
	psa_algorithm_t base = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);
	size_t tag = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

	if (base == PSA_ALG_CCM) {
		return tag < 4 || tag > 16 || tag % 2 ? PSA_ERROR_INVALID_ARGUMENT : PSA_SUCCESS;
	}
	if (base == PSA_ALG_GCM) {
		return tag != 4 && tag != 8 && (tag < 12 || tag > 16) ? PSA_ERROR_INVALID_ARGUMENT
								      : PSA_SUCCESS;
	}
	return PSA_ERROR_NOT_SUPPORTED;
}

/*
 * What tinypsa implements: CCM and GCM over AES, with the tags each permits.
 * Mbed TLS checks the tag first for multipart setup and the key type first
 * for one-shot calls, so the order is the caller's.
 */
static psa_status_t check_key_and_tag(psa_algorithm_t alg, psa_key_type_t type, bool tag_first)
{
	psa_status_t st = tag_first ? check_tag(alg) : PSA_SUCCESS;

	if (st == PSA_SUCCESS && type != PSA_KEY_TYPE_AES) {
		st = PSA_ERROR_NOT_SUPPORTED;
	}
	return st == PSA_SUCCESS && !tag_first ? check_tag(alg) : st;
}

/* Checks the key against alg's tag rules; on success the backend holds the key. */
static psa_status_t start_key(psa_aead_operation_t *op, const struct tp_key *k, psa_algorithm_t alg,
			      bool encrypt, bool tag_first)
{
	psa_status_t st = check_key_and_tag(alg, k->type, tag_first);

	if (st == PSA_SUCCESS) {
		op->alg = alg;
		op->state = ST_ACTIVE | (encrypt ? ST_ENCRYPT : 0);
		op->tag_len = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);
		op->key_len = k->len;
		if (is_ccm(op)) {
			tp_be_ccm_key(op->ctx.b, k->data, k->len);
		} else {
			tp_be_gcm_key(op->ctx.b, k->data, k->len);
		}
	}
	return st;
}

static psa_status_t get_key(mbedtls_svc_key_id_t key, psa_algorithm_t alg, bool encrypt,
			    struct tp_key *k)
{
	return tp_key_get(key, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT, alg, k);
}

/* Any setup error aborts the operation, one already running included. */
static psa_status_t setup(psa_aead_operation_t *op, mbedtls_svc_key_id_t key, psa_algorithm_t alg,
			  bool encrypt)
{
	psa_status_t st = check_alg(alg);
	struct tp_key k;

	if (st != PSA_SUCCESS) {
		return fail(op, st);
	}
	if (op->alg != 0) {
		return fail(op, PSA_ERROR_BAD_STATE);
	}
	st = get_key(key, alg, encrypt, &k);
	if (st == PSA_SUCCESS) {
		st = start_key(op, &k, alg, encrypt, true);
	}
	tp_wipe(&k, sizeof(k));
	return st;
}

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation, mbedtls_svc_key_id_t key,
				    psa_algorithm_t alg)
{
	return setup(operation, key, alg, true);
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation, mbedtls_svc_key_id_t key,
				    psa_algorithm_t alg)
{
	return setup(operation, key, alg, false);
}

/*
 * CCM takes its nonce and lengths together, so the nonce waits in the
 * operation until both are known. GCM starts as soon as the nonce arrives.
 */
static psa_status_t ccm_start(psa_aead_operation_t *op)
{
	if ((op->state & (ST_NONCE | ST_LENGTHS)) != (ST_NONCE | ST_LENGTHS)) {
		return PSA_SUCCESS;
	}
	/* The length field is 15 - nonce_len bytes wide. */
	if (op->nonce_len > 11 && op->body_left >> (8 * (15 - op->nonce_len))) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	tp_be_ccm_start(op->ctx.b, op->state & ST_ENCRYPT, op->key_len, op->nonce,
			op->nonce_len, op->tag_len, op->body_left, op->ad_left);
	op->state |= ST_STARTED;
	return PSA_SUCCESS;
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation, const uint8_t *nonce,
				size_t nonce_length)
{
	psa_aead_operation_t *op = operation;
	psa_status_t st;

	if (!(op->state & ST_ACTIVE) || (op->state & ST_NONCE)) {
		return fail(op, PSA_ERROR_BAD_STATE);
	}
	op->state |= ST_NONCE;
	if (!is_ccm(op)) {
		/* GCM accepts any non-empty IV. */
		if (nonce_length == 0) {
			return fail(op, PSA_ERROR_INVALID_ARGUMENT);
		}
		tp_be_gcm_start(op->ctx.b, op->state & ST_ENCRYPT, nonce, nonce_length);
		op->state |= ST_STARTED;
		return PSA_SUCCESS;
	}
	if (nonce_length < 7 || nonce_length > 13) {
		return fail(op, PSA_ERROR_INVALID_ARGUMENT);
	}
	memcpy(op->nonce, nonce, nonce_length);
	op->nonce_len = nonce_length;
	st = ccm_start(op);
	return st == PSA_SUCCESS ? st : fail(op, st);
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation, size_t ad_length,
				  size_t plaintext_length)
{
	psa_aead_operation_t *op = operation;
	psa_status_t st;

	if (!(op->state & ST_ACTIVE) || (op->state & (ST_LENGTHS | ST_AD | ST_BODY))) {
		return fail(op, PSA_ERROR_BAD_STATE);
	}
	op->ad_left = ad_length;
	op->body_left = plaintext_length;
	op->state |= ST_LENGTHS;
	st = is_ccm(op) ? ccm_start(op) : PSA_SUCCESS;
	return st == PSA_SUCCESS ? st : fail(op, st);
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation, const uint8_t *input,
				size_t input_length)
{
	psa_aead_operation_t *op = operation;

	if (!(op->state & ST_STARTED) || (op->state & ST_BODY)) {
		return fail(op, PSA_ERROR_BAD_STATE);
	}
	if (op->state & ST_LENGTHS) {
		if (input_length > op->ad_left) {
			return fail(op, PSA_ERROR_INVALID_ARGUMENT);
		}
		op->ad_left -= input_length;
	}
	op->state |= ST_AD;
	if (is_ccm(op)) {
		tp_be_ccm_update_ad(op->ctx.b, input, input_length);
	} else {
		tp_be_gcm_update_ad(op->ctx.b, input, input_length);
	}
	return PSA_SUCCESS;
}

psa_status_t psa_aead_update(psa_aead_operation_t *operation, const uint8_t *input,
			     size_t input_length, uint8_t *output, size_t output_size,
			     size_t *output_length)
{
	psa_aead_operation_t *op = operation;
	bool enc = op->state & ST_ENCRYPT;

	*output_length = 0;
	if (!(op->state & ST_STARTED)) {
		return fail(op, PSA_ERROR_BAD_STATE);
	}
	if (op->state & ST_LENGTHS) {
		if (op->ad_left) {
			return fail(op, PSA_ERROR_INVALID_ARGUMENT);
		}
		if (input_length > op->body_left) {
			return fail(op, PSA_ERROR_INVALID_ARGUMENT);
		}
	}
	if (output_size < input_length) {
		return fail(op, PSA_ERROR_BUFFER_TOO_SMALL);
	}
	if (op->state & ST_LENGTHS) {
		op->body_left -= input_length;
	}
	op->state |= ST_BODY;
	if (is_ccm(op)) {
		tp_be_ccm_update(op->ctx.b, enc, output, input, input_length);
	} else {
		tp_be_gcm_update(op->ctx.b, enc, output, input, input_length);
	}
	*output_length = input_length;
	return PSA_SUCCESS;
}

/* Common checks for finish and verify, in Mbed TLS's order. */
static psa_status_t can_end(psa_aead_operation_t *op, bool encrypt)
{
	/* CCM never told its lengths cannot produce a tag. */
	if ((op->state & ST_ACTIVE) && is_ccm(op) && !(op->state & ST_LENGTHS)) {
		return PSA_ERROR_BAD_STATE;
	}
	if (!(op->state & ST_NONCE)) {
		return PSA_ERROR_BAD_STATE;
	}
	if ((op->state & ST_LENGTHS) && (op->ad_left || op->body_left)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (!(op->state & ST_ENCRYPT) != !encrypt) {
		return PSA_ERROR_BAD_STATE;
	}
	return PSA_SUCCESS;
}

psa_status_t psa_aead_finish(psa_aead_operation_t *operation, uint8_t *ciphertext,
			     size_t ciphertext_size, size_t *ciphertext_length, uint8_t *tag,
			     size_t tag_size, size_t *tag_length)
{
	psa_aead_operation_t *op = operation;
	psa_status_t st = can_end(op, true);

	(void)ciphertext;
	(void)ciphertext_size;
	*ciphertext_length = 0;
	*tag_length = 0;
	if (st == PSA_SUCCESS && tag_size < op->tag_len) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	}
	if (st == PSA_SUCCESS) {
		if (is_ccm(op)) {
			tp_be_ccm_final_enc(op->ctx.b, tag, op->tag_len);
		} else {
			tp_be_gcm_final_enc(op->ctx.b, tag, op->tag_len);
		}
		*tag_length = op->tag_len;
	}
	psa_aead_abort(op);
	return st;
}

psa_status_t psa_aead_verify(psa_aead_operation_t *operation, uint8_t *plaintext,
			     size_t plaintext_size, size_t *plaintext_length, const uint8_t *tag,
			     size_t tag_length)
{
	psa_aead_operation_t *op = operation;
	psa_status_t st = can_end(op, false);
	int bad;

	(void)plaintext;
	(void)plaintext_size;
	*plaintext_length = 0;
	if (st == PSA_SUCCESS && tag_length != op->tag_len) {
		st = PSA_ERROR_INVALID_SIGNATURE;
	}
	if (st == PSA_SUCCESS) {
		bad = is_ccm(op) ? tp_be_ccm_final_dec(op->ctx.b, tag, tag_length)
				 : tp_be_gcm_final_dec(op->ctx.b, tag, tag_length);
		st = bad ? PSA_ERROR_INVALID_SIGNATURE : PSA_SUCCESS;
	}
	psa_aead_abort(op);
	return st;
}

psa_status_t psa_aead_abort(psa_aead_operation_t *operation)
{
	if (operation->alg != 0) {
		tp_be_ctx_free(operation->ctx.b, sizeof(operation->ctx));
	}
	tp_wipe(operation, sizeof(*operation));
	return PSA_SUCCESS;
}

/*
 * One-shot calls follow Mbed TLS's order: the algorithm, the key, the nonce,
 * the key type, the buffers, and only then the tag length. in_len and
 * out_size are the caller's input length and output buffer size.
 */
static psa_status_t oneshot_start(psa_aead_operation_t *op, mbedtls_svc_key_id_t key,
				  psa_algorithm_t alg, bool encrypt, size_t nonce_length,
				  size_t in_len, size_t out_size)
{
	psa_algorithm_t base = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);
	size_t tag = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);
	struct tp_key k;
	psa_status_t st = check_alg(alg);

	if (st != PSA_SUCCESS) {
		return st;
	}
	st = get_key(key, alg, encrypt, &k);
	if (st == PSA_SUCCESS && base != PSA_ALG_CCM && base != PSA_ALG_GCM) {
		st = PSA_ERROR_NOT_SUPPORTED;
	} else if (st == PSA_SUCCESS && (base == PSA_ALG_CCM ? nonce_length < 7 || nonce_length > 13
							   : nonce_length == 0)) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	} else if (st == PSA_SUCCESS && k.type != PSA_KEY_TYPE_AES) {
		st = PSA_ERROR_NOT_SUPPORTED;
	} else if (st == PSA_SUCCESS && encrypt &&
		   (in_len > SIZE_MAX - tag || out_size < in_len + tag)) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	} else if (st == PSA_SUCCESS && !encrypt && in_len < tag) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	} else if (st == PSA_SUCCESS && !encrypt && out_size < in_len - tag) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	}
	if (st == PSA_SUCCESS) {
		st = start_key(op, &k, alg, encrypt, true);
	}
	tp_wipe(&k, sizeof(k));
	return st;
}

psa_status_t psa_aead_encrypt(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
			      size_t nonce_length, const uint8_t *additional_data,
			      size_t additional_data_length, const uint8_t *plaintext,
			      size_t plaintext_length, uint8_t *ciphertext, size_t ciphertext_size,
			      size_t *ciphertext_length)
{
	psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
	size_t n, tag_len;
	psa_status_t st;

	*ciphertext_length = 0;
	st = oneshot_start(&op, key, alg, true, nonce_length, plaintext_length, ciphertext_size);
	if (st != PSA_SUCCESS) {
		return st;
	}
	tag_len = op.tag_len;
	st = psa_aead_set_lengths(&op, additional_data_length, plaintext_length);
	if (st == PSA_SUCCESS) {
		st = psa_aead_set_nonce(&op, nonce, nonce_length);
	}
	if (st == PSA_SUCCESS) {
		st = psa_aead_update_ad(&op, additional_data, additional_data_length);
	}
	if (st == PSA_SUCCESS) {
		st = psa_aead_update(&op, plaintext, plaintext_length, ciphertext, ciphertext_size,
				     &n);
	}
	if (st == PSA_SUCCESS) {
		st = psa_aead_finish(&op, NULL, 0, &n, &ciphertext[plaintext_length], tag_len, &n);
	}
	if (st == PSA_SUCCESS) {
		*ciphertext_length = plaintext_length + tag_len;
	}
	return st;
}

psa_status_t psa_aead_decrypt(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
			      size_t nonce_length, const uint8_t *additional_data,
			      size_t additional_data_length, const uint8_t *ciphertext,
			      size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size,
			      size_t *plaintext_length)
{
	psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
	size_t n, body;
	psa_status_t st;

	*plaintext_length = 0;
	st = oneshot_start(&op, key, alg, false, nonce_length, ciphertext_length, plaintext_size);
	if (st != PSA_SUCCESS) {
		return st;
	}
	body = ciphertext_length - op.tag_len;
	st = psa_aead_set_lengths(&op, additional_data_length, body);
	if (st == PSA_SUCCESS) {
		st = psa_aead_set_nonce(&op, nonce, nonce_length);
	}
	if (st == PSA_SUCCESS) {
		st = psa_aead_update_ad(&op, additional_data, additional_data_length);
	}
	if (st == PSA_SUCCESS) {
		st = psa_aead_update(&op, ciphertext, body, plaintext, plaintext_size, &n);
	}
	if (st == PSA_SUCCESS) {
		st = psa_aead_verify(&op, NULL, 0, &n, &ciphertext[body], ciphertext_length - body);
	}
	if (st == PSA_SUCCESS) {
		*plaintext_length = body;
	} else {
		/* Never hand back plaintext that failed authentication. */
		tp_wipe(plaintext, plaintext_size < body ? plaintext_size : body);
	}
	return st;
}
