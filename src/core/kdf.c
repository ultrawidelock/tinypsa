/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Key derivation: PBKDF2-AES-CMAC-PRF-128 (RFC 8018 with the RFC 4615 PRF),
 * which OpenThread uses for the PSKc, and HKDF-SHA-256 (RFC 5869) when
 * PSA_WANT_ALG_HKDF asks for it. Output streams: each call continues where
 * the last one stopped. As in Mbed TLS, a failed input aborts the operation
 * outright, while a failed output clears it down to its algorithm, so later
 * outputs fail rather than repeat bytes.
 */
#include <string.h>

#include "internal.h"

enum {
	S_COST = 1 << 0,
	S_SALT = 1 << 1,
	S_KEYED = 1 << 2, /* HKDF PRK or PBKDF2 K' is ready */
	S_INFO = 1 << 3,
	S_OUTPUT = 1 << 4,
};

#define PBKDF2 PSA_ALG_PBKDF2_AES_CMAC_PRF_128
#define HKDF   PSA_ALG_HKDF(PSA_ALG_SHA_256)

static bool hkdf_wanted(psa_algorithm_t alg)
{
#if defined(PSA_WANT_ALG_HKDF)
	return alg == HKDF;
#else
	(void)alg;
	return false;
#endif
}

psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t *operation,
				      psa_algorithm_t alg)
{
	if (operation->alg != 0) {
		return PSA_ERROR_BAD_STATE;
	}
	if (PSA_ALG_IS_KEY_AGREEMENT(alg)) {
		/* A raw agreement is no KDF; one feeding a KDF is not provided. */
		return PSA_ALG_IS_RAW_KEY_AGREEMENT(alg) ? PSA_ERROR_INVALID_ARGUMENT
							 : PSA_ERROR_NOT_SUPPORTED;
	}
	if (!PSA_ALG_IS_KEY_DERIVATION(alg)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (alg == PBKDF2) {
		/* (2^32 - 1) blocks of 16 bytes, clipped to what size_t holds. */
		operation->capacity = SIZE_MAX / 16 < UINT32_MAX ? SIZE_MAX : (size_t)UINT32_MAX * 16;
	} else if (hkdf_wanted(alg)) {
		operation->capacity = 255 * 32;
	} else {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	operation->alg = alg;
	return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t *operation)
{
	tp_wipe(operation, sizeof(*operation));
	return PSA_SUCCESS;
}

/* After a failed output: nothing more comes out, but the operation is not blank. */
static psa_status_t drain(psa_key_derivation_operation_t *op, psa_status_t st)
{
	psa_algorithm_t alg = op->alg;

	psa_key_derivation_abort(op);
	op->alg = alg;
	return st;
}

/* After a failed input: blank again. */
static psa_status_t fail(psa_key_derivation_operation_t *op, psa_status_t st)
{
	psa_key_derivation_abort(op);
	return st;
}

/* Which steps take which key types; PSA_KEY_TYPE_NONE stands for raw bytes. */
static psa_status_t check_input_type(psa_key_derivation_step_t step, psa_key_type_t type)
{
	switch (step) {
	case PSA_KEY_DERIVATION_INPUT_SECRET:
	case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
		return type == PSA_KEY_TYPE_DERIVE || type == PSA_KEY_TYPE_NONE
			       ? PSA_SUCCESS
			       : PSA_ERROR_INVALID_ARGUMENT;
	case PSA_KEY_DERIVATION_INPUT_LABEL:
	case PSA_KEY_DERIVATION_INPUT_SALT:
	case PSA_KEY_DERIVATION_INPUT_INFO:
	case PSA_KEY_DERIVATION_INPUT_SEED:
		return type == PSA_KEY_TYPE_RAW_DATA || type == PSA_KEY_TYPE_NONE
			       ? PSA_SUCCESS
			       : PSA_ERROR_INVALID_ARGUMENT;
	case PSA_KEY_DERIVATION_INPUT_PASSWORD:
		return type == PSA_KEY_TYPE_PASSWORD || type == PSA_KEY_TYPE_DERIVE ||
				       type == PSA_KEY_TYPE_NONE
			       ? PSA_SUCCESS
			       : PSA_ERROR_INVALID_ARGUMENT;
	default:
		return PSA_ERROR_INVALID_ARGUMENT;
	}
}

static psa_status_t append(psa_key_derivation_operation_t *op, uint8_t *len, const uint8_t *data,
			   size_t n)
{
	size_t used = op->salt_len + op->info_len;

	if (n > sizeof(op->buf) - used) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	memcpy(&op->buf[used], data, n);
	*len += n;
	return PSA_SUCCESS;
}

/* RFC 4615: a password of any length becomes a 16-byte AES key. */
static void pbkdf2_key(psa_key_derivation_operation_t *op, const uint8_t *p, size_t n)
{
	static const uint8_t zero[16];
	struct tinypsa_cmac_ctx c;

	if (n == 16) {
		memcpy(op->key, p, 16);
		return;
	}
	tp_cmac_start(&c, zero, sizeof(zero));
	tp_cmac_update(&c, p, n);
	tp_cmac_finish(&c, op->key);
	tp_wipe(&c, sizeof(c));
}

#if defined(PSA_WANT_ALG_HKDF)
/* Extract: PRK = HMAC(salt, IKM). Any info that arrived early moves to buf[0]. */
static void hkdf_extract(psa_key_derivation_operation_t *op, const uint8_t *ikm, size_t n)
{
	uint8_t ctx[TINYPSA_HMAC_SHA256_CTX_SIZE] __attribute__((aligned(8)));

	tp_be_hmac_sha256_init(ctx, op->buf, op->salt_len);
	tp_be_hmac_sha256_update(ctx, ikm, n);
	tp_be_hmac_sha256_final(ctx, op->key);
	tp_wipe(ctx, sizeof(ctx));
	memmove(op->buf, &op->buf[op->salt_len], op->info_len);
	tp_wipe(&op->buf[op->info_len], op->salt_len);
	op->salt_len = 0;
}
#endif

static psa_status_t input(psa_key_derivation_operation_t *op, psa_key_derivation_step_t step,
			  psa_key_type_t type, const uint8_t *data, size_t n)
{
	psa_status_t st;

	if (op->alg == 0) {
		return PSA_ERROR_BAD_STATE;
	}
	st = check_input_type(step, type);
	if (st != PSA_SUCCESS) {
		return st;
	}
	/* Each step's own state check follows; output implies keyed, so it is covered. */
	if (op->alg == PBKDF2) {
		if (step == PSA_KEY_DERIVATION_INPUT_SALT) {
			if (!(op->steps & S_COST) || (op->steps & S_KEYED)) {
				return PSA_ERROR_BAD_STATE;
			}
			op->steps |= S_SALT;
			return append(op, &op->salt_len, data, n);
		}
		if (step == PSA_KEY_DERIVATION_INPUT_PASSWORD) {
			if (!(op->steps & S_SALT) || (op->steps & S_KEYED)) {
				return PSA_ERROR_BAD_STATE;
			}
			pbkdf2_key(op, data, n);
			op->steps |= S_KEYED;
			return PSA_SUCCESS;
		}
		return PSA_ERROR_INVALID_ARGUMENT;
	}
#if defined(PSA_WANT_ALG_HKDF)
	switch (step) {
	case PSA_KEY_DERIVATION_INPUT_SALT:
		if (op->steps & (S_SALT | S_KEYED)) {
			return PSA_ERROR_BAD_STATE;
		}
		op->steps |= S_SALT;
		/* Salt sits before any info already in buf. */
		if (n > sizeof(op->buf) - op->info_len) {
			return PSA_ERROR_NOT_SUPPORTED;
		}
		memmove(&op->buf[n], op->buf, op->info_len);
		memcpy(op->buf, data, n);
		op->salt_len = n;
		return PSA_SUCCESS;
	case PSA_KEY_DERIVATION_INPUT_SECRET:
		if (op->steps & S_KEYED) {
			return PSA_ERROR_BAD_STATE;
		}
		hkdf_extract(op, data, n);
		op->steps |= S_KEYED;
		return PSA_SUCCESS;
	case PSA_KEY_DERIVATION_INPUT_INFO:
		if (op->steps & (S_INFO | S_OUTPUT)) {
			return PSA_ERROR_BAD_STATE;
		}
		op->steps |= S_INFO;
		return append(op, &op->info_len, data, n);
	default:
		return PSA_ERROR_INVALID_ARGUMENT;
	}
#else
	return PSA_ERROR_BAD_STATE;
#endif
}

psa_status_t psa_key_derivation_input_bytes(psa_key_derivation_operation_t *operation,
					    psa_key_derivation_step_t step, const uint8_t *data,
					    size_t data_length)
{
	psa_status_t st = input(operation, step, PSA_KEY_TYPE_NONE, data, data_length);

	return st == PSA_SUCCESS ? st : fail(operation, st);
}

psa_status_t psa_key_derivation_input_integer(psa_key_derivation_operation_t *operation,
					      psa_key_derivation_step_t step, uint64_t value)
{
	psa_key_derivation_operation_t *op = operation;

	if (op->alg != PBKDF2 || step != PSA_KEY_DERIVATION_INPUT_COST) {
		return fail(op, op->alg == 0 ? PSA_ERROR_BAD_STATE : PSA_ERROR_INVALID_ARGUMENT);
	}
	if (op->steps != 0) {
		return fail(op, PSA_ERROR_BAD_STATE);
	}
	if (value > UINT32_MAX) {
		return fail(op, PSA_ERROR_NOT_SUPPORTED);
	}
	if (value == 0) {
		return fail(op, PSA_ERROR_INVALID_ARGUMENT);
	}
	op->cost = value;
	op->steps |= S_COST;
	return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_input_key(psa_key_derivation_operation_t *operation,
					  psa_key_derivation_step_t step, mbedtls_svc_key_id_t key)
{
	struct tp_key k;
	psa_status_t st;

	st = tp_key_get(key, PSA_KEY_USAGE_DERIVE, operation->alg, &k);
	if (st == PSA_SUCCESS) {
		st = input(operation, step, k.type, k.data, k.len);
	}
	tp_wipe(&k, sizeof(k));
	return st == PSA_SUCCESS ? st : fail(operation, st);
}

/* Fills op->blk with the next block of output. */
static void next_block(psa_key_derivation_operation_t *op)
{
	op->counter++;
	if (op->alg == PBKDF2) {
		struct tinypsa_cmac_ctx c;
		uint8_t u[16], k1[16], be[4] = {
			op->counter >> 24, op->counter >> 16, op->counter >> 8, op->counter
		};

		/* U1 = PRF(K', salt || INT(i)) */
		tp_cmac_start(&c, op->key, 16);
		tp_cmac_update(&c, op->buf, op->salt_len);
		tp_cmac_update(&c, be, sizeof(be));
		tp_cmac_finish(&c, u);
		memcpy(op->blk, u, 16);
		/* Uj = PRF(K', Uj-1): one whole block, so CMAC is AES(Uj-1 ^ K1). */
		tp_cmac_start(&c, op->key, 16);
		tp_cmac_subkey(&c, k1);
		for (uint32_t j = 1; j < op->cost; j++) {
			for (int i = 0; i < 16; i++) {
				u[i] ^= k1[i];
			}
			tp_be_aes_encrypt(c.aes.b, u, u, 16);
			for (int i = 0; i < 16; i++) {
				op->blk[i] ^= u[i];
			}
		}
		tp_wipe(&c, sizeof(c));
		tp_wipe(u, sizeof(u));
		tp_wipe(k1, sizeof(k1));
		return;
	}
#if defined(PSA_WANT_ALG_HKDF)
	/* T(i) = HMAC(PRK, T(i-1) || info || i) */
	uint8_t ctx[TINYPSA_HMAC_SHA256_CTX_SIZE] __attribute__((aligned(8)));
	uint8_t i = op->counter;

	tp_be_hmac_sha256_init(ctx, op->key, 32);
	if (op->counter > 1) {
		tp_be_hmac_sha256_update(ctx, op->blk, 32);
	}
	tp_be_hmac_sha256_update(ctx, op->buf, op->info_len);
	tp_be_hmac_sha256_update(ctx, &i, 1);
	tp_be_hmac_sha256_final(ctx, op->blk);
	tp_wipe(ctx, sizeof(ctx));
#endif
}

psa_status_t psa_key_derivation_output_bytes(psa_key_derivation_operation_t *operation,
					     uint8_t *output, size_t output_length)
{
	psa_key_derivation_operation_t *op = operation;
	size_t blk_len = op->alg == PBKDF2 ? 16 : 32;
	uint8_t need = op->alg == PBKDF2 ? S_KEYED : S_KEYED | S_INFO;

	if (op->alg == 0) {
		return PSA_ERROR_BAD_STATE;
	}
	/* A drained operation lands here too: its capacity is 0. */
	if (output_length > op->capacity || (output_length == 0 && op->capacity == 0)) {
		tp_wipe(output, output_length);
		return drain(op, PSA_ERROR_INSUFFICIENT_DATA);
	}
	if ((op->steps & need) != need) {
		return drain(op, PSA_ERROR_BAD_STATE);
	}
	if (!(op->steps & S_OUTPUT)) {
		op->steps |= S_OUTPUT;
		op->blk_used = blk_len;
	}
	op->capacity -= output_length;
	while (output_length) {
		if (op->blk_used == blk_len) {
			next_block(op);
			op->blk_used = 0;
		}
		size_t n = blk_len - op->blk_used < output_length ? blk_len - op->blk_used
								     : output_length;

		memcpy(output, &op->blk[op->blk_used], n);
		op->blk_used += n;
		output += n;
		output_length -= n;
	}
	return PSA_SUCCESS;
}
