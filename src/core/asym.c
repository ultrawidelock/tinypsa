/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ECDSA over P-256, randomized and deterministic (RFC 6979 with SHA-256),
 * and raw ECDH. Signatures are r || s, 64 bytes. Checks run in the order
 * Mbed TLS reports them: the algorithm family, the key and its policy, the
 * key type, then the specifics.
 */
#include <string.h>

#include <tinypsa/prim.h>

#include "internal.h"

/* The algorithm checks made before the key is looked at. */
static psa_status_t check_sign_alg(psa_algorithm_t alg, bool message)
{
	psa_algorithm_t hash = PSA_ALG_IS_SIGN_HASH(alg) ? PSA_ALG_SIGN_GET_HASH(alg) : 0;

	if (message && !PSA_ALG_IS_SIGN_MESSAGE(alg)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if ((hash == 0 && message) || hash == PSA_ALG_ANY_HASH) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (hash != 0 && hash != PSA_ALG_SHA_256) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	return PSA_SUCCESS;
}

/* What the key and algorithm allow once both are known. */
static psa_status_t check_ecdsa(const struct tp_key *k, psa_algorithm_t alg)
{
	if (!PSA_KEY_TYPE_IS_ECC(k->type)) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	if (!PSA_ALG_IS_ECDSA(alg)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	/* The backend's RFC 6979 is fixed to SHA-256. */
	if (PSA_ALG_IS_DETERMINISTIC_ECDSA(alg) && PSA_ALG_SIGN_GET_HASH(alg) != PSA_ALG_SHA_256) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	return PSA_SUCCESS;
}

/*
 * ECDSA reads the hash as an integer cut to the curve's 256 bits, so a short
 * hash is left-padded and a long one keeps its leading bytes.
 */
static void fit_hash(uint8_t out[32], const uint8_t *hash, size_t len)
{
	memset(out, 0, 32);
	if (len >= 32) {
		memcpy(out, hash, 32);
	} else {
		memcpy(&out[32 - len], hash, len);
	}
}

static psa_status_t sign(mbedtls_svc_key_id_t key, psa_algorithm_t alg, bool message,
			 const uint8_t *input, size_t input_length, uint8_t *signature,
			 size_t signature_size, size_t *signature_length)
{
	uint8_t hash[32], ek[32];
	struct tp_key k;
	size_t n;
	psa_status_t st;

	*signature_length = 0;
	st = check_sign_alg(alg, message);
	if (st != PSA_SUCCESS) {
		return st;
	}
	if (signature_size == 0) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}
	st = tp_key_get(key, message ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_SIGN_HASH, alg,
			&k);
	if (st == PSA_SUCCESS && !PSA_KEY_TYPE_IS_KEY_PAIR(k.type)) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	}
	if (st == PSA_SUCCESS) {
		st = check_ecdsa(&k, alg);
	}
	if (st == PSA_SUCCESS && signature_size < 64) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	}
	if (st == PSA_SUCCESS && message) {
		st = psa_hash_compute(PSA_ALG_SHA_256, input, input_length, hash, sizeof(hash), &n);
	} else if (st == PSA_SUCCESS) {
		fit_hash(hash, input, input_length);
	}
	if (st == PSA_SUCCESS && PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
		tinypsa_p256_sign_hash_det(signature, hash, k.data);
	} else if (st == PSA_SUCCESS) {
		/* A draw outside [1, n-1] is rejected by the backend; draw again. */
		do {
			st = tp_random(ek, sizeof(ek));
		} while (st == PSA_SUCCESS && tp_be_p256_sign_hash(signature, hash, k.data, ek));
		tp_wipe(ek, sizeof(ek));
	}
	if (st == PSA_SUCCESS) {
		*signature_length = 64;
	}
	tp_wipe(&k, sizeof(k));
	return st;
}

static psa_status_t verify(mbedtls_svc_key_id_t key, psa_algorithm_t alg, bool message,
			   const uint8_t *input, size_t input_length, const uint8_t *signature,
			   size_t signature_length)
{
	uint8_t hash[32], pk[64];
	struct tp_key k;
	size_t n;
	psa_status_t st;

	st = check_sign_alg(alg, message);
	if (st != PSA_SUCCESS) {
		return st;
	}
	st = tp_key_get(key, message ? PSA_KEY_USAGE_VERIFY_MESSAGE : PSA_KEY_USAGE_VERIFY_HASH,
			alg, &k);
	if (st == PSA_SUCCESS) {
		st = check_ecdsa(&k, alg);
	}
	if (st == PSA_SUCCESS && message) {
		st = psa_hash_compute(PSA_ALG_SHA_256, input, input_length, hash, sizeof(hash), &n);
	} else if (st == PSA_SUCCESS) {
		fit_hash(hash, input, input_length);
	}
	if (st == PSA_SUCCESS && signature_length != 64) {
		st = PSA_ERROR_INVALID_SIGNATURE;
	}
	if (st == PSA_SUCCESS) {
		st = tp_key_p256_point(&k, pk);
	}
	if (st == PSA_SUCCESS && tp_be_p256_verify_hash(signature, hash, pk)) {
		st = PSA_ERROR_INVALID_SIGNATURE;
	}
	tp_wipe(&k, sizeof(k));
	return st;
}

psa_status_t psa_sign_hash(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *hash,
			   size_t hash_length, uint8_t *signature, size_t signature_size,
			   size_t *signature_length)
{
	return sign(key, alg, false, hash, hash_length, signature, signature_size,
		    signature_length);
}

psa_status_t psa_verify_hash(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *hash,
			     size_t hash_length, const uint8_t *signature, size_t signature_length)
{
	return verify(key, alg, false, hash, hash_length, signature, signature_length);
}

psa_status_t psa_sign_message(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
			      size_t input_length, uint8_t *signature, size_t signature_size,
			      size_t *signature_length)
{
	return sign(key, alg, true, input, input_length, signature, signature_size,
		    signature_length);
}

psa_status_t psa_verify_message(mbedtls_svc_key_id_t key, psa_algorithm_t alg,
				const uint8_t *input, size_t input_length,
				const uint8_t *signature, size_t signature_length)
{
	return verify(key, alg, true, input, input_length, signature, signature_length);
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg, mbedtls_svc_key_id_t private_key,
				   const uint8_t *peer_key, size_t peer_key_length,
				   uint8_t *output, size_t output_size, size_t *output_length)
{
	struct tp_key k;
	psa_status_t st;

	*output_length = 0;
	if (!PSA_ALG_IS_KEY_AGREEMENT(alg)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	st = tp_key_get(private_key, PSA_KEY_USAGE_DERIVE, alg, &k);
	if (st == PSA_SUCCESS && output_size < PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(k.type, k.bits)) {
		st = PSA_ERROR_BUFFER_TOO_SMALL;
	}
	if (st == PSA_SUCCESS && alg != PSA_ALG_ECDH) {
		st = PSA_ERROR_NOT_SUPPORTED;
	}
	if (st == PSA_SUCCESS && k.type != TP_P256_PAIR) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	}
	if (st == PSA_SUCCESS &&
	    (peer_key_length != 65 || peer_key[0] != 0x04 || tp_be_p256_pk_check(&peer_key[1]))) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	}
	if (st == PSA_SUCCESS && tp_be_p256_ecdh(output, k.data, &peer_key[1])) {
		st = PSA_ERROR_INVALID_ARGUMENT;
	}
	if (st == PSA_SUCCESS) {
		*output_length = 32;
	}
	tp_wipe(&k, sizeof(k));
	return st;
}
