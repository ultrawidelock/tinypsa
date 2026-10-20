/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The shim body: public PSA API only, so it compiles unchanged against
 * either implementation. The includer defines SHIM(name) to prefix names.
 */
#include <string.h>

#include "shim.h"

static psa_hash_operation_t hash_ops[N_OPS];
static psa_mac_operation_t mac_ops[N_OPS];
static psa_aead_operation_t aead_ops[N_OPS];
static psa_key_derivation_operation_t kdf_ops[N_OPS];

static void to_attrs(const struct dkey *k, psa_key_attributes_t *a)
{
	*a = psa_key_attributes_init();
	psa_set_key_type(a, k->type);
	psa_set_key_bits(a, k->bits);
	psa_set_key_usage_flags(a, k->usage);
	psa_set_key_algorithm(a, k->alg);
	/* A volatile key cannot carry an id through the public setters. */
	psa_set_key_lifetime(a, k->lifetime);
	if (!PSA_KEY_LIFETIME_IS_VOLATILE(k->lifetime)) {
		psa_set_key_id(a, k->id);
	}
}

int32_t SHIM(init)(void)
{
	return psa_crypto_init();
}

int32_t SHIM(import)(const struct dkey *k, const uint8_t *d, size_t n, uint32_t *id)
{
	psa_key_attributes_t a;
	mbedtls_svc_key_id_t key = 0;
	psa_status_t st;

	to_attrs(k, &a);
	st = psa_import_key(&a, d, n, &key);
	*id = key;
	return st;
}

int32_t SHIM(generate)(const struct dkey *k, uint32_t *id)
{
	psa_key_attributes_t a;
	mbedtls_svc_key_id_t key = 0;
	psa_status_t st;

	to_attrs(k, &a);
	st = psa_generate_key(&a, &key);
	*id = key;
	return st;
}

int32_t SHIM(destroy)(uint32_t id)
{
	return psa_destroy_key(id);
}

int32_t SHIM(get_attrs)(uint32_t id, struct dkey *out)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st = psa_get_key_attributes(id, &a);

	out->type = psa_get_key_type(&a);
	out->bits = psa_get_key_bits(&a);
	out->usage = psa_get_key_usage_flags(&a);
	out->alg = psa_get_key_algorithm(&a);
	out->lifetime = psa_get_key_lifetime(&a);
	out->id = psa_get_key_id(&a);
	psa_reset_key_attributes(&a);
	return st;
}

int32_t SHIM(export)(uint32_t id, uint8_t *o, size_t size, size_t *len)
{
	return psa_export_key(id, o, size, len);
}

int32_t SHIM(export_public)(uint32_t id, uint8_t *o, size_t size, size_t *len)
{
	return psa_export_public_key(id, o, size, len);
}

int32_t SHIM(random)(uint8_t *o, size_t n)
{
	return psa_generate_random(o, n);
}

int32_t SHIM(hash_compute)(uint32_t alg, const uint8_t *in, size_t n, uint8_t *o, size_t size,
			   size_t *len)
{
	return psa_hash_compute(alg, in, n, o, size, len);
}

int32_t SHIM(hash_setup)(int s, uint32_t alg)
{
	return psa_hash_setup(&hash_ops[s], alg);
}

int32_t SHIM(hash_update)(int s, const uint8_t *in, size_t n)
{
	return psa_hash_update(&hash_ops[s], in, n);
}

int32_t SHIM(hash_finish)(int s, uint8_t *o, size_t size, size_t *len)
{
	return psa_hash_finish(&hash_ops[s], o, size, len);
}

int32_t SHIM(hash_abort)(int s)
{
	return psa_hash_abort(&hash_ops[s]);
}

int32_t SHIM(mac_compute)(uint32_t id, uint32_t alg, const uint8_t *in, size_t n, uint8_t *o,
			  size_t size, size_t *len)
{
	return psa_mac_compute(id, alg, in, n, o, size, len);
}

int32_t SHIM(mac_setup)(int s, uint32_t id, uint32_t alg)
{
	return psa_mac_sign_setup(&mac_ops[s], id, alg);
}

int32_t SHIM(mac_update)(int s, const uint8_t *in, size_t n)
{
	return psa_mac_update(&mac_ops[s], in, n);
}

int32_t SHIM(mac_finish)(int s, uint8_t *o, size_t size, size_t *len)
{
	return psa_mac_sign_finish(&mac_ops[s], o, size, len);
}

int32_t SHIM(mac_abort)(int s)
{
	return psa_mac_abort(&mac_ops[s]);
}

int32_t SHIM(cipher_encrypt)(uint32_t id, uint32_t alg, const uint8_t *in, size_t n, uint8_t *o,
			     size_t size, size_t *len)
{
	return psa_cipher_encrypt(id, alg, in, n, o, size, len);
}

int32_t SHIM(aead_oneshot)(int enc, uint32_t id, uint32_t alg, const uint8_t *nonce, size_t nn,
			   const uint8_t *ad, size_t an, const uint8_t *in, size_t n, uint8_t *o,
			   size_t size, size_t *len)
{
	if (enc) {
		return psa_aead_encrypt(id, alg, nonce, nn, ad, an, in, n, o, size, len);
	}
	return psa_aead_decrypt(id, alg, nonce, nn, ad, an, in, n, o, size, len);
}

int32_t SHIM(aead_setup)(int s, int enc, uint32_t id, uint32_t alg)
{
	return enc ? psa_aead_encrypt_setup(&aead_ops[s], id, alg)
		   : psa_aead_decrypt_setup(&aead_ops[s], id, alg);
}

int32_t SHIM(aead_set_nonce)(int s, const uint8_t *nonce, size_t n)
{
	return psa_aead_set_nonce(&aead_ops[s], nonce, n);
}

int32_t SHIM(aead_set_lengths)(int s, size_t ad, size_t pt)
{
	return psa_aead_set_lengths(&aead_ops[s], ad, pt);
}

int32_t SHIM(aead_update_ad)(int s, const uint8_t *ad, size_t n)
{
	return psa_aead_update_ad(&aead_ops[s], ad, n);
}

int32_t SHIM(aead_update)(int s, const uint8_t *in, size_t n, uint8_t *o, size_t size,
			  size_t *len)
{
	return psa_aead_update(&aead_ops[s], in, n, o, size, len);
}

int32_t SHIM(aead_finish)(int s, uint8_t *tag, size_t size, size_t *len)
{
	uint8_t ct[16];
	size_t ctn;

	return psa_aead_finish(&aead_ops[s], ct, sizeof(ct), &ctn, tag, size, len);
}

int32_t SHIM(aead_verify)(int s, const uint8_t *tag, size_t n)
{
	uint8_t pt[16];
	size_t ptn;

	return psa_aead_verify(&aead_ops[s], pt, sizeof(pt), &ptn, tag, n);
}

int32_t SHIM(aead_abort)(int s)
{
	return psa_aead_abort(&aead_ops[s]);
}

int32_t SHIM(sign)(int message, uint32_t id, uint32_t alg, const uint8_t *in, size_t n,
		   uint8_t *o, size_t size, size_t *len)
{
	return message ? psa_sign_message(id, alg, in, n, o, size, len)
		       : psa_sign_hash(id, alg, in, n, o, size, len);
}

int32_t SHIM(verify)(int message, uint32_t id, uint32_t alg, const uint8_t *in, size_t n,
		     const uint8_t *sig, size_t sn)
{
	return message ? psa_verify_message(id, alg, in, n, sig, sn)
		       : psa_verify_hash(id, alg, in, n, sig, sn);
}

int32_t SHIM(agree)(uint32_t alg, uint32_t id, const uint8_t *peer, size_t pn, uint8_t *o,
		    size_t size, size_t *len)
{
	return psa_raw_key_agreement(alg, id, peer, pn, o, size, len);
}

int32_t SHIM(kdf_setup)(int s, uint32_t alg)
{
	return psa_key_derivation_setup(&kdf_ops[s], alg);
}

int32_t SHIM(kdf_bytes)(int s, uint32_t step, const uint8_t *d, size_t n)
{
	return psa_key_derivation_input_bytes(&kdf_ops[s], step, d, n);
}

int32_t SHIM(kdf_integer)(int s, uint32_t step, uint64_t v)
{
	return psa_key_derivation_input_integer(&kdf_ops[s], step, v);
}

int32_t SHIM(kdf_key)(int s, uint32_t step, uint32_t id)
{
	return psa_key_derivation_input_key(&kdf_ops[s], step, id);
}

int32_t SHIM(kdf_output)(int s, uint8_t *o, size_t n)
{
	return psa_key_derivation_output_bytes(&kdf_ops[s], o, n);
}

int32_t SHIM(kdf_abort)(int s)
{
	return psa_key_derivation_abort(&kdf_ops[s]);
}
