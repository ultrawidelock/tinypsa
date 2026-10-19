/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Runs the CAVP and Wycheproof tables through the public API. A vector the
 * implementation declines for a documented limit (a key over TP_KEY_MAX, KDF
 * input over TINYPSA_KDF_INPUT_MAX, parameters PSA itself forbids) counts as
 * skipped with its reason, never as passed.
 */
#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "internal.h"
#include "test.h"
#include "vectors.h"

struct bytes {
	uint8_t *p;
	size_t n;
};

static struct bytes dup_hex(const char *s)
{
	struct bytes b = { malloc(strlen(s) / 2 + 1), strlen(s) / 2 };

	hex(b.p, b.n, s);
	return b;
}

struct tally {
	const char *name;
	int pass, fail, skip;
};

static void verdict(struct tally *t, const char *id, int expect, int ok)
{
	if (expect == -1 || ok == expect) {
		t->pass++;
		return;
	}
	t->fail++;
	if (t->fail <= 5) {
		char m[200];

		snprintf(m, sizeof(m), "%s: %s (expected %s)", t->name, id,
			 expect ? "valid" : "invalid");
		test_fail(__FILE__, __LINE__, m);
	} else {
		test_failures++;
	}
}

static void report(const struct tally *t)
{
	test_checks += t->pass + t->fail;
	printf("  %-8s %6d pass %4d fail %5d skip\n", t->name, t->pass, t->fail, t->skip);
}

static psa_key_id_t import(psa_key_type_t type, psa_key_usage_t usage, psa_algorithm_t alg,
			   struct bytes k, psa_status_t *st)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0;

	psa_set_key_type(&a, type);
	psa_set_key_usage_flags(&a, usage);
	psa_set_key_algorithm(&a, alg);
	*st = psa_import_key(&a, k.p, k.n, &id);
	return id;
}

static void sha256(void)
{
	struct tally t = { .name = "sha256" };

	for (size_t i = 0; i < vec_sha256_count; i++) {
		const struct vec_hash *v = &vec_sha256[i];
		struct bytes msg = dup_hex(v->msg), md = dup_hex(v->md);
		uint8_t out[32];
		size_t n;

		verdict(&t, v->id, 1,
			psa_hash_compute(PSA_ALG_SHA_256, msg.p, msg.n, out, sizeof(out), &n) ==
					PSA_SUCCESS &&
				n == md.n && !memcmp(out, md.p, n));
		free(msg.p);
		free(md.p);
	}
	report(&t);
}

static void macs(void)
{
	struct tally t = { .name = "mac" };

	for (size_t i = 0; i < vec_macs_count; i++) {
		const struct vec_mac *v = &vec_macs[i];
		struct bytes key = dup_hex(v->key), msg = dup_hex(v->msg), tag = dup_hex(v->tag);
		psa_algorithm_t alg = v->cmac ? PSA_ALG_CMAC : PSA_ALG_HMAC(PSA_ALG_SHA_256);
		size_t full = v->cmac ? 16 : 32, n;
		uint8_t out[32];
		psa_status_t st;
		psa_key_id_t id;

		if (tag.n < full) {
			alg = PSA_ALG_TRUNCATED_MAC(alg, tag.n);
		}
		id = import(v->cmac ? PSA_KEY_TYPE_AES : PSA_KEY_TYPE_HMAC,
			    PSA_KEY_USAGE_SIGN_MESSAGE, alg, key, &st);
		if (st == PSA_ERROR_NOT_SUPPORTED && key.n > TP_KEY_MAX) {
			t.skip++; /* longer than the key table holds */
		} else if (st != PSA_SUCCESS) {
			verdict(&t, v->id, v->expect, 0);
		} else {
			st = psa_mac_compute(id, alg, msg.p, msg.n, out, sizeof(out), &n);
			verdict(&t, v->id, v->expect,
				st == PSA_SUCCESS && n == tag.n && !memcmp(out, tag.p, n));
		}
		psa_destroy_key(id);
		free(key.p);
		free(msg.p);
		free(tag.p);
	}
	report(&t);
}

static void ecbs(void)
{
	struct tally t = { .name = "aes-ecb" };

	for (size_t i = 0; i < vec_ecbs_count; i++) {
		const struct vec_ecb *v = &vec_ecbs[i];
		struct bytes key = dup_hex(v->key), pt = dup_hex(v->pt), ct = dup_hex(v->ct);
		uint8_t out[16];
		size_t n;
		psa_status_t st;
		psa_key_id_t id;

		id = import(PSA_KEY_TYPE_AES, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_ECB_NO_PADDING, key, &st);
		verdict(&t, v->id, 1,
			st == PSA_SUCCESS &&
				psa_cipher_encrypt(id, PSA_ALG_ECB_NO_PADDING, pt.p, pt.n, out,
						   sizeof(out), &n) == PSA_SUCCESS &&
				!memcmp(out, ct.p, 16));
		psa_destroy_key(id);
		free(key.p);
		free(pt.p);
		free(ct.p);
	}
	report(&t);
}

/* Tag and nonce sizes the PSA spec itself rules out. */
static bool psa_allows(int ccm, size_t iv, size_t tag)
{
	if (ccm) {
		return iv >= 7 && iv <= 13 && tag >= 4 && tag <= 16 && tag % 2 == 0;
	}
	return iv > 0 && (tag == 4 || tag == 8 || (tag >= 12 && tag <= 16));
}

static void aeads(void)
{
	struct tally t = { .name = "aead" };

	for (size_t i = 0; i < vec_aeads_count; i++) {
		const struct vec_aead *v = &vec_aeads[i];
		struct bytes key = dup_hex(v->key), iv = dup_hex(v->iv), aad = dup_hex(v->aad),
			     pt = dup_hex(v->pt), ct = dup_hex(v->ct), tag = dup_hex(v->tag);
		psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(v->ccm ? PSA_ALG_CCM
									     : PSA_ALG_GCM,
								     tag.n);
		size_t ctl = ct.n + tag.n, n;
		uint8_t *sealed = malloc(ctl + 1), *out = malloc(ctl + 1);
		psa_status_t st;
		psa_key_id_t id;
		bool ok;

		memcpy(sealed, ct.p, ct.n);
		memcpy(&sealed[ct.n], tag.p, tag.n);
		id = import(PSA_KEY_TYPE_AES, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, alg, key,
			    &st);
		if (st == PSA_SUCCESS && v->expect != 0 && !psa_allows(v->ccm, iv.n, tag.n)) {
			t.skip++; /* outside what PSA permits */
			goto next;
		}
		ok = st == PSA_SUCCESS &&
		     psa_aead_decrypt(id, alg, iv.p, iv.n, aad.p, aad.n, sealed, ctl, out, ctl, &n) ==
			     PSA_SUCCESS &&
		     n == pt.n && !memcmp(out, pt.p, n);
		if (ok && v->expect != 0) {
			/* A valid vector must also seal to the same bytes. */
			ok = psa_aead_encrypt(id, alg, iv.p, iv.n, aad.p, aad.n, pt.p, pt.n, out, ctl,
					      &n) == PSA_SUCCESS &&
			     n == ctl && !memcmp(out, sealed, ctl);
		}
		verdict(&t, v->id, v->expect, ok);
next:
		psa_destroy_key(id);
		free(sealed);
		free(out);
		free(key.p);
		free(iv.p);
		free(aad.p);
		free(pt.p);
		free(ct.p);
		free(tag.p);
	}
	report(&t);
}

static void ecdsas(void)
{
	struct tally t = { .name = "ecdsa" };
	psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

	for (size_t i = 0; i < vec_ecdsas_count; i++) {
		const struct vec_ecdsa *v = &vec_ecdsas[i];
		struct bytes pub = dup_hex(v->pub), msg = dup_hex(v->msg), sig = dup_hex(v->sig);
		psa_status_t st;
		psa_key_id_t id;

		id = import(TP_P256_PUB, PSA_KEY_USAGE_VERIFY_MESSAGE, alg, pub, &st);
		if (st == PSA_SUCCESS) {
			st = psa_verify_message(id, alg, msg.p, msg.n, sig.p, sig.n);
			CHECK(st == PSA_SUCCESS || st == PSA_ERROR_INVALID_SIGNATURE);
		}
		verdict(&t, v->id, v->expect, st == PSA_SUCCESS);
		psa_destroy_key(id);
		free(pub.p);
		free(msg.p);
		free(sig.p);
	}
	report(&t);

	/* Known per-signature secrets: the backend must reproduce r || s. */
	struct tally g = { .name = "siggen" };

	for (size_t i = 0; i < vec_siggens_count; i++) {
		const struct vec_siggen *v = &vec_siggens[i];
		struct bytes d = dup_hex(v->d), msg = dup_hex(v->msg), k = dup_hex(v->k),
			     r = dup_hex(v->r), s = dup_hex(v->s);
		uint8_t hash[32], sig[64];
		size_t n;

		psa_hash_compute(PSA_ALG_SHA_256, msg.p, msg.n, hash, sizeof(hash), &n);
		verdict(&g, v->id, 1,
			tp_be_p256_sign_hash(sig, hash, d.p, k.p) == 0 && !memcmp(sig, r.p, 32) &&
				!memcmp(&sig[32], s.p, 32));
		free(d.p);
		free(msg.p);
		free(k.p);
		free(r.p);
		free(s.p);
	}
	report(&g);
}

static void ecdhs(void)
{
	struct tally t = { .name = "ecdh" };

	for (size_t i = 0; i < vec_ecdhs_count; i++) {
		const struct vec_ecdh *v = &vec_ecdhs[i];
		struct bytes priv = dup_hex(v->priv), pub = dup_hex(v->pub),
			     shared = dup_hex(v->shared);
		uint8_t sk[32] = { 0 }, out[32];
		size_t n, skip = 0;
		psa_status_t st = PSA_ERROR_INVALID_ARGUMENT;
		psa_key_id_t id = 0;

		/* Wycheproof writes the scalar as a minimal signed integer. */
		while (skip < priv.n && priv.p[skip] == 0) {
			skip++;
		}
		if (priv.n - skip <= 32) {
			memcpy(&sk[32 - (priv.n - skip)], &priv.p[skip], priv.n - skip);
			id = import(TP_P256_PAIR, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH,
				    (struct bytes){ sk, 32 }, &st);
		}
		if (st == PSA_SUCCESS) {
			st = psa_raw_key_agreement(PSA_ALG_ECDH, id, pub.p, pub.n, out, sizeof(out),
						   &n);
		}
		verdict(&t, v->id, v->expect,
			st == PSA_SUCCESS && n == shared.n && !memcmp(out, shared.p, n));
		psa_destroy_key(id);
		free(priv.p);
		free(pub.p);
		free(shared.p);
	}
	report(&t);
}

static void hkdfs(void)
{
	struct tally t = { .name = "hkdf" };

	for (size_t i = 0; i < vec_hkdfs_count; i++) {
		const struct vec_hkdf *v = &vec_hkdfs[i];
		struct bytes ikm = dup_hex(v->ikm), salt = dup_hex(v->salt), info = dup_hex(v->info),
			     okm = dup_hex(v->okm);
		psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
		uint8_t *out = malloc(v->size + 1);
		psa_status_t st;

		if (salt.n + info.n > TINYPSA_KDF_INPUT_MAX) {
			t.skip++; /* more salt and info than the operation buffers */
			goto next;
		}
		st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
		if (st == PSA_SUCCESS && salt.n) {
			st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt.p,
							    salt.n);
		}
		if (st == PSA_SUCCESS) {
			st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm.p,
							    ikm.n);
		}
		if (st == PSA_SUCCESS) {
			st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info.p,
							    info.n);
		}
		if (st == PSA_SUCCESS) {
			st = psa_key_derivation_output_bytes(&op, out, v->size);
		}
		verdict(&t, v->id, v->expect,
			st == PSA_SUCCESS && okm.n == v->size && !memcmp(out, okm.p, okm.n));
		psa_key_derivation_abort(&op);
next:
		free(out);
		free(ikm.p);
		free(salt.p);
		free(info.p);
		free(okm.p);
	}
	report(&t);
}

static void drbgs(void)
{
	struct tally t = { .name = "drbg" };

	for (size_t i = 0; i < vec_drbgs_count; i++) {
		const struct vec_drbg *v = &vec_drbgs[i];
		struct bytes e = dup_hex(v->entropy), no = dup_hex(v->nonce), pe = dup_hex(v->pers),
			     re = dup_hex(v->reseed), bits = dup_hex(v->bits);
		uint8_t *seed = malloc(e.n + no.n + pe.n), *out = malloc(bits.n);
		struct tp_drbg d;

		memcpy(seed, e.p, e.n);
		memcpy(&seed[e.n], no.p, no.n);
		memcpy(&seed[e.n + no.n], pe.p, pe.n);
		tp_drbg_seed(&d, seed, e.n + no.n + pe.n);
		if (re.n) {
			tp_drbg_reseed(&d, re.p, re.n);
		}
		tp_drbg_generate(&d, out, bits.n);
		tp_drbg_generate(&d, out, bits.n);
		verdict(&t, v->id, 1, !memcmp(out, bits.p, bits.n));
		free(seed);
		free(out);
		free(e.p);
		free(no.p);
		free(pe.p);
		free(re.p);
		free(bits.p);
	}
	report(&t);
}

void test_vectors(void)
{
	sha256();
	macs();
	ecbs();
	aeads();
	ecdsas();
	ecdhs();
	hkdfs();
	drbgs();
}
