/* SPDX-License-Identifier: ISC */
/*
 * One known answer per algorithm, through the public API, plus the state
 * and policy rules each family depends on. The bulk vectors come from
 * test_mbedtls_data.c; this file is the quick signal that the plumbing works.
 */
#include <string.h>

#include <psa/crypto.h>

#include "internal.h"
#include "test.h"

static psa_key_id_t import(psa_key_type_t type, psa_key_usage_t usage, psa_algorithm_t alg,
			   const uint8_t *data, size_t len)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0;

	psa_set_key_type(&a, type);
	psa_set_key_usage_flags(&a, usage);
	psa_set_key_algorithm(&a, alg);
	CHECK_ST(psa_import_key(&a, data, len, &id), PSA_SUCCESS);
	return id;
}

static void sha256(void)
{
	uint8_t want[32], got[32];
	size_t n;

	HEX(want, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	CHECK_ST(psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)"abc", 3, got, sizeof(got),
				  &n),
		 PSA_SUCCESS);
	CHECK(n == 32 && !memcmp(got, want, 32));

	psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
	CHECK_ST(psa_hash_update(&op, got, 1), PSA_ERROR_BAD_STATE);
	CHECK_ST(psa_hash_setup(&op, PSA_ALG_SHA_256), PSA_SUCCESS);
	/* A second setup fails and, as in Mbed TLS, aborts the first. */
	CHECK_ST(psa_hash_setup(&op, PSA_ALG_SHA_256), PSA_ERROR_BAD_STATE);
	CHECK_ST(psa_hash_update(&op, (const uint8_t *)"a", 1), PSA_ERROR_BAD_STATE);
	CHECK_ST(psa_hash_setup(&op, PSA_ALG_SHA_256), PSA_SUCCESS);
	CHECK_ST(psa_hash_update(&op, (const uint8_t *)"a", 1), PSA_SUCCESS);
	CHECK_ST(psa_hash_update(&op, (const uint8_t *)"bc", 2), PSA_SUCCESS);
	CHECK_ST(psa_hash_finish(&op, got, 31, &n), PSA_ERROR_BUFFER_TOO_SMALL);
	CHECK_ST(psa_hash_update(&op, got, 1), PSA_ERROR_BAD_STATE);
	CHECK_ST(psa_hash_setup(&op, PSA_ALG_SHA_256), PSA_SUCCESS);
	psa_hash_update(&op, (const uint8_t *)"abc", 3);
	CHECK_ST(psa_hash_finish(&op, got, sizeof(got), &n), PSA_SUCCESS);
	CHECK(!memcmp(got, want, 32));
	CHECK_ST(psa_hash_setup(&op, PSA_ALG_SHA_1), PSA_ERROR_NOT_SUPPORTED);
	CHECK_ST(psa_hash_setup(&op, PSA_ALG_HMAC(PSA_ALG_SHA_256)), PSA_ERROR_INVALID_ARGUMENT);
}

static void hmac(void)
{
	uint8_t key[20], want[32], got[32];
	size_t n;
	psa_key_id_t id;

	memset(key, 0x0b, sizeof(key));
	HEX(want, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	id = import(PSA_KEY_TYPE_HMAC, PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_HMAC(PSA_ALG_SHA_256),
		    key, sizeof(key));
	CHECK_ST(psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), (const uint8_t *)"Hi There", 8,
				 got, sizeof(got), &n),
		 PSA_SUCCESS);
	CHECK(n == 32 && !memcmp(got, want, 32));

	/* Multipart, split across updates. */
	psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
	CHECK_ST(psa_mac_sign_setup(&op, id, PSA_ALG_HMAC(PSA_ALG_SHA_256)), PSA_SUCCESS);
	psa_mac_update(&op, (const uint8_t *)"Hi ", 3);
	psa_mac_update(&op, (const uint8_t *)"There", 5);
	CHECK_ST(psa_mac_sign_finish(&op, got, sizeof(got), &n), PSA_SUCCESS);
	CHECK(!memcmp(got, want, 32));

	/* Truncation within policy is refused unless the policy allows it. */
	CHECK_ST(psa_mac_compute(id, PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16),
				 (const uint8_t *)"Hi There", 8, got, sizeof(got), &n),
		 PSA_ERROR_NOT_PERMITTED);
	CHECK_ST(psa_destroy_key(id), PSA_SUCCESS);
	CHECK_ST(psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), got, 1, got, sizeof(got), &n),
		 PSA_ERROR_INVALID_HANDLE);
}

static void cmac_and_ecb(void)
{
	uint8_t key[16], msg[16], want[16], got[16];
	size_t n;
	psa_key_id_t id;

	HEX(key, "2b7e151628aed2a6abf7158809cf4f3c");
	HEX(msg, "6bc1bee22e409f96e93d7e117393172a");
	HEX(want, "070a16b46b4d4144f79bdd9dd04a287c");
	id = import(PSA_KEY_TYPE_AES, PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_CMAC, key, sizeof(key));
	CHECK_ST(psa_mac_compute(id, PSA_ALG_CMAC, msg, sizeof(msg), got, sizeof(got), &n),
		 PSA_SUCCESS);
	CHECK(n == 16 && !memcmp(got, want, 16));
	/* RFC 4493 example 1: the empty message. */
	HEX(want, "bb1d6929e95937287fa37d129b756746");
	CHECK_ST(psa_mac_compute(id, PSA_ALG_CMAC, NULL, 0, got, sizeof(got), &n), PSA_SUCCESS);
	CHECK(!memcmp(got, want, 16));
	CHECK_ST(psa_cipher_encrypt(id, PSA_ALG_ECB_NO_PADDING, msg, 16, got, 16, &n),
		 PSA_ERROR_NOT_PERMITTED);
	psa_destroy_key(id);

	/* FIPS-197 C.1 */
	HEX(key, "000102030405060708090a0b0c0d0e0f");
	HEX(msg, "00112233445566778899aabbccddeeff");
	HEX(want, "69c4e0d86a7b0430d8cdb78070b4c55a");
	id = import(PSA_KEY_TYPE_AES, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_ECB_NO_PADDING, key,
		    sizeof(key));
	CHECK_ST(psa_cipher_encrypt(id, PSA_ALG_ECB_NO_PADDING, msg, 16, got, 16, &n),
		 PSA_SUCCESS);
	CHECK(n == 16 && !memcmp(got, want, 16));
	CHECK_ST(psa_cipher_encrypt(id, PSA_ALG_ECB_NO_PADDING, msg, 15, got, 16, &n),
		 PSA_ERROR_INVALID_ARGUMENT);
	CHECK_ST(psa_cipher_encrypt(id, PSA_ALG_ECB_NO_PADDING, msg, 16, got, 15, &n),
		 PSA_ERROR_BUFFER_TOO_SMALL);
	psa_destroy_key(id);
}

static void ccm(void)
{
	uint8_t key[16], pt[23], nonce[13], ad[8], want[31], got[31], back[23];
	size_t n;
	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8);
	psa_key_id_t id;

	/* RFC 3610 packet vector #1 */
	HEX(key, "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
	HEX(pt, "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
	HEX(nonce, "00000003020100A0A1A2A3A4A5");
	HEX(ad, "0001020304050607");
	HEX(want, "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0");
	id = import(PSA_KEY_TYPE_AES, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, alg, key,
		    sizeof(key));
	CHECK_ST(psa_aead_encrypt(id, alg, nonce, sizeof(nonce), ad, sizeof(ad), pt, sizeof(pt),
				  got, sizeof(got), &n),
		 PSA_SUCCESS);
	CHECK(n == sizeof(want) && !memcmp(got, want, n));
	CHECK_ST(psa_aead_decrypt(id, alg, nonce, sizeof(nonce), ad, sizeof(ad), got, sizeof(got),
				  back, sizeof(back), &n),
		 PSA_SUCCESS);
	CHECK(n == sizeof(pt) && !memcmp(back, pt, n));
	got[30] ^= 1;
	CHECK_ST(psa_aead_decrypt(id, alg, nonce, sizeof(nonce), ad, sizeof(ad), got, sizeof(got),
				  back, sizeof(back), &n),
		 PSA_ERROR_INVALID_SIGNATURE);

	/* Multipart, nonce before lengths, body split. */
	psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
	uint8_t tag[16];
	size_t t;

	CHECK_ST(psa_aead_encrypt_setup(&op, id, alg), PSA_SUCCESS);
	CHECK_ST(psa_aead_set_nonce(&op, nonce, sizeof(nonce)), PSA_SUCCESS);
	CHECK_ST(psa_aead_update_ad(&op, ad, sizeof(ad)), PSA_ERROR_BAD_STATE);
	CHECK_ST(psa_aead_encrypt_setup(&op, id, alg), PSA_SUCCESS);
	CHECK_ST(psa_aead_set_nonce(&op, nonce, sizeof(nonce)), PSA_SUCCESS);
	CHECK_ST(psa_aead_set_lengths(&op, sizeof(ad), sizeof(pt)), PSA_SUCCESS);
	CHECK_ST(psa_aead_update_ad(&op, ad, 3), PSA_SUCCESS);
	CHECK_ST(psa_aead_update_ad(&op, &ad[3], 5), PSA_SUCCESS);
	CHECK_ST(psa_aead_update(&op, pt, 10, got, sizeof(got), &n), PSA_SUCCESS);
	CHECK(n == 10);
	CHECK_ST(psa_aead_update(&op, &pt[10], 13, &got[10], sizeof(got) - 10, &n), PSA_SUCCESS);
	CHECK_ST(psa_aead_finish(&op, NULL, 0, &n, tag, sizeof(tag), &t), PSA_SUCCESS);
	CHECK(t == 8 && !memcmp(got, want, 23) && !memcmp(tag, &want[23], 8));
	psa_destroy_key(id);
}

static void hkdf(void)
{
	uint8_t ikm[22], salt[13], info[10], want[42], got[42];
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

	memset(ikm, 0x0b, sizeof(ikm));
	HEX(salt, "000102030405060708090a0b0c");
	HEX(info, "f0f1f2f3f4f5f6f7f8f9");
	HEX(want, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
	CHECK_ST(psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)), PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt,
						sizeof(salt)),
		 PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm,
						sizeof(ikm)),
		 PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info,
						sizeof(info)),
		 PSA_SUCCESS);
	/* Streamed in pieces that straddle the 32-byte blocks. */
	CHECK_ST(psa_key_derivation_output_bytes(&op, got, 5), PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_output_bytes(&op, &got[5], 30), PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_output_bytes(&op, &got[35], 7), PSA_SUCCESS);
	CHECK(!memcmp(got, want, sizeof(want)));
	psa_key_derivation_abort(&op);

	/* Info before the secret gives the same output. */
	CHECK_ST(psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)), PSA_SUCCESS);
	psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, sizeof(info));
	psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, sizeof(salt));
	psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm, sizeof(ikm));
	CHECK_ST(psa_key_derivation_output_bytes(&op, got, sizeof(got)), PSA_SUCCESS);
	CHECK(!memcmp(got, want, sizeof(want)));
	psa_key_derivation_abort(&op);
}

static void pbkdf2(void)
{
	uint8_t want[64], got[64];
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_id_t pw;

	/* Mbed TLS test data, inputs from RFC 7914 #2 (80,000 iterations). */
	HEX(want, "3298e89bc3560e61b59aef2c104f93380b5fa26e2e011cb5ac5895fcd5a3bd5a"
		  "92e617d7cae020fa2c6ef895182d9ffa0cc8f9c22778beb02856127719d95570");
	pw = import(PSA_KEY_TYPE_PASSWORD, PSA_KEY_USAGE_DERIVE, PSA_ALG_PBKDF2_AES_CMAC_PRF_128,
		    (const uint8_t *)"Password", 8);
	CHECK_ST(psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_AES_CMAC_PRF_128), PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
						(const uint8_t *)"NaCl", 4),
		 PSA_ERROR_BAD_STATE);
	/* A failed input leaves the operation blank, as in Mbed TLS. */
	CHECK_ST(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
						(const uint8_t *)"NaCl", 4),
		 PSA_ERROR_BAD_STATE);
	psa_key_derivation_abort(&op);
	CHECK_ST(psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_AES_CMAC_PRF_128), PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, 0x13880),
		 PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
						(const uint8_t *)"NaCl", 4),
		 PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw),
		 PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_output_bytes(&op, got, 20), PSA_SUCCESS);
	CHECK_ST(psa_key_derivation_output_bytes(&op, &got[20], 44), PSA_SUCCESS);
	CHECK(!memcmp(got, want, sizeof(want)));
	psa_key_derivation_abort(&op);
	psa_destroy_key(pw);
}

static void p256(void)
{
	static const char *const d = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
	uint8_t sk[32], sig[64], want[64], pub[65], pub2[65];
	size_t n;
	psa_algorithm_t det = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
	psa_key_id_t id, pid;

	/* RFC 6979 A.2.5, message "sample". */
	HEX(sk, d);
	HEX(want, "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
		  "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
	id = import(TP_P256_PAIR, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT, det, sk,
		    sizeof(sk));
	CHECK_ST(psa_sign_message(id, det, (const uint8_t *)"sample", 6, sig, sizeof(sig), &n),
		 PSA_SUCCESS);
	CHECK(n == 64 && !memcmp(sig, want, 64));
	CHECK_ST(psa_export_public_key(id, pub, sizeof(pub), &n), PSA_SUCCESS);
	CHECK(n == 65 && pub[0] == 0x04);
	CHECK_ST(psa_export_key(id, pub2, sizeof(pub2), &n), PSA_SUCCESS);
	CHECK(n == 32 && !memcmp(pub2, sk, 32));
	/* A short hash is an integer like any other, as in Mbed TLS. */
	CHECK_ST(psa_sign_hash(id, det, sig, 31, sig, sizeof(sig), &n), PSA_SUCCESS);
	CHECK_ST(psa_sign_hash(id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), want, 32, sig, sizeof(sig), &n),
		 PSA_ERROR_NOT_PERMITTED);

	pid = import(TP_P256_PUB, PSA_KEY_USAGE_VERIFY_MESSAGE, det, pub, sizeof(pub));
	CHECK_ST(psa_verify_message(pid, det, (const uint8_t *)"sample", 6, want, 64), PSA_SUCCESS);
	CHECK_ST(psa_verify_message(pid, det, (const uint8_t *)"sampl3", 6, want, 64),
		 PSA_ERROR_INVALID_SIGNATURE);
	CHECK_ST(psa_verify_message(pid, det, (const uint8_t *)"sample", 6, want, 63),
		 PSA_ERROR_INVALID_SIGNATURE);
	CHECK_ST(psa_export_key(pid, pub2, sizeof(pub2), &n), PSA_SUCCESS);
	CHECK(n == 65 && !memcmp(pub, pub2, 65));
	psa_destroy_key(id);
	psa_destroy_key(pid);

	/* Randomized ECDSA round trip with a generated key. */
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t rnd = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

	psa_set_key_type(&a, TP_P256_PAIR);
	psa_set_key_bits(&a, 256);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&a, rnd);
	CHECK_ST(psa_generate_key(&a, &id), PSA_SUCCESS);
	CHECK_ST(psa_sign_hash(id, rnd, want, 32, sig, sizeof(sig), &n), PSA_SUCCESS);
	CHECK_ST(psa_verify_hash(id, rnd, want, 32, sig, 64), PSA_SUCCESS);
	sig[0] ^= 1;
	CHECK_ST(psa_verify_hash(id, rnd, want, 32, sig, 64), PSA_ERROR_INVALID_SIGNATURE);
	CHECK_ST(psa_export_key(id, pub2, sizeof(pub2), &n), PSA_ERROR_NOT_PERMITTED);
	psa_destroy_key(id);
}

static void ecdh(void)
{
	uint8_t da[32], qb[65], want[32], got[32];
	size_t n;
	psa_key_id_t id;

	/* Mbed TLS ecdh_primitive_testvec, NIST CAVS P-256 */
	HEX(da, "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
	HEX(qb, "04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63"
		"56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB");
	HEX(want, "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");
	id = import(TP_P256_PAIR, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH, da, sizeof(da));
	CHECK_ST(psa_raw_key_agreement(PSA_ALG_ECDH, id, qb, sizeof(qb), got, sizeof(got), &n),
		 PSA_SUCCESS);
	CHECK(n == 32 && !memcmp(got, want, 32));
	qb[64] ^= 1; /* off the curve */
	CHECK_ST(psa_raw_key_agreement(PSA_ALG_ECDH, id, qb, sizeof(qb), got, sizeof(got), &n),
		 PSA_ERROR_INVALID_ARGUMENT);
	psa_destroy_key(id);
}

static void drbg(void)
{
	uint8_t seed[48], want[128], got[128];
	struct tp_drbg d;

	/* NIST CAVS 14.3 HMAC_DRBG SHA-256 no reseed #0: entropy || nonce; the second output counts. */
	HEX(seed, "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488"
		  "659ba96c601dc69fc902940805ec0ca8");
	HEX(want, "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
		  "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
		  "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
		  "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8");
	tp_drbg_seed(&d, seed, sizeof(seed));
	tp_drbg_generate(&d, got, sizeof(got));
	tp_drbg_generate(&d, got, sizeof(got));
	CHECK(!memcmp(got, want, sizeof(want)));
}

static void keys(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t k[16] = { 1 }, out[16];
	size_t n;
	psa_key_id_t id;

	CHECK_ST(psa_destroy_key(0), PSA_SUCCESS);
	CHECK_ST(psa_destroy_key(0x12345), PSA_ERROR_INVALID_HANDLE);

	/* Persistent: created once, survives eviction from the cache, refuses a twin. */
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_EXPORT);
	psa_set_key_id(&a, 0x20001);
	CHECK(psa_get_key_lifetime(&a) == PSA_KEY_LIFETIME_PERSISTENT);
	CHECK_ST(psa_import_key(&a, k, sizeof(k), &id), PSA_SUCCESS);
	CHECK(id == 0x20001);
	CHECK_ST(psa_import_key(&a, k, sizeof(k), &id), PSA_ERROR_ALREADY_EXISTS);
	CHECK(id == 0);
	psa_reset_key_attributes(&a);
	CHECK_ST(psa_get_key_attributes(0x20001, &a), PSA_SUCCESS);
	CHECK(psa_get_key_type(&a) == PSA_KEY_TYPE_AES && psa_get_key_bits(&a) == 128 &&
	      psa_get_key_id(&a) == 0x20001);
	CHECK_ST(psa_export_key(0x20001, out, sizeof(out), &n), PSA_SUCCESS);
	CHECK(n == 16 && !memcmp(out, k, 16));
	CHECK_ST(psa_destroy_key(0x20001), PSA_SUCCESS);
	CHECK_ST(psa_get_key_attributes(0x20001, &a), PSA_ERROR_INVALID_HANDLE);

	/* Volatile keys fill the table, then the table says so. */
	psa_key_id_t ids[TP_KEY_SLOTS + 1];
	psa_reset_key_attributes(&a);
	psa_set_key_type(&a, PSA_KEY_TYPE_RAW_DATA);
	for (int i = 0; i < TP_KEY_SLOTS; i++) {
		CHECK_ST(psa_import_key(&a, k, 4, &ids[i]), PSA_SUCCESS);
	}
	CHECK_ST(psa_import_key(&a, k, 4, &ids[TP_KEY_SLOTS]), PSA_ERROR_INSUFFICIENT_MEMORY);
	for (int i = 0; i < TP_KEY_SLOTS; i++) {
		CHECK_ST(psa_destroy_key(ids[i]), PSA_SUCCESS);
	}

	/* Bad imports. */
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	CHECK_ST(psa_import_key(&a, k, 15, &id), PSA_ERROR_INVALID_ARGUMENT);
	psa_set_key_bits(&a, 256);
	CHECK_ST(psa_import_key(&a, k, 16, &id), PSA_ERROR_INVALID_ARGUMENT);
	psa_set_key_type(&a, TP_P256_PAIR);
	psa_set_key_bits(&a, 0);
	memset(out, 0, sizeof(out));
	uint8_t zero[32] = { 0 };
	CHECK_ST(psa_import_key(&a, zero, 32, &id), PSA_ERROR_INVALID_ARGUMENT);
}

void test_smoke(void)
{
	sha256();
	hmac();
	cmac_and_ecb();
	ccm();
	hkdf();
	pbkdf2();
	p256();
	ecdh();
	drbg();
	keys();
}
