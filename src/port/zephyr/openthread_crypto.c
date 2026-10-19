/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenThread's crypto platform (OPENTHREAD_CONFIG_CRYPTO_LIB_PLATFORM) over
 * tinypsa's primitives, past its PSA layer. Keys are literal: without
 * OPENTHREAD_PLATFORM_KEY_REF, OpenThread keeps them in its own settings
 * and the key-reference hooks are never called. ECDSA key pairs travel as
 * SEC1 DER, the form OpenThread stores.
 */
#include <string.h>

#include <openthread/platform/crypto.h>
#include <psa/crypto.h>
#include <tinypsa/prim.h>

#include "internal.h"

_Static_assert(TINYPSA_AES_CTX_SIZE <= OPENTHREAD_CONFIG_AES_CONTEXT_SIZE, "aes ctx");
_Static_assert(TINYPSA_HMAC_SHA256_CTX_SIZE <= OPENTHREAD_CONFIG_HMAC_SHA256_CONTEXT_SIZE, "hmac");
_Static_assert(TINYPSA_SHA256_CTX_SIZE <= OPENTHREAD_CONFIG_SHA256_CONTEXT_SIZE, "sha256 ctx");
_Static_assert(32 <= OPENTHREAD_CONFIG_HKDF_CONTEXT_SIZE, "hkdf ctx holds the PRK");

void otPlatCryptoInit(void)
{
	(void)psa_crypto_init();
}

otError otPlatCryptoAesInit(otCryptoContext *aContext)
{
	return OT_ERROR_NONE;
}

otError otPlatCryptoAesSetKey(otCryptoContext *aContext, const otCryptoKey *aKey)
{
	tp_be_aes_init(aContext->mContext, aKey->mKey, aKey->mKeyLength);
	return OT_ERROR_NONE;
}

otError otPlatCryptoAesEncrypt(otCryptoContext *aContext, const uint8_t *aInput, uint8_t *aOutput)
{
	tp_be_aes_encrypt(aContext->mContext, aOutput, aInput, 16);
	return OT_ERROR_NONE;
}

otError otPlatCryptoAesFree(otCryptoContext *aContext)
{
	tp_be_ctx_free(aContext->mContext, aContext->mContextSize);
	tp_wipe(aContext->mContext, aContext->mContextSize);
	return OT_ERROR_NONE;
}

otError otPlatCryptoHmacSha256Init(otCryptoContext *aContext)
{
	return OT_ERROR_NONE;
}

otError otPlatCryptoHmacSha256Deinit(otCryptoContext *aContext)
{
	tp_be_ctx_free(aContext->mContext, aContext->mContextSize);
	tp_wipe(aContext->mContext, aContext->mContextSize);
	return OT_ERROR_NONE;
}

otError otPlatCryptoHmacSha256Start(otCryptoContext *aContext, const otCryptoKey *aKey)
{
	tp_be_hmac_sha256_init(aContext->mContext, aKey->mKey, aKey->mKeyLength);
	return OT_ERROR_NONE;
}

otError otPlatCryptoHmacSha256Update(otCryptoContext *aContext, const void *aBuf,
				     uint16_t aBufLength)
{
	tp_be_hmac_sha256_update(aContext->mContext, aBuf, aBufLength);
	return OT_ERROR_NONE;
}

otError otPlatCryptoHmacSha256Finish(otCryptoContext *aContext, uint8_t *aBuf, size_t aBufLength)
{
	uint8_t mac[32];

	tp_be_hmac_sha256_final(aContext->mContext, mac);
	memcpy(aBuf, mac, aBufLength < sizeof(mac) ? aBufLength : sizeof(mac));
	tp_wipe(mac, sizeof(mac));
	return OT_ERROR_NONE;
}

otError otPlatCryptoSha256Init(otCryptoContext *aContext)
{
	return OT_ERROR_NONE;
}

otError otPlatCryptoSha256Deinit(otCryptoContext *aContext)
{
	tp_be_ctx_free(aContext->mContext, aContext->mContextSize);
	return OT_ERROR_NONE;
}

otError otPlatCryptoSha256Start(otCryptoContext *aContext)
{
	tp_be_sha256_init(aContext->mContext);
	return OT_ERROR_NONE;
}

otError otPlatCryptoSha256Update(otCryptoContext *aContext, const void *aBuf, uint16_t aBufLength)
{
	tp_be_sha256_update(aContext->mContext, aBuf, aBufLength);
	return OT_ERROR_NONE;
}

otError otPlatCryptoSha256Finish(otCryptoContext *aContext, uint8_t *aHash, uint16_t aHashSize)
{
	if (aHashSize < 32) {
		return OT_ERROR_INVALID_ARGS;
	}
	tp_be_sha256_final(aContext->mContext, aHash);
	return OT_ERROR_NONE;
}

/* HKDF-SHA-256 (RFC 5869); the context holds the PRK between extract and expand. */
otError otPlatCryptoHkdfInit(otCryptoContext *aContext)
{
	return OT_ERROR_NONE;
}

otError otPlatCryptoHkdfExtract(otCryptoContext *aContext, const uint8_t *aSalt,
				uint16_t aSaltLength, const otCryptoKey *aInputKey)
{
	uint8_t h[TINYPSA_HMAC_SHA256_CTX_SIZE] __attribute__((aligned(8)));

	tp_be_hmac_sha256_init(h, aSalt, aSaltLength);
	tp_be_hmac_sha256_update(h, aInputKey->mKey, aInputKey->mKeyLength);
	tp_be_hmac_sha256_final(h, aContext->mContext);
	tp_wipe(h, sizeof(h));
	return OT_ERROR_NONE;
}

otError otPlatCryptoHkdfExpand(otCryptoContext *aContext, const uint8_t *aInfo,
			       uint16_t aInfoLength, uint8_t *aOutputKey, uint16_t aOutputKeyLength)
{
	uint8_t h[TINYPSA_HMAC_SHA256_CTX_SIZE] __attribute__((aligned(8)));
	uint8_t t[32];
	uint8_t i = 0;

	if (aOutputKeyLength > 255 * 32) {
		return OT_ERROR_INVALID_ARGS;
	}
	while (aOutputKeyLength) {
		uint16_t n = aOutputKeyLength < 32 ? aOutputKeyLength : 32;

		tp_be_hmac_sha256_init(h, aContext->mContext, 32);
		if (i) {
			tp_be_hmac_sha256_update(h, t, sizeof(t));
		}
		i++;
		tp_be_hmac_sha256_update(h, aInfo, aInfoLength);
		tp_be_hmac_sha256_update(h, &i, 1);
		tp_be_hmac_sha256_final(h, t);
		memcpy(aOutputKey, t, n);
		aOutputKey += n;
		aOutputKeyLength -= n;
	}
	tp_wipe(h, sizeof(h));
	tp_wipe(t, sizeof(t));
	return OT_ERROR_NONE;
}

otError otPlatCryptoHkdfDeinit(otCryptoContext *aContext)
{
	tp_wipe(aContext->mContext, aContext->mContextSize);
	return OT_ERROR_NONE;
}

void otPlatCryptoRandomInit(void)
{
	(void)psa_crypto_init();
}

void otPlatCryptoRandomDeinit(void)
{
}

otError otPlatCryptoRandomGet(uint8_t *aBuffer, uint16_t aSize)
{
	return tinypsa_random(aBuffer, aSize) ? OT_ERROR_FAILED : OT_ERROR_NONE;
}

/*
 * SEC1 ECPrivateKey for P-256 with its public key, as Mbed TLS writes it:
 * the scalar at D and x || y at Q.
 */
enum { DER_LEN = 121, D = 7, Q = 57 };
static const uint8_t der_head[D] = { 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20 };
static const uint8_t der_mid[Q - D - 32] = { 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
					     0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04 };

static const uint8_t *der_scalar(const otPlatCryptoEcdsaKeyPair *k)
{
	return k->mDerLength == DER_LEN && !memcmp(k->mDerBytes, der_head, D) ? &k->mDerBytes[D]
									     : NULL;
}

otError otPlatCryptoEcdsaGenerateKey(otPlatCryptoEcdsaKeyPair *aKeyPair)
{
	uint8_t *d = aKeyPair->mDerBytes;

	if (tinypsa_p256_keygen(&d[D], &d[Q])) {
		return OT_ERROR_FAILED;
	}
	memcpy(d, der_head, D);
	memcpy(&d[D + 32], der_mid, sizeof(der_mid));
	aKeyPair->mDerLength = DER_LEN;
	return OT_ERROR_NONE;
}

otError otPlatCryptoEcdsaGetPublicKey(const otPlatCryptoEcdsaKeyPair *aKeyPair,
				      otPlatCryptoEcdsaPublicKey *aPublicKey)
{
	const uint8_t *sk = der_scalar(aKeyPair);

	return sk && !tp_be_p256_public_key(aPublicKey->m8, sk) ? OT_ERROR_NONE : OT_ERROR_PARSE;
}

otError otPlatCryptoEcdsaSign(const otPlatCryptoEcdsaKeyPair *aKeyPair,
			      const otPlatCryptoSha256Hash *aHash,
			      otPlatCryptoEcdsaSignature *aSignature)
{
	const uint8_t *sk = der_scalar(aKeyPair);

	if (!sk || tp_be_p256_sk_check(sk)) {
		return OT_ERROR_PARSE;
	}
	/* Deterministic, as OpenThread's PSA platform signs. */
	tinypsa_p256_sign_hash_det(aSignature->m8, aHash->m8, sk);
	return OT_ERROR_NONE;
}

otError otPlatCryptoEcdsaVerify(const otPlatCryptoEcdsaPublicKey *aPublicKey,
				const otPlatCryptoSha256Hash *aHash,
				const otPlatCryptoEcdsaSignature *aSignature)
{
	return !tp_be_p256_pk_check(aPublicKey->m8) &&
			       !tp_be_p256_verify_hash(aSignature->m8, aHash->m8, aPublicKey->m8)
		       ? OT_ERROR_NONE
		       : OT_ERROR_SECURITY;
}

/* PBKDF2 (RFC 8018) with the AES-CMAC-PRF-128 of RFC 4615, for the PSKc. */
otError otPlatCryptoPbkdf2GenerateKey(const uint8_t *aPassword, uint16_t aPasswordLen,
				      const uint8_t *aSalt, uint16_t aSaltLen,
				      uint32_t aIterationCounter, uint16_t aKeyLen, uint8_t *aKey)
{
	static const uint8_t zero[16];
	struct tinypsa_cmac_ctx c;
	uint8_t key[16], u[16], t[16], be[4];

	if (aPasswordLen == 16) {
		memcpy(key, aPassword, 16);
	} else {
		tp_cmac_start(&c, zero, sizeof(zero));
		tp_cmac_update(&c, aPassword, aPasswordLen);
		tp_cmac_finish(&c, key);
	}
	for (uint32_t block = 1; aKeyLen; block++) {
		uint16_t n = aKeyLen < 16 ? aKeyLen : 16;

		be[0] = block >> 24;
		be[1] = block >> 16;
		be[2] = block >> 8;
		be[3] = block;
		tp_cmac_start(&c, key, sizeof(key));
		tp_cmac_update(&c, aSalt, aSaltLen);
		tp_cmac_update(&c, be, sizeof(be));
		tp_cmac_finish(&c, u);
		memcpy(t, u, sizeof(t));
		for (uint32_t i = 1; i < aIterationCounter; i++) {
			tp_cmac_start(&c, key, sizeof(key));
			tp_cmac_update(&c, u, sizeof(u));
			tp_cmac_finish(&c, u);
			for (int j = 0; j < 16; j++) {
				t[j] ^= u[j];
			}
		}
		memcpy(aKey, t, n);
		aKey += n;
		aKeyLen -= n;
	}
	tp_wipe(&c, sizeof(c));
	tp_wipe(key, sizeof(key));
	tp_wipe(u, sizeof(u));
	tp_wipe(t, sizeof(t));
	return OT_ERROR_NONE;
}
