/* SPDX-License-Identifier: ISC */
/*
 * What the portable backend still borrows from ocrypto: P-256, until its
 * portable version lands. Same calls as backend_ocrypto.c.
 */
#include <ocrypto_ecdh_p256.h>
#include <ocrypto_ecdsa_p256.h>
#include <ocrypto_ecdsa_p256_det_sign.h>

#include "backend.h"

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
