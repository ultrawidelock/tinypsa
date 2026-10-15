/* SPDX-License-Identifier: ISC */
/*
 * SHA-256 and HMAC-SHA-256 over the vendored BearSSL sha2small and hmac.
 */
#include <bearssl_hash.h>
#include <bearssl_hmac.h>

#include "backend.h"
#include "tinypsa_backend_ctx.h"

_Static_assert(sizeof(br_sha256_context) <= TINYPSA_SHA256_CTX_SIZE, "sha256 ctx");
_Static_assert(sizeof(br_hmac_context) <= TINYPSA_HMAC_SHA256_CTX_SIZE, "hmac ctx");

void tp_be_sha256_init(void *ctx)
{
	br_sha256_init(ctx);
}

void tp_be_sha256_update(void *ctx, const uint8_t *in, size_t len)
{
	br_sha256_update(ctx, in, len);
}

void tp_be_sha256_final(void *ctx, uint8_t out[32])
{
	br_sha256_out(ctx, out);
}

void tp_be_hmac_sha256_init(void *ctx, const uint8_t *key, size_t key_len)
{
	br_hmac_key_context kc;
	volatile uint8_t *p = (volatile uint8_t *)&kc;

	br_hmac_key_init(&kc, &br_sha256_vtable, key, key_len);
	br_hmac_init(ctx, &kc, 0);
	/* kc holds the keyed inner and outer states. */
	for (size_t i = 0; i < sizeof(kc); i++) {
		p[i] = 0;
	}
}

void tp_be_hmac_sha256_update(void *ctx, const uint8_t *in, size_t len)
{
	br_hmac_update(ctx, in, len);
}

void tp_be_hmac_sha256_final(void *ctx, uint8_t out[32])
{
	br_hmac_out(ctx, out);
}
