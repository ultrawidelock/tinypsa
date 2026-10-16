/* SPDX-License-Identifier: ISC */
/*
 * SHA-256 over the vendored BearSSL sha2small, and HMAC-SHA-256 (RFC 2104)
 * over it directly. BearSSL's own HMAC keeps a hash union sized for
 * SHA-512; this one keeps the inner hash and the outer keyed state.
 */
#include <string.h>

#include <bearssl_hash.h>

#include "backend.h"
#include "tinypsa_backend_ctx.h"

struct hmac {
	br_sha256_context in;
	uint8_t outer[32]; /* SHA-256 state after K ^ opad */
};

_Static_assert(sizeof(br_sha256_context) <= TINYPSA_SHA256_CTX_SIZE, "sha256 ctx");
_Static_assert(sizeof(struct hmac) <= TINYPSA_HMAC_SHA256_CTX_SIZE, "hmac ctx");

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

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;

	while (n--) {
		*v++ = 0;
	}
}

static void xor_pad(uint8_t k[64], uint8_t pad)
{
	for (size_t i = 0; i < 64; i++) {
		k[i] ^= pad;
	}
}

void tp_be_hmac_sha256_init(void *ctx, const uint8_t *key, size_t key_len)
{
	struct hmac *h = ctx;
	uint8_t k[64] = { 0 };

	br_sha256_init(&h->in);
	if (key_len > sizeof(k)) {
		br_sha256_update(&h->in, key, key_len);
		br_sha256_out(&h->in, k);
		br_sha256_init(&h->in);
	} else if (key_len) {
		memcpy(k, key, key_len);
	}
	xor_pad(k, 0x5c);
	br_sha256_update(&h->in, k, sizeof(k));
	br_sha256_state(&h->in, h->outer);
	xor_pad(k, 0x5c ^ 0x36);
	br_sha256_init(&h->in);
	br_sha256_update(&h->in, k, sizeof(k));
	wipe(k, sizeof(k));
}

void tp_be_hmac_sha256_update(void *ctx, const uint8_t *in, size_t len)
{
	br_sha256_update(&((struct hmac *)ctx)->in, in, len);
}

void tp_be_hmac_sha256_final(void *ctx, uint8_t out[32])
{
	struct hmac *h = ctx;
	uint8_t ih[32];

	br_sha256_out(&h->in, ih);
	br_sha256_set_state(&h->in, h->outer, 64);
	br_sha256_update(&h->in, ih, sizeof(ih));
	br_sha256_out(&h->in, out);
	wipe(ih, sizeof(ih));
}
