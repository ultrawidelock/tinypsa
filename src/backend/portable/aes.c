/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * AES, CCM and GCM over the vendored BearSSL constant-time ("ct") AES, which
 * is bitsliced and table-free. GHASH is ghash_ctmul: constant-time where a
 * 32x32->64 multiply takes constant time, as on Cortex-M4 and M33.
 *
 * BearSSL wants all associated data before any payload (br_*_flip); the
 * core guarantees that order, and the first payload or final call flips.
 *
 * With CONFIG_TINYPSA_AES_MPSL, single-block AES-128 runs on the nRF ECB
 * peripheral through MPSL, which shares it with the radio drivers; CCM, GCM
 * and 256-bit keys stay on BearSSL.
 */
#include <string.h>

#include <bearssl_aead.h>
#include <bearssl_block.h>
#include <bearssl_hash.h>

#include "backend.h"
#include "tinypsa_backend_ctx.h"

#ifdef CONFIG_TINYPSA_AES_MPSL
#include <mpsl_ecb.h>

/* The raw key, behind a NULL where BearSSL's context has its vtable. */
struct aes_hw {
	const void *none;
	uint8_t key[16];
};

_Static_assert(sizeof(struct aes_hw) <= TINYPSA_AES_CTX_SIZE, "aes hw ctx");
#endif

struct ccm {
	br_aes_ct_ctrcbc_keys aes;
	br_ccm_context ccm;
	int flipped;
};

struct gcm {
	br_aes_ct_ctr_keys aes;
	br_gcm_context gcm;
	int flipped;
};

_Static_assert(sizeof(br_aes_ct_cbcenc_keys) <= TINYPSA_AES_CTX_SIZE, "aes ctx");
_Static_assert(sizeof(struct ccm) <= TINYPSA_CCM_CTX_SIZE, "ccm ctx");
_Static_assert(sizeof(struct gcm) <= TINYPSA_GCM_CTX_SIZE, "gcm ctx");

void tp_be_aes_init(void *ctx, const uint8_t *key, size_t key_len)
{
#ifdef CONFIG_TINYPSA_AES_MPSL
	if (key_len == 16) {
		struct aes_hw *h = ctx;

		h->none = NULL;
		memcpy(h->key, key, 16);
		return;
	}
#endif
	br_aes_ct_cbcenc_init(ctx, key, key_len);
}

/* ECB as one-block CBC from a zero IV: BearSSL has no ECB entry point. */
void tp_be_aes_encrypt(void *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
	uint8_t iv[16];

#ifdef CONFIG_TINYPSA_AES_MPSL
	const struct aes_hw *h = ctx;

	if (h->none == NULL) {
		/* MPSL copies each block to RAM first, so out may alias in. */
		for (size_t i = 0; i < len; i += 16) {
			mpsl_ecb_block_encrypt_extended(h->key, &in[i], &out[i],
							MPSL_ECB_NO_FLAGS);
		}
		return;
	}
#endif
	memmove(out, in, len);
	for (size_t i = 0; i < len; i += 16) {
		memset(iv, 0, sizeof(iv));
		br_aes_ct_cbcenc_run(ctx, iv, &out[i], 16);
	}
}

void tp_be_ccm_key(void *ctx, const uint8_t *key, size_t key_len)
{
	struct ccm *c = ctx;

	br_aes_ct_ctrcbc_init(&c->aes, key, key_len);
	br_ccm_init(&c->ccm, &c->aes.vtable);
}

void tp_be_ccm_start(void *ctx, int encrypt, size_t key_len, const uint8_t *nonce,
		     size_t nonce_len, size_t tag_len, size_t pt_len, size_t ad_len)
{
	struct ccm *c = ctx;

	(void)encrypt;
	(void)key_len;
	/* The core has already checked every length br_ccm_reset() checks. */
	(void)br_ccm_reset(&c->ccm, nonce, nonce_len, ad_len, pt_len, tag_len);
	c->flipped = 0;
}

void tp_be_ccm_update_ad(void *ctx, const uint8_t *ad, size_t len)
{
	br_ccm_aad_inject(&((struct ccm *)ctx)->ccm, ad, len);
}

static void ccm_flip(struct ccm *c)
{
	if (!c->flipped) {
		br_ccm_flip(&c->ccm);
		c->flipped = 1;
	}
}

void tp_be_ccm_update(void *ctx, int encrypt, uint8_t *out, const uint8_t *in, size_t len)
{
	struct ccm *c = ctx;

	ccm_flip(c);
	memmove(out, in, len);
	br_ccm_run(&c->ccm, encrypt, out, len);
}

void tp_be_ccm_final_enc(void *ctx, uint8_t *tag, size_t tag_len)
{
	struct ccm *c = ctx;

	(void)tag_len; /* the length given to br_ccm_reset() */
	ccm_flip(c);
	br_ccm_get_tag(&c->ccm, tag);
}

int tp_be_ccm_final_dec(void *ctx, const uint8_t *tag, size_t tag_len)
{
	struct ccm *c = ctx;

	(void)tag_len;
	ccm_flip(c);
	return br_ccm_check_tag(&c->ccm, tag) ? 0 : -1;
}

void tp_be_gcm_key(void *ctx, const uint8_t *key, size_t key_len)
{
	struct gcm *g = ctx;

	br_aes_ct_ctr_init(&g->aes, key, key_len);
	br_gcm_init(&g->gcm, &g->aes.vtable, br_ghash_ctmul);
}

void tp_be_gcm_start(void *ctx, int encrypt, const uint8_t *iv, size_t iv_len)
{
	struct gcm *g = ctx;

	(void)encrypt;
	br_gcm_reset(&g->gcm, iv, iv_len);
	g->flipped = 0;
}

void tp_be_gcm_update_ad(void *ctx, const uint8_t *ad, size_t len)
{
	br_gcm_aad_inject(&((struct gcm *)ctx)->gcm, ad, len);
}

static void gcm_flip(struct gcm *g)
{
	if (!g->flipped) {
		br_gcm_flip(&g->gcm);
		g->flipped = 1;
	}
}

void tp_be_gcm_update(void *ctx, int encrypt, uint8_t *out, const uint8_t *in, size_t len)
{
	struct gcm *g = ctx;

	gcm_flip(g);
	memmove(out, in, len);
	br_gcm_run(&g->gcm, encrypt, out, len);
}

void tp_be_gcm_final_enc(void *ctx, uint8_t *tag, size_t tag_len)
{
	struct gcm *g = ctx;

	gcm_flip(g);
	br_gcm_get_tag_trunc(&g->gcm, tag, tag_len);
}

int tp_be_gcm_final_dec(void *ctx, const uint8_t *tag, size_t tag_len)
{
	struct gcm *g = ctx;

	gcm_flip(g);
	return br_gcm_check_tag_trunc(&g->gcm, tag, tag_len) ? 0 : -1;
}

/* Nothing outside the storage: the core wipes the storage itself. */
void tp_be_ctx_free(void *ctx, size_t size)
{
	(void)ctx;
	(void)size;
}
