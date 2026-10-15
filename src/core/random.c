/* SPDX-License-Identifier: ISC */
/*
 * psa_crypto_init and the random generator: HMAC_DRBG with SHA-256
 * (SP 800-90A Rev. 1, 10.1.2), seeded and reseeded from the port's entropy
 * source. No prediction resistance and no additional input, which no
 * caller here asks for.
 */
#include <string.h>

#include "internal.h"

#define SEED_LEN    48 /* 256 bits of entropy plus a 128-bit nonce */
#define MAX_REQUEST 1024

static struct tp_drbg drbg;
static bool initialized;

psa_status_t tp_check_init(void)
{
	return initialized ? PSA_SUCCESS : PSA_ERROR_BAD_STATE;
}

/* Update (10.1.2.2): fold data into K and V. */
static void drbg_update(struct tp_drbg *d, const uint8_t *data, size_t len)
{
	uint8_t ctx[TINYPSA_HMAC_SHA256_CTX_SIZE] __attribute__((aligned(8)));

	for (uint8_t round = 0; round < 2; round++) {
		tp_be_hmac_sha256_init(ctx, d->k, sizeof(d->k));
		tp_be_hmac_sha256_update(ctx, d->v, sizeof(d->v));
		tp_be_hmac_sha256_update(ctx, &round, 1);
		tp_be_hmac_sha256_update(ctx, data, len);
		tp_be_hmac_sha256_final(ctx, d->k);
		tp_be_hmac_sha256_init(ctx, d->k, sizeof(d->k));
		tp_be_hmac_sha256_update(ctx, d->v, sizeof(d->v));
		tp_be_hmac_sha256_final(ctx, d->v);
		if (len == 0) {
			break;
		}
	}
	tp_wipe(ctx, sizeof(ctx));
}

void tp_drbg_seed(struct tp_drbg *d, const uint8_t *seed, size_t len)
{
	memset(d->k, 0x00, sizeof(d->k));
	memset(d->v, 0x01, sizeof(d->v));
	drbg_update(d, seed, len);
	d->uses = 0;
}

void tp_drbg_reseed(struct tp_drbg *d, const uint8_t *seed, size_t len)
{
	drbg_update(d, seed, len);
	d->uses = 0;
}

void tp_drbg_generate(struct tp_drbg *d, uint8_t *out, size_t len)
{
	uint8_t ctx[TINYPSA_HMAC_SHA256_CTX_SIZE] __attribute__((aligned(8)));

	while (len) {
		size_t n = len < sizeof(d->v) ? len : sizeof(d->v);

		tp_be_hmac_sha256_init(ctx, d->k, sizeof(d->k));
		tp_be_hmac_sha256_update(ctx, d->v, sizeof(d->v));
		tp_be_hmac_sha256_final(ctx, d->v);
		memcpy(out, d->v, n);
		out += n;
		len -= n;
	}
	tp_wipe(ctx, sizeof(ctx));
	drbg_update(d, NULL, 0);
	d->uses++;
}

psa_status_t psa_crypto_init(void)
{
	uint8_t seed[SEED_LEN];
	psa_status_t st = PSA_SUCCESS;

	tp_port_lock();
	if (!initialized) {
		if (tp_port_entropy(seed, sizeof(seed))) {
			st = PSA_ERROR_INSUFFICIENT_ENTROPY;
		} else {
			tp_drbg_seed(&drbg, seed, sizeof(seed));
			initialized = true;
		}
		tp_wipe(seed, sizeof(seed));
	}
	tp_port_unlock();
	return st;
}

psa_status_t tp_random(uint8_t *out, size_t len)
{
	uint8_t seed[SEED_LEN - 16];
	psa_status_t st;

	st = tp_check_init();
	if (st != PSA_SUCCESS) {
		return st;
	}
	tp_port_lock();
	while (len && st == PSA_SUCCESS) {
		size_t n = len < MAX_REQUEST ? len : MAX_REQUEST;

		if (drbg.uses >= TP_DRBG_RESEED_INTERVAL) {
			if (tp_port_entropy(seed, sizeof(seed))) {
				st = PSA_ERROR_INSUFFICIENT_ENTROPY;
				break;
			}
			tp_drbg_reseed(&drbg, seed, sizeof(seed));
		}
		tp_drbg_generate(&drbg, out, n);
		out += n;
		len -= n;
	}
	tp_port_unlock();
	tp_wipe(seed, sizeof(seed));
	return st;
}

psa_status_t psa_generate_random(uint8_t *output, size_t output_size)
{
	return tp_random(output, output_size);
}
