/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Times candidate P-256 cores, AES-GCM and SHA-256 on the target and checks
 * every result against Oberon, so a fast wrong answer cannot pass as a
 * result. Cycles come from the DWT counter with interrupts locked; each
 * figure is the best of REPS runs. Each P-256 core runs on its own thread
 * so its stack peak can be read back.
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <cmsis_core.h>

#include <ocrypto_aes_gcm.h>
#include <ocrypto_ecdh_p256.h>
#include <ocrypto_ecdsa_p256.h>
#include <ocrypto_sha256.h>

#include <bearssl.h>
#include "p256-cortex-m4.h"
#include "p256-m.h"

#define REPS 3
#define MHZ  64u

static uint32_t xs = 0x2545F491u;

/* Test-only filler; not a secure source. */
static void fill(uint8_t *p, size_t n)
{
	while (n--) {
		xs ^= xs << 13;
		xs ^= xs >> 17;
		xs ^= xs << 5;
		*p++ = (uint8_t)xs;
	}
}

int p256_generate_random(uint8_t *out, unsigned n)
{
	fill(out, n);
	return 0;
}

static int failures;
#define EXPECT(c)                                                                  \
	do {                                                                       \
		if (!(c)) {                                                        \
			printf("  MISMATCH %s:%d %s\n", __func__, __LINE__, #c);   \
			failures++;                                                \
		}                                                                  \
	} while (0)

#define TIME(dst, ...)                                                             \
	do {                                                                       \
		uint32_t best_ = UINT32_MAX;                                       \
		for (int r_ = 0; r_ < REPS; r_++) {                                \
			unsigned int k_ = irq_lock();                              \
			uint32_t t_ = DWT->CYCCNT;                                 \
			__VA_ARGS__;                                               \
			t_ = DWT->CYCCNT - t_;                                     \
			irq_unlock(k_);                                            \
			best_ = MIN(best_, t_);                                    \
		}                                                                  \
		(dst) = best_;                                                     \
	} while (0)

/* Reference material, all from Oberon. */
static uint8_t sk[32], pk[64], peer_pk[64], z_ref[32], hash[32], sig_ref[64];

struct timing {
	uint32_t keygen, ecdh, sign, verify;
};

static void oberon(struct timing *t, const void *arg)
{
	uint8_t p[64], z[32], sig[64], ek[32];
	int rc = 0;

	TIME(t->keygen, rc |= ocrypto_ecdh_p256_public_key(p, sk));
	EXPECT(rc == 0 && !memcmp(p, pk, 64));
	TIME(t->ecdh, rc |= ocrypto_ecdh_p256_common_secret(z, sk, peer_pk));
	EXPECT(rc == 0 && !memcmp(z, z_ref, 32));
	fill(ek, sizeof(ek));
	TIME(t->sign, rc |= ocrypto_ecdsa_p256_sign_hash(sig, hash, sk, ek));
	EXPECT(rc == 0 && ocrypto_ecdsa_p256_verify_hash(sig, hash, pk) == 0);
	TIME(t->verify, rc |= ocrypto_ecdsa_p256_verify_hash(sig_ref, hash, pk));
	EXPECT(rc == 0);
}

static void p256m(struct timing *t, const void *arg)
{
	uint8_t priv[32], pub[64], chk[64], z[32], sig[64];
	int rc = 0;

	TIME(t->keygen, rc |= p256_gen_keypair(priv, pub));
	EXPECT(rc == P256_SUCCESS && ocrypto_ecdh_p256_public_key(chk, priv) == 0 &&
	       !memcmp(chk, pub, 64));
	TIME(t->ecdh, rc |= p256_ecdh_shared_secret(z, sk, peer_pk));
	EXPECT(rc == P256_SUCCESS && !memcmp(z, z_ref, 32));
	TIME(t->sign, rc |= p256_ecdsa_sign(sig, sk, hash, 32));
	EXPECT(rc == P256_SUCCESS && ocrypto_ecdsa_p256_verify_hash(sig, hash, pk) == 0);
	TIME(t->verify, rc |= p256_ecdsa_verify(sig_ref, pk, hash, 32));
	EXPECT(rc == P256_SUCCESS);
}

static void p256m4(struct timing *t, const void *arg)
{
	uint32_t d[8], px[8], py[8], qx[8], qy[8], r[8], s[8], k[8], vx[8], vy[8];
	uint8_t z[32], kb[32], sig[64], oct[65];
	bool ok = true;

	p256_convert_endianness(d, sk, 32);
	TIME(t->keygen, ok &= p256_keygen(px, py, d));
	p256_point_to_octet_string_uncompressed(oct, px, py);
	EXPECT(ok && oct[0] == 4 && !memcmp(oct + 1, pk, 64));
	p256_convert_endianness(qx, peer_pk, 32);
	p256_convert_endianness(qy, peer_pk + 32, 32);
	TIME(t->ecdh, ok &= p256_ecdh_calc_shared_secret(z, d, qx, qy));
	EXPECT(ok && !memcmp(z, z_ref, 32));
	fill(kb, sizeof(kb));
	p256_convert_endianness(k, kb, 32);
	TIME(t->sign, ok &= p256_sign(r, s, hash, 32, d, k));
	p256_convert_endianness(sig, r, 32);
	p256_convert_endianness(sig + 32, s, 32);
	EXPECT(ok && ocrypto_ecdsa_p256_verify_hash(sig, hash, pk) == 0);
	p256_convert_endianness(vx, pk, 32);
	p256_convert_endianness(vy, pk + 32, 32);
	p256_convert_endianness(r, sig_ref, 32);
	p256_convert_endianness(s, sig_ref + 32, 32);
	TIME(t->verify, ok &= p256_verify(vx, vy, hash, 32, r, s));
	EXPECT(ok);
}

struct br_variant {
	const br_ec_impl *impl;
	br_ecdsa_sign sign;
	br_ecdsa_vrfy vrfy;
};

static void bearssl(struct timing *t, const void *arg)
{
	const struct br_variant *v = arg;
	br_ec_private_key bsk = { BR_EC_secp256r1, sk, 32 };
	br_ec_public_key bpk;
	uint8_t q[65], g[65], pkq[65], sig[64];
	size_t n = 0;
	uint32_t ok = 1;

	TIME(t->keygen, n = br_ec_compute_pub(v->impl, &bpk, q, &bsk));
	EXPECT(n == 65 && q[0] == 4 && !memcmp(q + 1, pk, 64));
	TIME(t->ecdh, g[0] = 4; memcpy(g + 1, peer_pk, 64);
	     ok &= v->impl->mul(g, 65, sk, 32, BR_EC_secp256r1));
	EXPECT(ok == 1 && !memcmp(g + 1, z_ref, 32));
	TIME(t->sign, n = v->sign(v->impl, &br_sha256_vtable, hash, &bsk, sig));
	EXPECT(n == 64 && ocrypto_ecdsa_p256_verify_hash(sig, hash, pk) == 0);
	pkq[0] = 4;
	memcpy(pkq + 1, pk, 64);
	bpk = (br_ec_public_key){ BR_EC_secp256r1, pkq, 65 };
	TIME(t->verify, ok &= v->vrfy(v->impl, hash, 32, &bpk, sig_ref, 64));
	EXPECT(ok == 1);
}

#define STACK_SZ 8192
K_THREAD_STACK_DEFINE(bstack, STACK_SZ);
static struct k_thread bthread;

struct job {
	const char *name;
	void (*fn)(struct timing *t, const void *arg);
	const void *arg;
	struct timing t;
};

static void job_entry(void *a, void *b, void *c)
{
	struct job *j = a;

	j->fn(&j->t, j->arg);
}

static void ms(char *out, size_t size, uint64_t cycles)
{
	uint64_t us = cycles / MHZ;

	snprintf(out, size, "%u.%u", (unsigned int)(us / 1000), (unsigned int)(us % 1000 / 100));
}

static void run(struct job *j)
{
	size_t unused = 0;
	char a[16], b[16], c[16], d[16], e[16];

	k_thread_create(&bthread, bstack, STACK_SZ, job_entry, j, NULL, NULL,
			K_PRIO_PREEMPT(1), 0, K_NO_WAIT);
	k_thread_join(&bthread, K_FOREVER);
	k_thread_stack_space_get(&bthread, &unused);
	ms(a, sizeof(a), j->t.keygen);
	ms(b, sizeof(b), j->t.ecdh);
	ms(c, sizeof(c), j->t.sign);
	ms(d, sizeof(d), j->t.verify);
	/* The CASE bench's P-256 work: 2 key pairs, ECDH, a sign, 3 verifies. */
	ms(e, sizeof(e), 2ull * j->t.keygen + j->t.ecdh + j->t.sign + 3ull * j->t.verify);
	printf("p256 %-14s keygen %7s ms  ecdh %7s ms  sign %7s ms  verify %7s ms  case %8s ms  stack %u B\n",
	       j->name, a, b, c, d, e, (unsigned int)(STACK_SZ - unused));
}

static uint8_t buf[1024], ct_o[1024], ct_b[1024];

static void symmetric(void)
{
	uint8_t key[32], iv[12], tag_o[16], tag_b[16], d_o[32], d_b[32];
	uint32_t to, tb, tc;

	fill(key, sizeof(key));
	fill(iv, sizeof(iv));
	fill(buf, sizeof(buf));
	for (size_t ks = 16; ks <= 32; ks += 16) {
		br_aes_ct_ctr_keys bc;
		br_gcm_context gc;

		TIME(to, ocrypto_aes_gcm_encrypt(ct_o, tag_o, 16, buf, sizeof(buf), key, ks, iv,
						 NULL, 0));
		TIME(tb, br_aes_ct_ctr_init(&bc, key, ks); br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);
		     br_gcm_reset(&gc, iv, 12); br_gcm_flip(&gc); memcpy(ct_b, buf, sizeof(buf));
		     br_gcm_run(&gc, 1, ct_b, sizeof(ct_b)); br_gcm_get_tag(&gc, tag_b));
		EXPECT(!memcmp(ct_o, ct_b, sizeof(buf)) && !memcmp(tag_o, tag_b, 16));
		TIME(tc, br_aes_ct_ctr_init(&bc, key, ks); br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
		     br_gcm_reset(&gc, iv, 12); br_gcm_flip(&gc); memcpy(ct_b, buf, sizeof(buf));
		     br_gcm_run(&gc, 1, ct_b, sizeof(ct_b)); br_gcm_get_tag(&gc, tag_b));
		EXPECT(!memcmp(ct_o, ct_b, sizeof(buf)) && !memcmp(tag_o, tag_b, 16));
		printf("aes-%u-gcm 1 KiB: oberon %u cyc, bearssl ct+ctmul32 %u cyc, ct+ctmul %u cyc\n",
		       (unsigned int)(ks * 8), to, tb, tc);
	}

	br_sha256_context sc;

	TIME(to, ocrypto_sha256(d_o, buf, sizeof(buf)));
	TIME(tb, br_sha256_init(&sc); br_sha256_update(&sc, buf, sizeof(buf)); br_sha256_out(&sc, d_b));
	EXPECT(!memcmp(d_o, d_b, 32));
	printf("sha256 1 KiB: oberon %u cyc, bearssl %u cyc\n", to, tb);
}

static const struct br_variant br31 = { &br_ec_p256_m31, br_ecdsa_i31_sign_raw,
					br_ecdsa_i31_vrfy_raw };
static const struct br_variant br15 = { &br_ec_p256_m15, br_ecdsa_i15_sign_raw,
					br_ecdsa_i15_vrfy_raw };

static struct job jobs[] = {
	{ "oberon", oberon, NULL },
	{ "p256-m", p256m, NULL },
	{ "p256-cortex-m4", p256m4, NULL },
	{ "bearssl m31", bearssl, &br31 },
	{ "bearssl m15", bearssl, &br15 },
};

int main(void)
{
	uint8_t peer_sk[32], ek[32];

	CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
	DWT->CYCCNT = 0;
	DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

	do {
		fill(sk, sizeof(sk));
	} while (ocrypto_ecdh_p256_secret_key_check(sk));
	do {
		fill(peer_sk, sizeof(peer_sk));
	} while (ocrypto_ecdh_p256_secret_key_check(peer_sk));
	ocrypto_ecdh_p256_public_key(pk, sk);
	ocrypto_ecdh_p256_public_key(peer_pk, peer_sk);
	ocrypto_ecdh_p256_common_secret(z_ref, sk, peer_pk);
	fill(hash, sizeof(hash));
	fill(ek, sizeof(ek));
	ocrypto_ecdsa_p256_sign_hash(sig_ref, hash, sk, ek);

	printf("bench start, %u MHz, best of %d\n", MHZ, REPS);
	for (size_t i = 0; i < ARRAY_SIZE(jobs); i++) {
		run(&jobs[i]);
	}
	symmetric();
	printf("bench done: %d mismatches\n", failures);
	return 0;
}
