/* SPDX-License-Identifier: ISC */
/*
 * tinytalk's recorded PASE exchange, replayed through the four SPAKE2+
 * calls exactly as tinytalk's responder makes them (src/matter_pase_sm.c):
 * reduce 40 bytes of entropy to y, check pA, pB = y*G + w0*N, then the
 * verifier's Z and V with w1 NULL and L given. The values are read at run
 * time from tinytalk's tests/host/test_matter_pase_sm.c, whose path is the
 * suite's first argument; without it the replay is skipped.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tinypsa/spake2p_p256.h>

#include "test.h"

/* Concatenates the string literals after "name =" up to the ';'. */
static int constant(const char *src, const char *name, char *out, size_t cap)
{
	char key[48];
	const char *p;
	size_t n = 0;

	snprintf(key, sizeof(key), "%s =", name);
	p = strstr(src, key);
	if (!p) {
		return -1;
	}
	for (p += strlen(key); *p && *p != ';'; p++) {
		if (*p != '"') {
			continue;
		}
		for (p++; *p && *p != '"'; p++) {
			if (n + 1 >= cap) {
				return -1;
			}
			out[n++] = *p;
		}
	}
	out[n] = '\0';
	return n ? 0 : -1;
}

static int load(const char *src, const char *name, uint8_t *out, size_t len)
{
	char h[2 * 65 + 1];

	if (constant(src, name, h, sizeof(h)) != 0 || strlen(h) != 2 * len) {
		fprintf(stderr, "pase replay: no %zu-byte %s\n", len, name);
		return -1;
	}
	hex(out, len, h);
	return 0;
}

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	char *s = NULL;
	long n;

	if (!f) {
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) == 0 && (n = ftell(f)) > 0 && fseek(f, 0, SEEK_SET) == 0 &&
	    (s = malloc((size_t)n + 1)) != NULL) {
		if (fread(s, 1, (size_t)n, f) != (size_t)n) {
			free(s);
			s = NULL;
		} else {
			s[n] = '\0';
		}
	}
	fclose(f);
	return s;
}

void test_pase_replay(const char *path)
{
	/* RFC 9383 section 4's M and N for P-256, as in test_smoke.c. */
	uint8_t M[65], N[65], w0[32], L[65], yws[40], pa[65], pb[65], Z[65], V[65];
	uint8_t y[32], got[65], z[65], v[65];
	char *src = path ? slurp(path) : NULL;

	if (!src) {
		printf("pase replay: skipped (pass tinytalk's tests/host/test_matter_pase_sm.c)\n");
		return;
	}
	HEX(M, "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
	       "5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20");
	HEX(N, "04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
	       "07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7");
	test_checks++;
	if (load(src, "K_W0", w0, 32) || load(src, "K_L", L, 65) || load(src, "K_Y_WS", yws, 40) ||
	    load(src, "K_PA", pa, 65) || load(src, "K_EXPECT_PB", pb, 65) ||
	    load(src, "K_Z", Z, 65) || load(src, "K_V", V, 65)) {
		test_fail(__FILE__, __LINE__, "recorded exchange not found");
		free(src);
		return;
	}
	free(src);

	/* matter_pase_responder_init: y from MATTER_PASE_Y_ENTROPY_LEN (40) bytes. */
	tinypsa_spake2p_p256_reduce(y, yws, sizeof(yws));
	/* on_pake1, in its order; tinytalk treats any nonzero return as failure. */
	CHECK_ST(tinypsa_spake2p_p256_check_key(pa), 0);
	CHECK_ST(tinypsa_spake2p_p256_get_key_share(got, w0, y, N), 0);
	CHECK(!memcmp(got, pb, 65));
	CHECK_ST(tinypsa_spake2p_p256_get_ZV(z, v, w0, NULL, y, pa, M, L), 0);
	CHECK(!memcmp(z, Z, 65) && !memcmp(v, V, 65));

	/* A pA off the curve is refused by check_key and again inside get_ZV. */
	pa[64] ^= 1;
	CHECK_ST(tinypsa_spake2p_p256_check_key(pa), -1);
	CHECK_ST(tinypsa_spake2p_p256_get_ZV(z, v, w0, NULL, y, pa, M, L), -1);
	pa[64] ^= 1;
	pa[0] = 0x02;
	CHECK_ST(tinypsa_spake2p_p256_check_key(pa), -1);
	printf("pase replay: %s\n", path);
}
