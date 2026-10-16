/* SPDX-License-Identifier: ISC */
#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "test.h"

int test_failures;
int test_checks;

void test_smoke(void);
void test_vectors(void);
void test_pase_replay(const char *path);

void test_fail(const char *file, int line, const char *what)
{
	test_failures++;
	fprintf(stderr, "FAIL %s:%d: %s\n", file, line, what);
}

static int nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

size_t hex(uint8_t *out, size_t size, const char *s)
{
	size_t n = strlen(s) / 2;

	if (strlen(s) % 2 || n > size) {
		fprintf(stderr, "bad hex literal: %s\n", s);
		abort();
	}
	for (size_t i = 0; i < n; i++) {
		int hi = nibble(s[2 * i]), lo = nibble(s[2 * i + 1]);

		if (hi < 0 || lo < 0) {
			fprintf(stderr, "bad hex literal: %s\n", s);
			abort();
		}
		out[i] = hi << 4 | lo;
	}
	return n;
}

int main(int argc, char **argv)
{
	uint8_t b[4];

	CHECK_ST(psa_generate_random(b, sizeof(b)), PSA_ERROR_BAD_STATE);
	CHECK_ST(psa_crypto_init(), PSA_SUCCESS);
	CHECK_ST(psa_crypto_init(), PSA_SUCCESS);
	test_smoke();
#ifdef TINYPSA_HAVE_VECTORS
	test_vectors();
#endif
#ifdef TINYPSA_PASE_REPLAY
	test_pase_replay(argc > 1 ? argv[1] : NULL);
#endif
	printf("%d checks, %d failures\n", test_checks, test_failures);
	return test_failures != 0;
}
