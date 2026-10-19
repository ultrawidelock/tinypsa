/* SPDX-License-Identifier: Apache-2.0 */
#ifndef TINYPSA_TEST_H
#define TINYPSA_TEST_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int test_failures;
extern int test_checks;

void test_fail(const char *file, int line, const char *what);

#define CHECK(cond)                                                  \
	do {                                                         \
		test_checks++;                                       \
		if (!(cond)) {                                       \
			test_fail(__FILE__, __LINE__, #cond);        \
		}                                                    \
	} while (0)

#define CHECK_ST(expr, want)                                                        \
	do {                                                                        \
		long got_ = (long)(expr);                                           \
		test_checks++;                                                      \
		if (got_ != (long)(want)) {                                         \
			char m_[160];                                               \
			snprintf(m_, sizeof(m_), "%s = %ld, want %s (%ld)", #expr,  \
				 got_, #want, (long)(want));                        \
			test_fail(__FILE__, __LINE__, m_);                          \
		}                                                                   \
	} while (0)

/* Hex string to bytes; returns the length. Aborts on bad input. */
size_t hex(uint8_t *out, size_t size, const char *s);
#define HEX(buf, s) hex((buf), sizeof(buf), (s))

#endif
