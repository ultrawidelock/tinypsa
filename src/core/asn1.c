/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The two Mbed TLS ASN.1 readers OpenThread's crypto_psa.c calls to unwrap
 * a SEC1 private key, with the semantics mbedtls/asn1.h documents: DER
 * lengths up to four bytes, and only non-negative integers that fit an int.
 */
#include <mbedtls/asn1.h>

static int get_len(unsigned char **p, const unsigned char *end, size_t *len)
{
	size_t n;

	if (end - *p < 1) {
		return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
	}
	if (!(**p & 0x80)) {
		*len = *(*p)++;
	} else {
		n = *(*p)++ & 0x7f;
		if (n == 0 || n > 4) {
			return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
		}
		if ((size_t)(end - *p) < n) {
			return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
		}
		*len = 0;
		while (n--) {
			*len = *len << 8 | *(*p)++;
		}
	}
	if (*len > (size_t)(end - *p)) {
		return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
	}
	return 0;
}

int mbedtls_asn1_get_tag(unsigned char **p, const unsigned char *end, size_t *len, int tag)
{
	if (end - *p < 1) {
		return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
	}
	if (**p != tag) {
		return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
	}
	(*p)++;
	return get_len(p, end, len);
}

int mbedtls_asn1_get_int(unsigned char **p, const unsigned char *end, int *val)
{
	size_t len;
	int ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_INTEGER);

	if (ret) {
		return ret;
	}
	/* Zero is 02 01 00; an empty integer is malformed. Negatives are refused. */
	if (len == 0 || (**p & 0x80)) {
		return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
	}
	while (len > 0 && **p == 0) {
		(*p)++;
		len--;
	}
	if (len > sizeof(int) || (len == sizeof(int) && (**p & 0x80))) {
		return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
	}
	*val = 0;
	while (len--) {
		*val = (int)((unsigned int)*val << 8 | *(*p)++);
	}
	return 0;
}
