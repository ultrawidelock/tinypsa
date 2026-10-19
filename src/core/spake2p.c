/* SPDX-License-Identifier: Apache-2.0 */
/*
 * SPAKE2+ over P-256 from the backend's point operations, so one
 * composition, and the RFC 9383 vectors, cover every backend.
 */
#include <tinypsa/spake2p_p256.h>

#include "internal.h"

void tinypsa_spake2p_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len)
{
	tp_be_p256_reduce(x, xs, xs_len);
}

int tinypsa_spake2p_p256_check_key(const uint8_t K[65])
{
	return K[0] == 0x04 && !tp_be_p256_pk_check(&K[1]) ? 0 : -1;
}

int tinypsa_spake2p_p256_get_key_share(uint8_t XY[65], const uint8_t w0[32], const uint8_t xy[32],
				       const uint8_t MN[65])
{
	uint8_t a[64], b[64];
	int ret = tp_be_p256_public_key(a, xy) || tp_be_p256_mul(b, w0, &MN[1]) ||
		  tp_be_p256_add(&XY[1], a, b, 0);

	XY[0] = 0x04;
	tp_wipe(a, sizeof(a));
	tp_wipe(b, sizeof(b));
	return ret ? -1 : 0;
}

int tinypsa_spake2p_p256_get_ZV(uint8_t Z[65], uint8_t V[65], const uint8_t w0[32],
				const uint8_t w1[32], const uint8_t xy[32], const uint8_t YX[65],
				const uint8_t NM[65], const uint8_t L[65])
{
	uint8_t a[64], t[64];
	int ret;

	/* Neither side named: nothing to compute V from. */
	if (!w1 && !L) {
		return -1;
	}
	ret = tinypsa_spake2p_p256_check_key(YX) || tp_be_p256_mul(a, w0, &NM[1]) ||
	      tp_be_p256_add(t, &YX[1], a, 1) || tp_be_p256_mul(&Z[1], xy, t) ||
	      (w1 ? tp_be_p256_mul(&V[1], w1, t) : tp_be_p256_mul(&V[1], xy, &L[1]));

	Z[0] = V[0] = 0x04;
	tp_wipe(a, sizeof(a));
	tp_wipe(t, sizeof(t));
	return ret ? -1 : 0;
}
