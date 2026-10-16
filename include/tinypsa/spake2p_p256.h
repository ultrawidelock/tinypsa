/* SPDX-License-Identifier: ISC */
/*
 * SPAKE2+ over P-256 (RFC 9383), the group operations only: the caller owns
 * the transcript, key schedule and confirmation. The contract is ocrypto's
 * (ocrypto_spake2p_p256.h), so code written against it changes only names.
 * Points are SEC1 uncompressed, 65 bytes; scalars are 32 bytes big-endian.
 * Functions that return int give 0 on success and -1 otherwise, including
 * when a scalar is 0 or a result is the point at infinity.
 */
#ifndef TINYPSA_SPAKE2P_P256_H
#define TINYPSA_SPAKE2P_P256_H

#include <stddef.h>
#include <stdint.h>

/* x = xs mod n, for a big-endian xs of any length (w0s, w1s, a random draw). */
void tinypsa_spake2p_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len);

/* Whether K is an uncompressed point on the curve. */
int tinypsa_spake2p_p256_check_key(const uint8_t K[65]);

/* XY = xy*G + w0*MN: the prover's X with M, the verifier's Y with N. */
int tinypsa_spake2p_p256_get_key_share(uint8_t XY[65], const uint8_t w0[32], const uint8_t xy[32],
				       const uint8_t MN[65]);

/*
 * Z = xy*T and, with T = YX - w0*NM, V = w1*T on the prover (L NULL) or
 * V = xy*L on the verifier (w1 NULL). YX is checked as check_key does.
 */
int tinypsa_spake2p_p256_get_ZV(uint8_t Z[65], uint8_t V[65], const uint8_t w0[32],
				const uint8_t w1[32], const uint8_t xy[32], const uint8_t YX[65],
				const uint8_t NM[65], const uint8_t L[65]);

#endif
