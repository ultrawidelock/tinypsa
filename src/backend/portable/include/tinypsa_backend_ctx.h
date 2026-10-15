/* SPDX-License-Identifier: ISC */
/*
 * Context sizes for the portable backend on 32-bit targets, in bytes. Public
 * because operation objects embed them; each backend file asserts its own
 * against the real type.
 */
#ifndef TINYPSA_BACKEND_CTX_H
#define TINYPSA_BACKEND_CTX_H

#define TINYPSA_SHA256_CTX_SIZE      112 /* br_sha256_context */
#define TINYPSA_HMAC_SHA256_CTX_SIZE 280 /* br_hmac_context */
/* ocrypto's, until the portable AES lands (borrowed.c). */
#define TINYPSA_AES_CTX_SIZE         244 /* ocrypto_aes_ecb_ctx */
#define TINYPSA_CCM_CTX_SIZE         300 /* ocrypto_aes_ccm_ctx */
#define TINYPSA_GCM_CTX_SIZE         316 /* ocrypto_aes_gcm_ctx */

#endif
