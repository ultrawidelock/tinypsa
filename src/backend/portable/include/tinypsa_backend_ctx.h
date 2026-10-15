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
#define TINYPSA_AES_CTX_SIZE         248 /* br_aes_ct_cbcenc_keys */
#define TINYPSA_CCM_CTX_SIZE         328 /* struct ccm in aes.c */
#define TINYPSA_GCM_CTX_SIZE         352 /* struct gcm in aes.c */

#endif
