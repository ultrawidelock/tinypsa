/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Context sizes for the ocrypto backend, in bytes. Public because operation
 * objects embed them; backend_ocrypto.c asserts each against the real type.
 */
#ifndef TINYPSA_BACKEND_CTX_H
#define TINYPSA_BACKEND_CTX_H

#define TINYPSA_SHA256_CTX_SIZE      200 /* ocrypto_sha256_ctx */
#define TINYPSA_HMAC_SHA256_CTX_SIZE 264 /* ocrypto_hmac_sha256_ctx */
#define TINYPSA_AES_CTX_SIZE         244 /* ocrypto_aes_ecb_ctx */
#define TINYPSA_CCM_CTX_SIZE         300 /* ocrypto_aes_ccm_ctx */
#define TINYPSA_GCM_CTX_SIZE         316 /* ocrypto_aes_gcm_ctx */

#endif
