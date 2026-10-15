/* SPDX-License-Identifier: ISC */
/*
 * Context sizes for the host test backend: generous enough for it and for the
 * portable families tested in its place, each of which asserts its own.
 */
#ifndef TINYPSA_BACKEND_CTX_H
#define TINYPSA_BACKEND_CTX_H

#define TINYPSA_SHA256_CTX_SIZE      128
#define TINYPSA_HMAC_SHA256_CTX_SIZE 512
#define TINYPSA_AES_CTX_SIZE         512
#define TINYPSA_CCM_CTX_SIZE         1024
#define TINYPSA_GCM_CTX_SIZE         1024

#endif
