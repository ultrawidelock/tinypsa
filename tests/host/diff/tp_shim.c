/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/* The shim against tinypsa. */
#include <psa/crypto.h>

#define SHIM(name) tps_##name
#include "shim.inc"
