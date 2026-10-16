# SPDX-License-Identifier: ISC
#
# P256-Cortex-M4 build options, shared by the Zephyr module and the host
# tests so both build what ships: only the P-256 functions the backend
# calls, and no FPU registers as scratch (Zephyr saves those only for
# threads it knows use the FPU).
set(TINYPSA_P256M4_DEFINES
  include_p256_raw_scalarmult_generic=0
  include_p256_raw_scalarmult_base=0
  include_p256_to_octet_string_compressed=0
  include_p256_to_octet_string_hybrid=0
  include_p256_decompress_point=0
  has_fpu=0)
