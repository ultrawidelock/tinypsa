# SPDX-License-Identifier: ISC
#
# P256-Cortex-M4 build options, shared by the Zephyr module and the host
# tests so both build what ships: only the P-256 functions the backend
# calls, no FPU registers as scratch (Zephyr saves those only for threads
# it knows use the FPU), and table lookups by constant-time scan: without
# has_d_cache, the fixed-base multiply copies its 1 KB table onto the
# caller's stack, which Bluetooth's work queues have no room for.
# The fast fixed-base multiply is off unless CONFIG_TINYPSA_P256_FAST_BASEMULT
# turns it on (see Kconfig): 1.4 KB of flash against slower keygen and sign.
if(CONFIG_TINYPSA_P256_FAST_BASEMULT)
  set(TINYPSA_P256M4_FAST 1)
else()
  set(TINYPSA_P256M4_FAST 0)
endif()
set(TINYPSA_P256M4_DEFINES
  has_d_cache=1
  use_fast_p256_basemult=${TINYPSA_P256M4_FAST}
  include_p256_raw_scalarmult_base=0
  include_p256_to_octet_string_compressed=0
  include_p256_to_octet_string_hybrid=0
  include_p256_decompress_point=0
  has_fpu=0)
