# SPDX-License-Identifier: ISC

if(CONFIG_TINYPSA)
  # Public PSA headers come from the workspace's Mbed TLS in client mode;
  # PSA_WANT_* come from Kconfig through Zephyr's config-psa.h.
  zephyr_include_directories(
    include
    ${ZEPHYR_MBEDTLS_MODULE_DIR}/include
    ${ZEPHYR_BASE}/modules/mbedtls/configs
  )
  zephyr_compile_definitions(MBEDTLS_CONFIG_FILE="tinypsa_mbedtls_config.h")

  zephyr_library_named(tinypsa)
  zephyr_library_include_directories(src/core src/backend src/port)
  zephyr_library_sources(
    src/core/aead.c
    src/core/asn1.c
    src/core/asym.c
    src/core/hash_mac.c
    src/core/kdf.c
    src/core/keys.c
    src/core/random.c
    src/port/zephyr/port_zephyr.c
  )

  if(CONFIG_TINYPSA_BACKEND_OCRYPTO)
    zephyr_include_directories(src/backend/ocrypto/include)
    zephyr_library_sources(src/backend/ocrypto/backend_ocrypto.c)
    zephyr_link_libraries(nrfxlib_crypto)
  endif()
endif()
