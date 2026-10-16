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
    src/core/prim.c
    src/core/keys.c
    src/core/random.c
    src/core/spake2p.c
    src/port/zephyr/port_zephyr.c
  )

  if(CONFIG_TINYPSA_OPENTHREAD)
    zephyr_library_sources(src/port/zephyr/openthread_crypto.c)
    zephyr_library_include_directories(${ZEPHYR_OPENTHREAD_MODULE_DIR}/include)
    # OpenThread allocates the contexts: the largest of either backend's,
    # checked in openthread_crypto.c. 2 is OPENTHREAD_CONFIG_CRYPTO_LIB_PLATFORM.
    zephyr_compile_definitions(
      OPENTHREAD_CONFIG_CRYPTO_LIB=2
      OPENTHREAD_CONFIG_AES_CONTEXT_SIZE=248
      OPENTHREAD_CONFIG_HMAC_SHA256_CONTEXT_SIZE=280
      OPENTHREAD_CONFIG_HKDF_CONTEXT_SIZE=32
      OPENTHREAD_CONFIG_SHA256_CONTEXT_SIZE=200
    )
  endif()

  if(CONFIG_TINYPSA_BACKEND_OCRYPTO)
    zephyr_include_directories(src/backend/ocrypto/include)
    zephyr_library_sources(src/backend/ocrypto/backend_ocrypto.c)
    zephyr_link_libraries(nrfxlib_crypto)
  endif()
  if(CONFIG_TINYPSA_BACKEND_PORTABLE)
    set(PORTABLE src/backend/portable)
    set(P256M4 ${PORTABLE}/p256-cortex-m4)
    file(GLOB_RECURSE BEARSSL_SRC ${PORTABLE}/bearssl/src/*.c)
    set(P256M4_SRC ${P256M4}/p256-cortex-m4.c ${P256M4}/p256-cortex-m4-asm-gcc.S)
    # Vendored unmodified; its warnings are upstream's.
    set_source_files_properties(${BEARSSL_SRC} ${P256M4_SRC} PROPERTIES COMPILE_OPTIONS -w)
    zephyr_include_directories(${PORTABLE}/include)
    zephyr_library_include_directories(${PORTABLE}/bearssl/inc ${PORTABLE}/bearssl/src ${P256M4})
    include(${PORTABLE}/config.cmake)
    zephyr_library_compile_definitions(${TINYPSA_P256M4_DEFINES})
    zephyr_library_sources(${PORTABLE}/hash.c ${PORTABLE}/aes.c ${PORTABLE}/p256.c
      ${BEARSSL_SRC} ${P256M4_SRC})
  endif()
endif()
