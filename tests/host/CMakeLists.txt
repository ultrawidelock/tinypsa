# SPDX-License-Identifier: ISC
#
# Host tests: the core, a host port, and a test-only backend over Mbed TLS's
# legacy crypto (ocrypto ships only as Cortex-M archives).
#
#   cmake -S tests/host -B build/host -G Ninja \
#     -DCMAKE_C_COMPILER=/usr/bin/cc -DTINYPSA_MBEDTLS_DIR=<mbedtls 3.6 tree>
#   cmake --build build/host && build/host/tinypsa_host_test
cmake_minimum_required(VERSION 3.20)
project(tinypsa_host_tests C)

set(TINYPSA_MBEDTLS_DIR "" CACHE PATH "Mbed TLS 3.6 source tree")
if(NOT EXISTS "${TINYPSA_MBEDTLS_DIR}/include/psa/crypto.h")
  message(FATAL_ERROR "set TINYPSA_MBEDTLS_DIR to an Mbed TLS 3.6 source tree")
endif()

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(CMAKE_C_STANDARD 11)
add_compile_options(-Wall -Wextra -Wno-unused-parameter -g -O1 -fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

# Mbed TLS, built once: its legacy primitives back the test backend, and its
# PSA implementation is the reference for the differential test. rename.h
# moves its PSA entry points to ref_psa_* so tinypsa's own can link beside them.
file(GLOB MBEDTLS_SRC ${TINYPSA_MBEDTLS_DIR}/library/*.c)
add_library(mbedtls_host STATIC ${MBEDTLS_SRC})
target_include_directories(mbedtls_host PUBLIC
  ${TINYPSA_MBEDTLS_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/diff ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE ${TINYPSA_MBEDTLS_DIR}/library ${TINYPSA_MBEDTLS_DIR}/include/library)
target_compile_definitions(mbedtls_host PUBLIC MBEDTLS_CONFIG_FILE="ref_config.h")
target_compile_options(mbedtls_host PRIVATE -w)

add_library(test_backend STATIC backend_mbedtls/backend_mbedtls.c)
target_include_directories(test_backend PRIVATE
  ${ROOT}/src/backend ${CMAKE_CURRENT_SOURCE_DIR}/backend_mbedtls/include)
target_link_libraries(test_backend PRIVATE mbedtls_host)

# The portable backend's C families over the vendored BearSSL, with the test
# backend standing in for the rest (TP_TEST_PORTABLE_* leaves its versions out).
set(PORTABLE ${ROOT}/src/backend/portable)
file(GLOB_RECURSE BEARSSL_SRC ${PORTABLE}/bearssl/src/*.c)
set_source_files_properties(${BEARSSL_SRC} PROPERTIES COMPILE_OPTIONS -w)
add_library(portable_backend STATIC
  ${PORTABLE}/hash.c ${BEARSSL_SRC} backend_mbedtls/backend_mbedtls.c)
target_include_directories(portable_backend PRIVATE
  ${ROOT}/src/backend ${CMAKE_CURRENT_SOURCE_DIR}/backend_mbedtls/include
  ${PORTABLE}/bearssl/inc ${PORTABLE}/bearssl/src)
target_compile_definitions(portable_backend PRIVATE TP_TEST_PORTABLE_HASH)
target_link_libraries(portable_backend PRIVATE mbedtls_host)

# Differential test reference: Mbed TLS PSA.
add_library(ref_shim STATIC diff/ref_shim.c)
target_link_libraries(ref_shim PRIVATE mbedtls_host)

# CAVP and Wycheproof tables, when tests/vectors/fetch.sh has run.
set(TINYPSA_VECTORS_DIR "${ROOT}/build/vectors" CACHE PATH "Fetched test vectors")
if(EXISTS "${TINYPSA_VECTORS_DIR}/wycheproof")
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vectors.c
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
            ${TINYPSA_VECTORS_DIR} ${CMAKE_CURRENT_BINARY_DIR}/vectors.c
    DEPENDS gen_vectors.py ${CMAKE_CURRENT_SOURCE_DIR}/../vectors/sources.sha256)
  add_library(vectors STATIC ${CMAKE_CURRENT_BINARY_DIR}/vectors.c)
  target_include_directories(vectors PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_options(vectors PRIVATE -O0)
else()
  message(WARNING "no vectors in ${TINYPSA_VECTORS_DIR}: run tests/vectors/fetch.sh")
endif()

# tinypsa on the host port over one backend, with its test suite and
# differential test.
function(tinypsa_suite suffix backend)
  add_library(tinypsa_host${suffix} STATIC
    ${ROOT}/src/core/aead.c
    ${ROOT}/src/core/asn1.c
    ${ROOT}/src/core/asym.c
    ${ROOT}/src/core/hash_mac.c
    ${ROOT}/src/core/kdf.c
    ${ROOT}/src/core/keys.c
    ${ROOT}/src/core/random.c
    port_host.c)
  target_include_directories(tinypsa_host${suffix} PUBLIC
    ${ROOT}/include ${TINYPSA_MBEDTLS_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/backend_mbedtls/include ${CMAKE_CURRENT_SOURCE_DIR}
    ${ROOT}/src/core ${ROOT}/src/backend ${ROOT}/src/port)
  target_compile_definitions(tinypsa_host${suffix} PUBLIC
    MBEDTLS_CONFIG_FILE="tinypsa_mbedtls_config.h"
    TINYPSA_PSA_WANT_FILE="host_psa_want.h"
    TP_PERSISTENT=1)
  target_link_libraries(tinypsa_host${suffix} PRIVATE ${backend})

  add_executable(tinypsa_host_test${suffix} test_main.c test_smoke.c)
  target_link_libraries(tinypsa_host_test${suffix} PRIVATE tinypsa_host${suffix})
  if(TARGET vectors)
    target_sources(tinypsa_host_test${suffix} PRIVATE test_vectors.c)
    target_compile_definitions(tinypsa_host_test${suffix} PRIVATE TINYPSA_HAVE_VECTORS)
    target_link_libraries(tinypsa_host_test${suffix} PRIVATE vectors)
  endif()

  add_executable(tinypsa_diff${suffix} diff/diff.c diff/tp_shim.c)
  target_include_directories(tinypsa_diff${suffix} PRIVATE diff)
  target_link_libraries(tinypsa_diff${suffix} PRIVATE tinypsa_host${suffix} ref_shim)

  add_test(NAME host${suffix} COMMAND tinypsa_host_test${suffix})
  add_test(NAME diff${suffix} COMMAND tinypsa_diff${suffix} 1 20000)
endfunction()

enable_testing()
tinypsa_suite("" test_backend)
tinypsa_suite(_portable portable_backend)
