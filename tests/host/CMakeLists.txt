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

# tinypsa itself, on the host port and the test backend.
add_library(tinypsa_host STATIC
  ${ROOT}/src/core/aead.c
  ${ROOT}/src/core/asn1.c
  ${ROOT}/src/core/asym.c
  ${ROOT}/src/core/hash_mac.c
  ${ROOT}/src/core/kdf.c
  ${ROOT}/src/core/keys.c
  ${ROOT}/src/core/random.c
  port_host.c)
target_include_directories(tinypsa_host PUBLIC
  ${ROOT}/include ${TINYPSA_MBEDTLS_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/backend_mbedtls/include ${CMAKE_CURRENT_SOURCE_DIR}
  ${ROOT}/src/core ${ROOT}/src/backend ${ROOT}/src/port)
target_compile_definitions(tinypsa_host PUBLIC
  MBEDTLS_CONFIG_FILE="tinypsa_mbedtls_config.h"
  TINYPSA_PSA_WANT_FILE="host_psa_want.h"
  TP_PERSISTENT=1)
target_link_libraries(tinypsa_host PRIVATE test_backend)

add_executable(tinypsa_host_test test_main.c test_smoke.c)
target_link_libraries(tinypsa_host_test PRIVATE tinypsa_host)

# Differential test against Mbed TLS PSA.
add_library(ref_shim STATIC diff/ref_shim.c)
target_link_libraries(ref_shim PRIVATE mbedtls_host)
add_executable(tinypsa_diff diff/diff.c diff/tp_shim.c)
target_include_directories(tinypsa_diff PRIVATE diff)
target_link_libraries(tinypsa_diff PRIVATE tinypsa_host ref_shim)

# CAVP and Wycheproof tables, when tests/vectors/fetch.sh has run.
set(TINYPSA_VECTORS_DIR "${ROOT}/build/vectors" CACHE PATH "Fetched test vectors")
if(EXISTS "${TINYPSA_VECTORS_DIR}/wycheproof")
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vectors.c
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
            ${TINYPSA_VECTORS_DIR} ${CMAKE_CURRENT_BINARY_DIR}/vectors.c
    DEPENDS gen_vectors.py ${CMAKE_CURRENT_SOURCE_DIR}/../vectors/sources.sha256)
  target_sources(tinypsa_host_test PRIVATE test_vectors.c ${CMAKE_CURRENT_BINARY_DIR}/vectors.c)
  set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/vectors.c PROPERTIES COMPILE_OPTIONS -O0)
  target_compile_definitions(tinypsa_host_test PRIVATE TINYPSA_HAVE_VECTORS)
else()
  message(WARNING "no vectors in ${TINYPSA_VECTORS_DIR}: run tests/vectors/fetch.sh")
endif()

enable_testing()
add_test(NAME host COMMAND tinypsa_host_test)
add_test(NAME diff COMMAND tinypsa_diff 1 20000)
