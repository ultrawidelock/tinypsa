# SPDX-License-Identifier: Apache-2.0
#
# The host tests on a Nordic board, over the ocrypto backend:
#
#   west build -b <board> -d build/target tests/target
#
# With tests/vectors/fetch.sh run, a sample of the vector tables is included,
# sized by TINYPSA_VECTOR_BUDGET (bytes of hex).
cmake_minimum_required(VERSION 3.20)
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(tinypsa_target_test)

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(HOST ${ROOT}/tests/host)
target_sources(app PRIVATE src/main.c ${HOST}/test_main.c ${HOST}/test_smoke.c)
# The host suite's main runs first from src/main.c.
set_source_files_properties(${HOST}/test_main.c PROPERTIES COMPILE_DEFINITIONS main=test_host_main)
target_include_directories(app PRIVATE
  ${HOST} ${ROOT}/src/core ${ROOT}/src/backend ${ROOT}/src/port)

set(TINYPSA_VECTORS_DIR "${ROOT}/build/vectors" CACHE PATH "Fetched test vectors")
set(TINYPSA_VECTOR_BUDGET 300000 CACHE STRING "Bytes of vector hex to include")
if(EXISTS "${TINYPSA_VECTORS_DIR}/wycheproof")
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vectors.c
    COMMAND ${PYTHON_EXECUTABLE} -I ${HOST}/gen_vectors.py
            ${TINYPSA_VECTORS_DIR} ${CMAKE_CURRENT_BINARY_DIR}/vectors.c ${TINYPSA_VECTOR_BUDGET}
    DEPENDS ${HOST}/gen_vectors.py ${ROOT}/tests/vectors/sources.sha256)
  target_sources(app PRIVATE ${HOST}/test_vectors.c ${CMAKE_CURRENT_BINARY_DIR}/vectors.c)
  target_compile_definitions(app PRIVATE TINYPSA_HAVE_VECTORS)
else()
  message(WARNING "no vectors in ${TINYPSA_VECTORS_DIR}: run tests/vectors/fetch.sh")
endif()
