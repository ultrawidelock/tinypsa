# SPDX-FileCopyrightText: 2026 Aseem Chopra
# SPDX-License-Identifier: Apache-2.0
#
# Candidate primitive cores timed and sized on a Nordic board, against
# Oberon. tests/bench/fetch.sh puts the sources in build/ext.
cmake_minimum_required(VERSION 3.20)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(tinypsa_bench)

set(EXT ${CMAKE_CURRENT_SOURCE_DIR}/../../build/ext)

# One archive per candidate, so the link map attributes every byte.
add_library(c_p256m STATIC ${EXT}/p256-m/p256-m.c)
target_include_directories(c_p256m PUBLIC ${EXT}/p256-m)

add_library(c_p256m4 STATIC
  ${EXT}/P256-Cortex-M4/p256-cortex-m4.c
  ${EXT}/P256-Cortex-M4/p256-cortex-m4-asm-gcc.S)
target_include_directories(c_p256m4 PUBLIC ${EXT}/P256-Cortex-M4)
# Only what a PSA provider plus SPAKE2+ would call.
target_compile_definitions(c_p256m4 PUBLIC
  include_p256_to_octet_string_compressed=0
  include_p256_to_octet_string_hybrid=0
  include_p256_decompress_point=0)

file(GLOB_RECURSE BR_SRC ${EXT}/BearSSL/src/*.c)
list(FILTER BR_SRC EXCLUDE REGEX "/(ssl|x509|rsa)/|sysrng")
add_library(c_bearssl STATIC ${BR_SRC})
target_include_directories(c_bearssl PRIVATE ${EXT}/BearSSL/src PUBLIC ${EXT}/BearSSL/inc)

foreach(l c_p256m c_p256m4 c_bearssl)
  target_link_libraries(${l} PRIVATE zephyr_interface)
  target_compile_options(${l} PRIVATE -w)
endforeach()

target_sources(app PRIVATE src/main.c)
target_link_libraries(app PRIVATE c_p256m c_p256m4 c_bearssl)
target_link_libraries(app PRIVATE nrfxlib_crypto)
