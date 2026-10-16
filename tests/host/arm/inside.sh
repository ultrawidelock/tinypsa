#!/bin/sh
# SPDX-License-Identifier: ISC
# Runs inside the stock Ubuntu container started by run.sh: the repository
# is at /src and Mbed TLS at /mbedtls. Installs a 32-bit ARM cross
# toolchain and QEMU user mode first.
set -eu

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends \
	gcc-arm-linux-gnueabihf libc6-dev-armhf-cross libasan8-armhf-cross \
	libubsan1-armhf-cross qemu-user cmake ninja-build python3 >/dev/null

b=/src/build/host-arm
cmake -S /src/tests/host -B "$b" -G Ninja \
	-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=arm \
	-DCMAKE_C_COMPILER=arm-linux-gnueabihf-gcc \
	-DCMAKE_ASM_COMPILER=arm-linux-gnueabihf-gcc \
	-DTINYPSA_MBEDTLS_DIR=/mbedtls -DTINYPSA_HOST_P256_ASM=ON
cmake --build "$b"

# LeakSanitizer does not run under QEMU user mode.
export ASAN_OPTIONS=detect_leaks=0
run() { qemu-arm -L /usr/arm-linux-gnueabihf "$@"; }

run "$b/tinypsa_host_test_portable"
mkdir -p "$b/diffrun"
cd "$b/diffrun"
for seed in 1 2 3 4; do
	rm -f ./*.psa_its
	run ../tinypsa_diff_portable "$seed" 50000
done
