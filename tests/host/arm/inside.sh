#!/bin/sh
# SPDX-FileCopyrightText: 2026 Aseem Chopra
# SPDX-License-Identifier: Apache-2.0
# Runs inside the stock Ubuntu container started by run.sh: the repository
# is at /src and Mbed TLS at /mbedtls. Installs a 32-bit ARM cross
# toolchain and QEMU user mode first. Under QEMU everything runs several
# times slower, so the ARM run leaves AddressSanitizer to the native host run
# (this one is for the assembly) and runs the seeds in parallel.
set -eu

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends \
	gcc-arm-linux-gnueabihf libc6-dev-armhf-cross libubsan1-armhf-cross qemu-user cmake ninja-build python3 >/dev/null

b=/src/build/host-arm
cmake -S /src/tests/host -B "$b" -G Ninja \
	-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=arm \
	-DCMAKE_C_COMPILER=arm-linux-gnueabihf-gcc \
	-DCMAKE_ASM_COMPILER=arm-linux-gnueabihf-gcc \
	-DTINYPSA_MBEDTLS_DIR=/mbedtls -DTINYPSA_HOST_P256_ASM=ON \
	-DTINYPSA_HOST_SANITIZE=undefined
cmake --build "$b"

run() { qemu-arm -L /usr/arm-linux-gnueabihf "$@"; }

run "$b/tinypsa_host_test_portable"
pids=
for seed in 1 2 3 4; do
	d="$b/diffrun$seed"
	rm -rf "$d" && mkdir -p "$d"
	(cd "$d" && run ../tinypsa_diff_portable "$seed" 50000) &
	pids="$pids $!"
done
rc=0
for p in $pids; do wait "$p" || rc=1; done
exit $rc
