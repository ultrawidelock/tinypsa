#!/bin/sh
# SPDX-License-Identifier: ISC
#
# The host suite on 32-bit ARM Linux under QEMU, with the portable backend
# complete: its P-256 is Cortex-M assembly, which a Mac or x86 host cannot
# run natively. Uses Apple's container CLI, or docker with CONTAINER=docker.
#
#   tests/host/arm/run.sh <Mbed TLS 3.6 tree>
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
mbedtls=$(cd "$1" && pwd)
tool=${CONTAINER:-container}

$tool run --rm -v "$root:/src" -v "$mbedtls:/mbedtls" ubuntu:24.04 \
	sh /src/tests/host/arm/inside.sh
