#!/bin/sh
# SPDX-FileCopyrightText: 2026 Aseem Chopra
# SPDX-License-Identifier: Apache-2.0
#
# Clones the candidate cores tests/bench compares, at the commits it was
# last run with.
#
#   tests/bench/fetch.sh [dest]    (default build/ext)
set -eu

dest=${1:-build/ext}
mkdir -p "$dest"

clone() {
	[ -d "$dest/$1" ] || git clone -q "$2" "$dest/$1"
	git -C "$dest/$1" checkout -q "$3"
}

clone p256-m https://github.com/mpg/p256-m 44af59e0cff5d3b1d653bc333814077ef830e1bd
clone P256-Cortex-M4 https://github.com/Emill/P256-Cortex-M4 ecd3ec2222fc9e18b6b44c86bb7183971a2041fc
clone BearSSL https://www.bearssl.org/git/BearSSL 7bea48e5e850ab4cafbe68d3765cdaba13a86d6f
