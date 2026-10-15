#!/bin/sh
# Fetches the pinned test vectors into $1 (default build/vectors) and checks
# each against sources.sha256. --pin records the sums instead of checking.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
pin=0
[ "${1:-}" = "--pin" ] && { pin=1; shift; }
out=${1:-build/vectors}
mkdir -p "$out"
grep -v '^#' "$here/sources.txt" | while read -r name url; do
	[ -n "$name" ] || continue
	mkdir -p "$out/$(dirname "$name")"
	[ -s "$out/$name" ] || curl -fsSL --retry 3 -o "$out/$name" "$url"
done
cd "$out"
if [ $pin = 1 ]; then
	grep -v '^#' "$here/sources.txt" | awk 'NF {print $1}' | xargs shasum -a 256 > "$here/sources.sha256"
else
	shasum -a 256 -c "$here/sources.sha256" >/dev/null
	for z in cavp/*.zip; do d=${z%.zip}; [ -d "$d" ] || unzip -qo "$z" -d "$d"; done
	# The DRBG archive nests one zip per reseed policy.
	for z in cavp/drbgtestvectors/*.zip; do d=${z%.zip}; [ -d "$d" ] || unzip -qo "$z" -d "$d"; done
fi
