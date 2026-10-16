# Portable backend

Primitives from vendored, permissively licensed cores, so tinypsa needs
nothing from the toolchain or the SDK.

| Family | Source | Upstream |
|---|---|---|
| SHA-256, HMAC-SHA-256 | `bearssl/` | BearSSL, MIT, commit `7bea48e5e850ab4cafbe68d3765cdaba13a86d6f` |
| AES, CCM, GCM | `bearssl/` (constant-time `aes_ct`, `ghash_ctmul`) | BearSSL, as above |
| P-256 | `p256-cortex-m4/` | P256-Cortex-M4, MIT, commit `ecd3ec2222fc9e18b6b44c86bb7183971a2041fc` |
| RFC 6979 nonces | `bearssl/` (`hmac_drbg`) | BearSSL, as above |

Vendored files are copied unmodified, keeping upstream's paths and license
file. Only what the backend links is copied; `bearssl/inc` is complete
because `inner.h` includes all of it. Upstreams:
https://www.bearssl.org/git/BearSSL and https://github.com/Emill/P256-Cortex-M4

P256-Cortex-M4 is assembly for Cortex-M4 and M33. Host tests run it on
32-bit ARM Linux under QEMU (`tests/host/arm/run.sh`).
