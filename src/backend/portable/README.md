# Portable backend

Primitives from vendored, permissively licensed cores, so tinypsa needs
nothing from the toolchain or the SDK.

| Family | Source | Upstream |
|---|---|---|
| SHA-256, HMAC-SHA-256 | `bearssl/` | BearSSL, MIT, commit `7bea48e5e850ab4cafbe68d3765cdaba13a86d6f` |
| AES, CCM, GCM | ocrypto, for now (`borrowed.c`) | |
| P-256 | ocrypto, for now (`borrowed.c`) | |

Vendored files are copied unmodified, keeping upstream's paths and license
file. Only what the backend links is copied; `bearssl/inc` is complete
because `inner.h` includes all of it. Upstream: https://www.bearssl.org/git/BearSSL
