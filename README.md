# tinypsa

A minimal PSA Crypto provider for Zephyr: the 42 calls OpenThread, the
Zephyr Bluetooth host and tinytalk make, over a vetted primitive backend.
No crypto of its own beyond standard constructions.

SHA-256 · HMAC · AES-CMAC · AES-ECB · AES-CCM · AES-GCM · ECDSA P-256 ·
ECDH P-256 · HKDF · PBKDF2 · SPAKE2+ · HMAC_DRBG

Anything else returns `PSA_ERROR_NOT_SUPPORTED`.

17.8 KB flash, 1.5 KB RAM, LTO release build, portable backend.

## Use

```cmake
list(APPEND ZEPHYR_EXTRA_MODULES <tinypsa>)
```

Then the fragment `zephyr/tinypsa.conf`, plus `zephyr/tinypsa-openthread.conf`
in an image with OpenThread. Tunables: `menuconfig TINYPSA`.

**Backends** `portable`, vendored and permissive, the default on Cortex-M4
and M33. `ocrypto`, Nordic's Oberon from NCS, never vendored.

**Persistent keys** are settings entries `tinypsa/<id>`, in the clear. NCS
trusted storage only obfuscated them. Keys it wrote are not read.

## Test

```sh
tests/vectors/fetch.sh build/vectors
cmake -S tests/host -B build/host -G Ninja -DTINYPSA_MBEDTLS_DIR=<mbedtls-3.6>
cmake --build build/host
build/host/tinypsa_host_test   # known answers, NIST CAVP, Wycheproof
```

Also: `tinypsa_diff` against Mbed TLS PSA, Arm's psa-arch-tests
(`tests/host/arch/run.sh`), on target (`tests/target`).

Apache-2.0. Vendored cores: `NOTICE`.

Unofficial. Not affiliated with, endorsed or certified by any company or
standards body named here. Trademarks belong to their owners.
