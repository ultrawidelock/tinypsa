# tinypsa

A minimal PSA Crypto API provider for Zephyr. It implements the 42 PSA calls,
and the two Mbed TLS ASN.1 readers, that OpenThread, the Zephyr Bluetooth host
and UltraWideLock make, over a vetted primitive backend. It adds no crypto
algorithm of its own beyond standard constructions over those primitives:
CMAC (SP 800-38B), HKDF (RFC 5869), PBKDF2 with the RFC 4615 PRF,
HMAC_DRBG (SP 800-90A), and SPAKE2+'s group operations (RFC 9383).

License: ISC.

## What it provides

| Family | Algorithms |
|---|---|
| Keys | import, generate, export, export public, destroy, attributes; volatile and persistent |
| Hash | SHA-256 |
| MAC | HMAC-SHA-256, AES-CMAC, truncated |
| Cipher | AES-ECB, one-shot encrypt |
| AEAD | AES-CCM, AES-GCM, one-shot and multipart |
| Signature | ECDSA P-256 with SHA-256, randomized and deterministic (RFC 6979) |
| Key agreement | raw ECDH P-256 |
| Key derivation | HKDF-SHA-256, PBKDF2-AES-CMAC-PRF-128 |
| PAKE | SPAKE2+ P-256 group operations, outside the PSA API: `tinypsa_spake2p_p256_*` in `<tinypsa/spake2p_p256.h>`, with ocrypto's contract |
| Random | HMAC_DRBG seeded from the `zephyr,entropy` device |

Anything else returns `PSA_ERROR_NOT_SUPPORTED`.

## Use in a Zephyr application

Add the checkout as a module and select the custom provider:

```cmake
list(APPEND ZEPHYR_EXTRA_MODULES <path to tinypsa>)
```

```
CONFIG_PSA_CRYPTO=y
CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM=y
# On NCS, nrf_security must be off; OpenThread then needs its Custom choice.
CONFIG_NRF_SECURITY=n
CONFIG_CUSTOM_OPENTHREAD_SECURITY=y
CONFIG_OPENTHREAD_CRYPTO_PSA=y
CONFIG_OPENTHREAD_MBEDTLS_LIB_NAME="tinypsa"
```

`zephyr/tinypsa.conf` is these lines with a reason each, the key slots and
the `PSA_WANT_*` a Bluetooth host, OpenThread and tinytalk image calls, for
a sample to copy as its crypto fragment.

Kconfig options (`menuconfig TINYPSA`):

| Option | Default | Meaning |
|---|---|---|
| `TINYPSA_KEY_SLOTS` | 16 | keys held in RAM at once |
| `TINYPSA_KEY_MAX_SIZE` | 65 | largest key in bytes; 65 fits a P-256 public key |
| `TINYPSA_KDF_INPUT_MAX` | 64 | salt plus info buffered by a derivation |
| `TINYPSA_DRBG_RESEED_INTERVAL` | 4096 | DRBG requests between reseeds |
| `TINYPSA_PERSISTENT_KEYS` | y with `SETTINGS` | persistent keys as settings entries |

Persistent keys are stored as settings entries named `tinypsa/<id in hex>`,
in the clear. NCS trusted storage sealed them with a key hashed from the
device UID, which anyone holding the flash can recompute, so this drops
obfuscation, not secrecy. Keys written by NCS trusted storage are not read.

## Backends

- `ocrypto`: Nordic's nrf_oberon, linked from the NCS install. Never vendored:
  its license limits use to Nordic chips, and it ships only as Cortex-M
  archives.
- `portable`: vendored, permissively licensed cores, nothing from the SDK;
  see `src/backend/portable/README.md`.

The default is `portable` on a Cortex-M4 or M33, whose assembly its P-256
needs, and `ocrypto` on any other Nordic core. Select
`CONFIG_TINYPSA_BACKEND_OCRYPTO=y` to keep Oberon on an M4 or M33.

## Tests

Host tests run the core over a test-only backend built on Mbed TLS's legacy
primitives, because ocrypto has no host build.

```sh
tests/vectors/fetch.sh build/vectors          # pinned CAVP and Wycheproof files
cmake -S tests/host -B build/host -G Ninja \
  -DCMAKE_C_COMPILER=/usr/bin/cc -DTINYPSA_MBEDTLS_DIR=<Mbed TLS 3.6 tree>
cmake --build build/host
build/host/tinypsa_host_test                  # smoke tests plus all vectors
(mkdir -p build/diffrun && cd build/diffrun && ../host/tinypsa_diff 1 50000)
tests/host/arch/run.sh <psa-arch-tests v24.03 checkout> build/host <Mbed TLS tree>
```

Each runs twice: over the test backend, and as `*_portable` with the
portable backend's C families swapped in for the test backend's.

- `tinypsa_host_test`: known answers per algorithm, then NIST CAVP (SHA-256,
  HMAC, CMAC, AES-ECB, CCM, GCM, ECDSA SigVer and SigGen, ECDH, HMAC_DRBG)
  and Wycheproof (GCM, CCM, CMAC, HMAC, HKDF, ECDSA P1363, ECDH).
- `tinypsa_diff`: differential test against Mbed TLS 3.6 PSA, comparing every
  status and every deterministic output over random call sequences. The few
  places tinypsa differs on purpose are counted as "by design" with their
  reason in `diff.c`.
- `arch/run.sh`: Arm's psa-arch-tests crypto suite. Calls tinypsa does not
  provide link to stubs returning `PSA_ERROR_NOT_SUPPORTED`.

The ocrypto backend runs only on a Nordic chip. `tests/target` builds the
smoke tests and an evenly spaced sample of the vector tables (about 300 KB of
hex, `TINYPSA_VECTOR_BUDGET`) into a Zephyr app, then checks that a persistent
key survives a reset. Results go to RTT; reset the board once more to see the
key check.

```sh
west build -b <board> -d build/target tests/target
west flash -d build/target --erase
```

`tests/bench` times candidate P-256, AES-GCM and SHA-256 cores against
Oberon on a Nordic board, checking every output against Oberon's, and its
link map gives each core's size. `tests/bench/fetch.sh` fetches the
candidates at pinned commits.
