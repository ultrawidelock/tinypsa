# Plan

Replacing nrf_security/Oberon in UltraWideLock (UWL) with tinypsa's own
portable backend. One commit per step.

## Done

| Step | What | Commit |
|---|---|---|
| 1 | Benchmark | f420cd1 |
| 2 | SHA-256, HMAC (BearSSL) | 6f08837 |
| 3 | AES, CCM, GCM (BearSSL `aes_ct`) | 76018d7 |
| 4 | P-256 (P256-Cortex-M4), RFC 6979 | 2aa579a |
| 5 | SPAKE2+ group operations | d9b292c |
| 6a | Primitives past the PSA layer (`prim.h`), OpenThread crypto platform | 4af64e0 |
| 6b | Stack: HMAC over SHA-256, one DRBG HMAC context, `has_d_cache` | 11a0794 |
| 6c | Fast fixed-base multiply behind `CONFIG_TINYPSA_P256_FAST_BASEMULT`, now on | ba4e291 |

On the UWL lock image (DWM3001CDK, release), against nrf_security: 18.6 KB
less code, 1.2 KB less RAM. Only the Bluetooth host still calls PSA.

## Board pass: tinylock door-lock (2026-10-17)

The first full pass with tinypsa as the only PSA provider, run by the
tinylock session on a DWM3001CDK (decawave_dwm3001cdk), LTO on, logs INF:
tinylock 623785e, tinytalk f28240f, tinypsa b61bb7c, fragments
`prj.conf;stacks/bt-host.conf;stacks/openthread.conf;stacks/tinypsa.conf;stacks/tinypsa-openthread.conf`
(the last two are `zephyr/tinypsa.conf` and `zephyr/tinypsa-openthread.conf`),
296,468 B flash, 95,968 B RAM. Portable backend, fast basemult on,
OpenThread over PSA.

Passed in Apple Home: commissioning over BLE, PASE (0.38 s to the first
reply, host-stamped RTT, about +/- 50 ms), CASE on two fabrics (413 ms and
264 ms) and from the hub (339 ms), Thread attach (1,098 ms) with
OpenThread's SRP key as a persistent PSA key, lock and unlock from the phone
and through the hub, factory reset with the settings wipe, and re-adding.

Stack peaks from the paint, sampled every 60 s: system work queue 3,236 B
of 6,144 B (nrf_security: 3,872 B); OpenThread thread 3,944 B of 4,096 B,
reached in the minute of the first CASE over Thread.

## Next

1. **Board pass** on the UWL lock image, with fast basemult and hardware
   AES on. Passed 2026-10-16: boot, Matter commissioning over BLE, Thread
   join, lock and unlock from Apple Home, a UWB walk-up unlock. Left: LE
   Secure Connections pairing, DFU over GATT and over CoC. Devices are
   recommissioned on upgrade; no key migration.
2. **Backend decision (portable vs ocrypto)** by the CASE bench on the
   reader image: `make reader CDK_READER_BUILD=<dir>
   "CDK_READER_ARGS=-DEXTRA_CONF_FILE=<bench.conf> $(CDK_SIGN)"`, with
   bench.conf setting `ULTRAWIDELOCK_CASE_BENCH`, `INIT_STACKS`,
   `THREAD_STACK_INFO`, `PSA_WANT_ALG_CCM` and `TINYPSA_KEY_SLOTS=16` (the
   bench holds 9 PSA keys at once); one result line on RTT per
   boot. Three images: portable with fast basemult off (shipping), portable
   with it on, ocrypto (`NRF_OBERON`, `TINYPSA_BACKEND_OCRYPTO`).
   **Decided: portable.** 2026-10-16, 4 boots each:

   | Image | CASE crypto | Stack peak |
   |---|---|---|
   | nrf_security (earlier) | 258.17 ms | 1,304 B |
   | tinypsa+ocrypto | 256.72 ms | 1,216 B |
   | portable, fast basemult off | 117.04 ms | 2,552 B |
   | portable, fast basemult on (ships since 68a1be0) | 97.44 ms | 2,544 B |
3. **Hardware AES-128: very important.** See below.
4. ARM QEMU suite after every portable-backend change
   (`tests/host/arm/run.sh <mbedtls>`, about 2 h).
5. Push tinypsa once the ARM suite passes; open the UWL PR after the board
   pass.

## Fast fixed-base P-256 multiply (on)

`CONFIG_TINYPSA_P256_FAST_BASEMULT=y`, the default, makes keygen and
signing use P256-Cortex-M4's precomputed-table routine for 1,392 B more
flash: 290,232 B against 288,840 B on tinylock's door-lock, RAM unchanged at
95,712 B (decawave_dwm3001cdk, LTO on, BT host, OpenThread over PSA,
`zephyr/tinypsa.conf`, measured 2026-10-16). The UWL lock image gave the same
1,392 B earlier. On the CASE bench it cuts 117.04 ms to 97.44 ms
(19.6 ms, 17%). It also takes signing's stack from 1,852 B to 996 B: off, the
generic routine's 1,088 B frame overflowed the OpenThread thread (4,096 B)
when the SRP client signed after the Thread join, and commissioning failed.
With `has_d_cache` the table is scanned in flash, not copied.

## Hardware AES-128 (very important)

**Status.** Built behind `CONFIG_TINYPSA_AES_MPSL`, off by default: 40 B
more code on the UWL lock image, which links and calls
`mpsl_ecb_block_encrypt_extended` from `tp_be_aes_encrypt`. On the board
it commissioned, joined Thread and unlocked over Thread and UWB, so its
blocks are right; the risks and the stress run below are still open.

Measured on the board (CASE bench's AES loop, 1,000 operations, 2 boots each):

| Operation | Software (`aes_ct`) | Hardware (ECB) | Speedup |
|---|---|---|---|
| AES-128 block, key set once | 122.8 us | 11.4 us | 10.7x |
| AES-128 block, new key each | 276.6 us | 12.1 us | 22.8x |
| CMAC, 64 B | 892 us | 166 us | 5.4x |

CASE is unchanged (about 97 ms): Matter's CCM still runs on BearSSL. Moving
CCM onto the same ECB blocks is the next step.

**Why.** BearSSL's constant-time `aes_ct` is the slowest primitive here and
the deepest stack user after P-256: it expands the key schedule into 480 B
on every call (`br_aes_ct_cbcenc_run`, 576 B frame). Every AES-128 user in
UWL is one block at a time with a 128-bit key: Bluetooth CMAC (SMP, GATT
database hash), OpenThread's MAC and MLE CCM, Matter's CCM, and UWL's ECB.
The nRF52833 has an AES-128 ECB peripheral, already shared by the
Bluetooth controller and linked in the image.

**API.** `mpsl_ecb_block_encrypt_extended(key, cleartext, ciphertext,
MPSL_ECB_NO_FLAGS)` (nrfxlib/mpsl/include/mpsl_ecb.h:52). It blocks until
done, at most 7.2 us per block (nRF52833 PS 6.6.5.1). Nordic's own Bluetooth
glue uses it. Zephyr's `crypto_nrf_ecb` driver is excluded when a Bluetooth
controller is present (`depends on !HAS_BT_CTLR`), and the older
`mpsl_ecb_block_encrypt` is deprecated.

**Design.**
1. Zephyr port with `CONFIG_MPSL`: `tp_be_aes_init` with a 16 B key stores
   the raw key and a tag in the context instead of BearSSL's schedule.
2. `tp_be_aes_encrypt` with the tag calls the MPSL function once per block.
3. Everything else stays on BearSSL: 256-bit keys, CCM and GCM contexts, host
   builds.

All single-block callers already go through these two functions
(`src/core/hash_mac.c`, `src/core/kdf.c`, `src/port/zephyr/openthread_crypto.c`,
UWL's `ultrawidelock_prim_tinypsa.c`), so nothing above the backend
changes.

**Risks to settle first.**
1. Concurrency with the controller and the 802.15.4 driver is not
   documented. The disassembly suggests the call retries internally when the
   AES core is taken (ECB has the lowest priority against CCM and AAR).
   Confirm with Nordic or by a stress run on the board.
2. MPSL copies the key into a stack struct it does not wipe.
3. Constant-time behaviour of the hardware is not documented.
4. It must not run before `mpsl_init`.
5. ISR or high-priority callers are untested.

**Check.** The CASE bench and a walk-up unlock with Bluetooth and Thread both
active, before and after; plus the full host suite, which keeps covering the
software path.
