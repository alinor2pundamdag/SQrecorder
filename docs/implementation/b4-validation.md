# B4 validation record

## Implemented

- Approved B1 foundation retained: SQVE v1 chunked AES-256-GCM, RSA-OAEP SHA-256 wrap contract, and KMP Vault/session/journal contracts.
- Rust Vault writer/chunk AEAD, DEK zeroization, SQJ hash-chain/recovery, terminal writer after sink failure.
- JCS canonical payload enforcement (RFC 8785), nested/escaped duplicate-key detection, canonical recovery verification.
- Verified-only journal resume restores sequence/digest/timestamp; damaged tails require recovery.
- Durable-store staged promotion/sync/verify/rename/parent-sync/journal callback, explicit pending/unknown outcomes, non-destructive stage discovery, fault injection.
- Rust opaque Vault-key C ABI + JNI entry points: create/import/copy-for-public-wrap/destroy, chunk encrypt/decrypt, authentication-failure status, guarded FFI and zeroized transient native buffers.
- Android KMP adapter source, auth-epoch validation, explicit key rotation/invalidation handling, P-256 journal-anchor signing, domain-separated signed preimage, host crypto tests.
- Android native build script now cross-compiles arm64-v8a + x86_64 and verifies 16 KB LOAD alignment before packaging.

## Latest hardening delta

- Android Vault unwrap, chunk decrypt, and journal-anchor signing now share the same monotonic auth-context verifier: expiry, revocation/epoch, and the maximum 30-second authorization window are enforced on all three sensitive paths.
- Rust FFI transient DEK copies now use RAII zeroization, including early-return/error paths during import and public-wrap copy. Exact-head CI caught and fixed the RAII slice-coercion compile issue and scoped the `Zeroize` trait import to tests; both fixes are included in the passing Rust source SHA above.
- Added host tests for exact-window acceptance, overlong authorization rejection, revoked epochs, and expired contexts. Commit: `91b89fa7ab3bb5ab40dc7d146f47ae4ff3db7017` (implementation), `b017a778f0653dc7934a6d797d5cf91b9810045f` (tests), `93221e987ad2e0bd540e09287645efb3503120be` (anchor-signing integration), `2b5dcfe7f4eda492b58d0bd47c8f75448610b361` (FFI transient-key zeroization).

## Verification

- Historical baseline: Rust **Run #26 PASS** for workspace tests/Clippy and native ABI tests at source SHA `b6ca43124ec1ed9cf2a49e1090dc051a73ad9e06`; this is not evidence for current branch HEAD.
- Historical Android Gradle **Run #13 PASS** covered KMP/host crypto tests before later JNI/anchor/auth changes.
- Android Run #18 recorded transient Maven HTTP 429/502; bounded retry/cache mitigation remains in workflow.
- CI workflow hardening committed: Rust validation now targets `main` for PR #2, checks the event revision via pinned checkout, validates the committed lockfile (`cargo metadata --locked`), uses `cargo fmt --check`, and has read-only permissions (no bot formatting/lockfile pushes).
- Exact-head code verification: Rust workflow Run #32 completed **PASS** at source SHA `1a1bc57968d63886ab2b1935773edb254aca6e1c`: committed lockfile, rustfmt, all workspace tests, and Clippy (`-D warnings`) passed. Run URL: https://github.com/alinor2pundamdag/SQrecorder/actions/runs/45965522422. The subsequent PR head may be newer if this record is committed; a docs-only delta does not change the tested Rust source. Android workflow Run #29 failed at host-test step: the auth-window test incorrectly expected a context to be expired one nanosecond after the validation start even though its absolute expiry was 30 seconds later. The implementation correctly treats expiry as an absolute monotonic deadline; the test assertion was wrong. Corrected test commit `e225e1194bcf1de345e3f62ac708bf78bde4a0a1` now has Android workflow Run #30 queued: https://github.com/alinor2pundamdag/SQrecorder/actions/runs/45967005480. Await this exact-head rerun; no Android/device pass is claimed yet. Exact workflow job steps and run conclusions were checked through the GitHub Actions API. Historical run results remain separate from this exact-head evidence.

## Locked-contract compatibility blocker

SQVE v1 specifies a **non-empty OAEP label** `SQREC-VAULT-DEK-v1` and MGF1-SHA256. Android Keystore exposes configurable MGF1 digest from API 35, but its RSA-OAEP private-key provider rejects non-empty `PSource.PSpecified` labels. The adapter fails closed with `UNSUPPORTED_PLATFORM` for key generation/wrap/unwrap/rotation; it does not alter the locked envelope or create keys that cannot decrypt. AOSP AndroidKeyStore RSA cipher implementation confirms that its OAEP `PSource.PSpecified` is restricted to an empty value; API 35 MGF1 digest configurability does not remove this label restriction (source: https://android.googlesource.com/platform/frameworks/base/+/master/keystore/java/android/security/keystore/AndroidKeyStoreRSACipherSpi.java).

This platform/format incompatibility requires explicit change control before production Android Vault acceptance.

## Remaining B4 acceptance

- Resolve OAEP-label compatibility through an approved versioned wrap-suite change or a verified compatible Keystore design.
- Verify anchor signatures cross-platform in Rust and maintain a durable signing-key registry.
- Connect and test the native library package on Android devices; verify API/auth, key invalidation/rotation, and lifecycle.
- Wire Android journal and durable file promotion to Rust recovery; complete crash-cut/ENOSPC tests and security review.
- Device evidence: locked encrypt-only capture, authenticated unwrap/playback/export, 16 KB page compliance across supported ABIs.

B4 remains **BLOCKED / NOT 100% accepted** until all gates pass.


### CI follow-up — emulator runner failure and correction (2026-11-27)

- Android Run #30 completed **FAIL** at `e225e1194bcf1de345e3f62ac708bf78bde4a0a1`: Gradle/AAR compilation, native arm64-v8a/x86_64 build, 16 KB ELF alignment, and Android host contract tests all passed. API 36 emulator did not boot.
- Root cause verified in job log: emulator runner invoked `-accel off`; emulator 37.3.10 exited with `Software CPU emulation (-accel off) is not supported. A hardware CPU accelerator is required (or set ANDROID_I_WANT_MY_TCG=yes to force TCG software emulation).` Subsequent ADB polling ended in `Timeout waiting for emulator to boot.` This is CI runner/emulator startup failure, not a Vault test assertion or product code failure.
- Corrective workflow commit `4b208a6c666969d22e8ef6aa70fc41cedd53127d` sets the documented `ANDROID_I_WANT_MY_TCG=yes` fallback for the emulator step. Android Run #31 was triggered and was **QUEUED** at the time of this record: https://github.com/alinor2pundamdag/SQrecorder/actions/runs/45969516297. It must complete before claiming emulator acceptance.
- Rust Run #32 remains **PASS** at tested Rust source SHA `1a1bc57968d63886ab2b1935773edb254aca6e1c`. Latest workflow-only head is `4b208a6c666969d22e8ef6aa70fc41cedd53127d`; do not claim exact-current-head green until Run #31 and any triggered checks conclude.


## Latest PR #3 host-test repair — 2026-11-27

- Investigated failed Android Run #32 (PR #3; native ABI build and 16 KB ELF alignment succeeded). Job log localized both failures to Android host tests: valid anchor verification and key-fingerprint mismatch assertions.
- Root cause: Android host-test mocks do not implement `android.util.Base64`; verifier decoding threw a mocked-platform `RuntimeException`, and the test fixture encoder also called the mocked Android API. This is a host-test portability defect.
- Corrective PR #3 commits: verifier `836afe79b1e71838ae7771737015f879df5ca56c`; test fixture `5a11193d2dc17d56af2edd4c35bb11bab20eb232`.
- Fix: strict standard Base64 decoder compatible with minSdk 23; JVM Base64 in host-test fixture. Checks alphabet, padding placement, output size and canonical unused padding bits. No signature preimage, fingerprint, suite, SQVE or envelope changed.
- **Verification:** commits exist; follow-up CI result pending. Do not mark PR #3 tests or B4 accepted until the new run passes.

## B4 acceptance checklist (live status)

| Gate | Status | Evidence / remaining action |
|---|---|---|
| Rust format, locked metadata, workspace tests, Clippy | PASS on recorded SHA only | Re-run on final integrated B4 SHA |
| Android native ABI build + 16 KB ELF LOAD alignment | PASS on prior CI source | Re-run after integration; physical page-size evidence required |
| Android host anchor verifier tests | FIX COMMITTED; CI PENDING | PR #3 new run must pass |
| API 36 emulator Vault bridge | Run #34 PASS on prior main B4 SHA | Re-run against integrated candidate head |
| Durable historical anchor-key registry + rotation retention | NOT IMPLEMENTED / BLOCKING | Persist append-only key records; rotation/recovery tests |
| Rust cross-platform anchor verifier + golden vectors | BLOCKING | Cross-check identical preimage/signature semantics |
| Android journal + durable-store recovery wiring | BLOCKING | Integrate and test safe recovery/no silent loss |
| Crash-cut + ENOSPC + fault matrix | BLOCKING | Complete fault injection and recovery assertions |
| SQVE OAEP-label compatibility | BLOCKING / DECISION REQUIRED | Recommend separately versioned SQVE v2 (option B); preserve v1 pending explicit approval |
| Physical-device auth, Keystore invalidation/rotation, locked encrypt-only, authenticated unwrap/play/export | NOT RUN — DEVICE REQUIRED | User device run and evidence artifacts |
| Physical-device 16 KB page support across supported ABI/device matrix | NOT RUN — DEVICE REQUIRED | Record actual device evidence |
| PR #2 / PR #3 merge | HOLD | Both stay open/draft until every required CI and physical gate is green |

**B4 verdict: IN PROGRESS — NOT 100%.** No acceptance gate is waived. Historical CI passes are not final-head or physical-device evidence.
