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
- **Verification:** Android Run #36 PASS at repair commit `5a11193d2dc17d56af2edd4c35bb11bab20eb232`. Host contract tests, native arm64-v8a/x86_64 build, ELF 16 KB LOAD alignment, API 36 emulator Vault bridge all completed successfully. Run: https://github.com/alinor2pundamdag/SQrecorder/actions/runs/45978069195. This is CI evidence for PR #3 repair—not physical-device acceptance or final integrated B4 acceptance.

## B4 acceptance checklist (live status)

| Gate | Status | Evidence / remaining action |
|---|---|---|
| Rust format, locked metadata, workspace tests, Clippy | PASS on recorded SHA only | Re-run on final integrated B4 SHA |
| Android native ABI build + 16 KB ELF LOAD alignment | PASS on prior CI source | Re-run after integration; physical page-size evidence required |
| Android host anchor verifier tests | PASS Run #36 | PR #3 repair SHA `5a11193d2dc17d56af2edd4c35bb11bab20eb232`; API 36 emulator also passed |
| API 36 emulator Vault bridge | PASS Run #36 on PR #3 repair SHA | Re-run against final integrated B4 candidate SHA |
| Durable historical anchor-key registry + rotation retention | NOT IMPLEMENTED / BLOCKING | Persist append-only key records; rotation/recovery tests |
| Rust cross-platform anchor verifier + golden vectors | BLOCKING | Cross-check identical preimage/signature semantics |
| Android journal + durable-store recovery wiring | BLOCKING | Integrate and test safe recovery/no silent loss |
| Crash-cut + ENOSPC + fault matrix | BLOCKING | Complete fault injection and recovery assertions |
| SQVE OAEP-label compatibility | BLOCKING / DECISION REQUIRED | Recommend separately versioned SQVE v2 (option B); preserve v1 pending explicit approval |
| Physical-device auth, Keystore invalidation/rotation, locked encrypt-only, authenticated unwrap/play/export | NOT RUN — DEVICE REQUIRED | User device run and evidence artifacts |
| Physical-device 16 KB page support across supported ABI/device matrix | NOT RUN — DEVICE REQUIRED | Record actual device evidence |
| PR #2 / PR #3 merge | HOLD | Both stay open/draft until every required CI and physical gate is green |

**B4 verdict: IN PROGRESS — NOT 100%.** No acceptance gate is waived. Historical CI passes are not final-head or physical-device evidence.


## Owner-approved cross-platform architecture and latest CI evidence — 2026-11-27

- Owner approved option B: a separately versioned SQVE v2 and broad platform compatibility as an architectural target. The decision is recorded in `docs/decisions/0002-cross-platform-sqve-v2.md`; design and implementation gates are in `docs/security/sqve-v2-envelope-design.md`.
- Added `docs/architecture/platform-compatibility.md` covering Android, Wear OS, iOS/iPadOS, watchOS, Windows, macOS, Linux, and JVM/Java API integration. It distinguishes planned/build/CI/device/production status and explicitly avoids claiming every OS provides identical background capture or hardware-backed key protection.
- Android Run #36: **PASS**. Job `android-vault` passed all 21 listed steps, including native arm64-v8a/x86_64 build, ELF 16 KB LOAD alignment, Android host contract tests, KVM setup, and API 36 emulator Vault bridge. Source repair commit: `5a11193d2dc17d56af2edd4c35bb11bab20eb232`. URL: https://github.com/alinor2pundamdag/SQrecorder/actions/runs/45978069195.
- This is not final B4 acceptance: physical Android tests, cross-platform provider builds, SQVE v2 vectors/security review, durable key registry, recovery/fault matrix, and exact-final-integrated-SHA CI remain open.
- PR #2 and PR #3 must remain draft/open/unmerged. B4 is **IN PROGRESS / NOT 100%** until all required CI and physical-device gates pass.


## Cross-platform target declaration and CI handoff — 2026-11-27

- Shared KMP domain target declarations added: JVM, Android, Linux x64, Windows MinGW x64, iOS arm64/simulator, macOS arm64, watchOS device/simulator. Commit: `5d080afd6f5de41f714967090a34e9e5ad9cb041`.
- Added cross-platform CI workflow `.github/workflows/platform-compatibility.yml` (Rust workspace test matrix on Linux/Windows/macOS; KMP domain target compile/test matrix on Linux/Windows/macOS; manual `workflow_dispatch`). Workflow commit: `ef1231680b2ae49dde31bafebc63335ae6f7e926`.
- Current PR #2 head verified by GitHub: `23c6f467041b51d8321e57cbe249a5ae7bd401df`. GitHub connector did not return a workflow run or combined check status for this exact head at verification time. Therefore the newly declared cross-platform target matrix is **CI NOT YET VERIFIED**, not green.
- Existing Android Run #36 remains a PASS for the PR #3 verifier repair SHA only. It is not evidence for the new KMP target declarations or exact PR #2 head.
- The platform matrix is now a declared build contract; no iOS/watchOS/Windows/macOS/Linux app or physical-device support is claimed until its target-specific checks and device gates pass.


## Cross-platform implementation delta — 2026-11-27

- **Root cause found:** `shared/capability-system` contained common Kotlin capability-selection code and tests, but it had no Gradle module build file and was not included in `settings.gradle.kts`. Thus its selector/test suite was outside the configured build graph. Fixed by adding `shared/capability-system/build.gradle.kts` with KMP JVM/Android/Linux/Windows/iOS/macOS/watchOS targets and including `:shared:capability-system` in settings. Commits: module `67089dc9c901fc6d42b2eb0bc182511a9b14046b`; settings `6bfe0d67c6e60048ef67c5209d3e0b5b405b2e27`.
- **SQVE v2 common contract added:** `shared/domain/src/commonMain/.../VaultV2Contracts.kt` and common tests. Structural validation covers explicit version/suite, file salt, nonce prefix, 1 MiB chunk geometry, 32-byte header-MAC encoding, recipient uniqueness/bounds, RSA/ECDH metadata requirements, and canonical Base64 pad bits. This is a shared metadata contract only; Rust/provider cryptographic wrapping, header-MAC verification, serialized v2 parser/writer, golden vectors and migration are still NOT implemented/verified. Commits: contract `7dbe744be5f509b22c38880ed67859193591fc4e`; tests `f9a3039069a3be23d72169109ab1911adf62ac92`.
- **Cross-platform KMP target declarations + CI workflow:** shared domain and capability selector declare JVM/Android/Linux x64/Windows MinGW x64/iOS/watchOS/macOS targets. New matrix runs Rust workspace tests on Linux/Windows/macOS and KMP compilation/tests on supported host OS runners. Workflow is in `.github/workflows/platform-compatibility.yml`; Android contract workflow now includes capability-system host tests.
- **CI limitation at this checkpoint:** GitHub connector returned no workflow run or combined status for the current PR #2 head at the latest query. Therefore the new module, KMP native targets, SQVE v2 common contract, and cross-OS matrix remain **NOT VERIFIED by CI**. Do not treat target declarations or committed tests as passing.
- PR #3 Android Run #36 remains verified PASS on its repair commit only; it is not evidence for the newer PR #2 source.


## Final implementation checkpoint — 2026-11-27

- PR #2 source head before this evidence commit: `c1f1f5cc8a713e51060c53b2b5806358ccf3c08c`.
- Added SQVE v2 KMP metadata contracts and negative/positive common tests; strict canonical Base64 pad-bit validation and bounded recipient/ephemeral-key metadata are included.
- Added the formerly uncompiled capability selector to the Gradle build graph and platform CI job matrix. Added JVM/Linux/Windows/Apple/watchOS KMP target declarations and cross-platform Rust/KMP workflow.
- **Execution status:** The GitHub Actions connector returned an empty workflow-run list and no combined commit statuses for the exact PR #2 head above. CI was not observed to start for this latest branch update; do not mark those new checks as passed. No local Rust/Kotlin toolchain is available in the current execution container, and outbound GitHub cloning is blocked, so local build execution was unavailable.
- Android Run #36 PASS remains verified on PR #3 commit `5a11193d2dc17d56af2edd4c35bb11bab20eb232`, not this newer PR #2 head.
- Physical Android/iOS/watchOS/Windows device acceptance was not performed in this session. B4 remains **NOT 100% accepted**.


## Verification and integration checkpoint — 2026-11-27 10:45 UTC

### Exact source
- B4 PR #2 head before this evidence update: `fc4950b3ce80125ec6a9183df37454d36212ee8b` (branch `b4-hardening-approved-foundation`).
- PR #2: draft/open/unmerged. PR #3: draft/open/unmerged. Merge is intentionally prohibited pending all gates.

### Fixes completed in this continuation
- Corrected both CI pull-request path filters so changes under `shared/capability-system/**` trigger Android and cross-platform contract workflows; Android workflow checkout now uses `persist-credentials: false`.
- Enabled Android-KMP host test compilations in both `:shared:domain` and `:shared:capability-system`. Official Android-KMP docs state host/device tests are disabled by default unless explicitly enabled; previously the domain build emitted that warning. This fixes test-source activation, not yet a CI pass.
- Integrated PR #3's anchor verifier and tests into the B4 branch without merging either PR. The Android Run #36 PASS was executed on PR #3's merge ref `7053602107e085990209d33d577d9c60516d2d22` (PR3 head `5a11193d2dc17d56af2edd4c35bb11bab20eb232` + old base `2c42593cb040d5a36a92a718997258ebcbf7d799`); it did **not** validate the latest B4 branch head.
- Added Android Keystore retained-alias resolver: enumerates numbered historical signer aliases and matches key IDs by public-key SHA-256 fingerprint; missing/malformed records fail closed, and returned key bytes are defensive copies. Added host tests. This is an Android Keystore retained-key lookup implementation, not yet an OS-independent append-only public-key registry or signed registry export/restore mechanism.

### Verified CI / not verified
- Android Run #36: PASS for the PR #3 merge-ref source above; host verifier, native ARM64/x86_64 build, 16 KB ELF LOAD alignment, and API 36 emulator Vault bridge all succeeded.
- Android Run #32: FAIL before verifier repair; host tests failed on mocked `android.util.Base64` portability at the verifier tests. Run #36 passed the repaired merge ref.
- Latest B4 branch commits after Run #36 include new target/test wiring and retained-key resolver. The GitHub connector returns only PR-triggered workflow runs for a commit and reports no run/status for the current branch head. These newest changes are **NOT CI VERIFIED**; do not transfer Run #36 PASS to them.

### Remaining acceptance blockers — no gate waived
1. Exact latest B4 head: Rust fmt/metadata/workspace/Clippy, Android native/ELF/AAR + host tests, API 36 emulator bridge, and new cross-platform matrix must all execute and pass.
2. Anchor key registry: Android retained Keystore alias resolver added; cross-platform durable append-only registry semantics, export/restore/history integrity, and rotation/invalidation/recovery integration remain.
3. Cross-platform Rust anchor verifier and Android↔Rust golden vectors remain.
4. Journal anchor creation/verification integrated with durable journal recovery and signed checkpoint policy remains.
5. Crash-cut + ENOSPC/storage fault matrix and recovery evidence remain.
6. SQVE v2: common metadata contract exists; canonical binary parser/writer, provider crypto implementations, authenticated header, ECDH/RSA suite test vectors, v1→v2 migration/recovery, fuzz/tamper vectors, and independent security review remain. SQVE v1 is unchanged.
7. Declared KMP targets are not installable product builds yet: Android/Wear app shell, iOS/iPadOS/watchOS shell, Windows/macOS/Linux/JVM packaging/adapters, permissions/background capture, auth/key providers, audio I/O, and target-specific tests need implementation. Target declarations alone do not mean universal device compatibility.
8. Physical acceptance required: hardware-backed Android Keystore/auth/invalidation/rotation, locked encrypt-only, authenticated unwrap/playback/export, real crash/reboot/storage exhaustion, and physical 16 KB page evidence. Add iOS/watchOS/Windows device/provider tests as those platforms reach their supported implementation tier.
9. Final checklist and evidence must be regenerated against one exact integrated commit after all required gates pass.

**B4 acceptance remains IN PROGRESS / NOT 100%.**


## Portable anchor registry/verifier implementation — 2026-11-27

- Added `core/session-journal/src/anchor_registry.rs`: append-only SQAK v1 public-key records with sequence, prior-digest chain, key-ID SHA-256 fingerprint binding, record digest, strict scan/recovery status, duplicate-key rejection, bounded registry/record/key sizes, durable sink append+sync interface, and verified-only resume. Unit tests cover append/verify/resume/history, duplicate key, tamper, and truncated tail.
- Added `core/session-journal/src/anchor_verifier.rs`: Rust portable anchor metadata validation, retained-key resolution, and exact Android-compatible binary signing preimage. ECDSA execution is intentionally provider-injected; **the RustCrypto/platform provider implementation and real cross-platform signature golden vector are not complete**. Fake-provider tests validate control flow/preimage, not the ECDSA primitive.
- Added Android retained-key resolver/test earlier: scans retained numbered Android Keystore signer aliases, checks fingerprinted key ID, returns defensive copy, fails closed. The Android alias lookup is implemented; registry export/restore and multi-platform durable store integration remain.
- Latest PR #2 B4 head before this evidence commit: `74fbb78b7556e3c3368417bc663ba9206b3aee9e`.
- **Local verification limitation:** no Rust toolchain is installed in the execution container (`rustc: command not found`). GitHub Actions connector returned no PR-triggered workflow run or combined status for the current head. New Rust registry/verifier and Kotlin host tests are **not yet CI-verified**; source commits/tests are not proof of passing.
- Android Run #36 is still a PASS only for PR #3 merge ref `7053602107e085990209d33d577d9c60516d2d22`; it is not latest B4 branch evidence.


## Consolidated B4 verification evidence — 2026-11-27

### Source/evidence SHA
- Implementation source head before this evidence commit: `31bab8539af221f576a56cd2cfb2f69bb73b790d`.
- This evidence update is committed separately; CI is configured to trigger for `docs/implementation/**` so the final evidence revision receives its own checks.
- PR #2 is draft/open/unmerged. PR #3 is draft/open/unmerged and tracking-only; verifier source is integrated once in PR #2's B4 branch.

### Implemented and CI-tested foundations
- Rust append-only SQAK public-key registry: hash-chained sequence, key fingerprint binding, duplicate rejection, bounded parser, verified-only resume, append+sync sink; unit tests for tamper/tail/rotation history.
- Portable Rust anchor verifier: metadata/key-ID binding and byte-exact Android signing preimage; ECDSA provider is injected. RustCrypto/provider implementation and true cross-platform ECDSA golden vectors remain unimplemented.
- Android historical-key resolver scans retained numbered Keystore aliases; unknown/malformed key ID fails closed; defensive-copy and lookup tests added.
- Windows durable promotion: isolated `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` helper; durable-store crate retains `forbid(unsafe_code)`; Windows Rust test leg passed in Run #52.
- KMP shared identities changed from JVM-specific inline wrappers to portable data classes after Native compile failures.
- Missing model install planner implemented: verified trust verdict, 2× storage policy, partial cleanup, overflow/negative storage fail-closed, digest idempotency, version compatibility; common tests added.
- CI workflow scope fixed: Android job runs JVM contract tests + Android adapter (native target matrix runs separately); workflow/path triggers synchronized; PR #3 source copied to B4 once, branch reset to tracking-only to prevent duplicate cherry-pick.

### Verified CI evidence
- Rust Run #67 PASS on source `1ce88b75082e62af29580d1357bf4055e3f6ce79`: locked metadata, rustfmt, workspace tests, Clippy.
- Cross-platform Run #52 PASS on the same source: Rust Linux/macOS/Windows and KMP Linux/Windows/macOS host compile/test tasks all succeeded.
- Android Run #82 failed due Maven Central HTTP 429 while compiling unnecessary iOS Native test artifacts in Android workflow, not a Kotlin source error. Workflow narrowed to JVM tests + Android adapter; Android Run #83 is in progress on workflow revision `31bab8539af221f576a56cd2cfb2f69bb73b790d`.
- Earlier true source failures were repaired: Rust format/Clippy, missing test-only sink import, Windows directory-sync behavior, Native `JvmInline`, and absent model install planner. Each fix was driven by actual CI logs.

### Gates still open — do not mark B4 100%
1. Exact final evidence-SHA CI: Rust, Android JNI/16 KB, Android host tests, API 36 emulator, and cross-platform Rust/KMP matrix must all pass on the evidence commit.
2. SQVE v2 is only a common metadata contract/design. Canonical serialized parser/writer, cryptographic RSA/ECDH providers, header MAC/AAD, nonces/counter enforcement, cross-platform golden vectors, v1 read/migration, recovery, fuzz/tamper vectors, and independent security review remain. SQVE v1 unchanged.
3. Rust anchor verifier still lacks a production ECDSA P-256/SHA-256 implementation/provider and real signature vectors; registry/preimage primitive is not the end-to-end signed journal acceptance.
4. Anchor registry must be wired into signer rotation, durable journal checkpoints/recovery, key invalidation, registry export/restore, and trusted integrity/backup policy on each platform.
5. Crash-cut + ENOSPC/storage-fault integration tests and recovery evidence remain.
6. Product-level platform compatibility is incomplete: KMP targets compile shared contracts, but installable Android/Wear OS, iOS/iPadOS/watchOS, Windows/macOS/Linux/JVM app shells, audio/lifecycle/auth/key adapters, packaging/signing, and platform permission/background-capture tests remain.
7. Physical-device gates not performed here: Android hardware-backed Keystore/auth/invalidation/rotation; locked encrypt-only and authenticated unwrap/playback/export; actual crash/reboot/storage exhaustion; physical 16 KB page-size matrix. Physical Apple/Windows device/provider acceptance remains for those implementations.
8. Final B4 acceptance checklist and PR #2 status remain blocked until all applicable CI + physical gates pass. Keep both PRs draft/open/unmerged.

**Final verdict at this checkpoint: B4 = IN PROGRESS / NOT 100% accepted.**


## Current repository re-verification checkpoint — 2026-11-27

- PR #2 remains open/draft/unmerged at source head `6759dce49c2bd13ee4665560833e5d5d6492e23a`.
- PR #3 remains open/draft/unmerged and tracking-only; the anchor verifier source is already integrated in B4. No duplicate cherry-pick/merge action is needed.
- Historical GitHub Actions jobs inspected during this checkpoint were green: Rust run `45987953578`, Android Vault run `45987953623`, and six-job cross-platform run `45987953672`. Their job conclusions were success; however, the commit-run lookup did **not** associate a fresh run with the exact current B4 source SHA. Therefore these are historical green evidence, not a fresh exact-head attestation.
- No new B4 source defect was established from the present repository read. The release blockers listed above remain real implementation/security gates—not checklist-only items.
- This evidence revision requires its own exact-commit CI association before it can be treated as final evidence. Do not mark B4 complete or release-ready based on historical green jobs.
