# B4 validation record

> **AUTHORITATIVE LOCK: SQVE v2 is the only current encrypted-write/finalization target. SQVE v1 is legacy read/verification compatibility only; no new V1 output and no silent downgrade. This supersedes historical B1/B4 wording that called V1 the locked/current write format. Implement V2 only against the approved canonical schema, provider suite IDs, golden vectors, and review gates.**

## Implemented

- Approved B1 foundation retained: Historical SQVE v1 reader/compatibility contract, plus KMP Vault/session/journal contracts; SQVE v2 is the authoritative current write/finalization target.
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
2. SQVE v2 is only a common metadata contract/design. Canonical serialized parser/writer, cryptographic RSA/ECDH providers, header MAC/AAD, nonces/counter enforcement, cross-platform golden vectors, v1 read/migration, recovery, fuzz/tamper vectors, and independent security review remain. SQVE v1 retained only as immutable legacy read/verification compatibility; SQVE v2 is the sole current write target.
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


## Windows durable-store CI repair — 2026-11-27 22:27 +08:00

- Current B4 head before this correction: `4784ff128fd016d13337c5971de1f252a6107671`.
- Cross-platform Run #91 (`46009026821`) failed only in Windows Rust portable-core test `directory_sync_failure_reports_ambiguous_promotion`; Rust and Android workflow at that SHA passed.
- Log confirmed seven durable-store tests passed and the injected parent-directory-sync test failed its expected `PromotionDurabilityUnknown` assertion after stage creation/rename. The test combined a synthetic post-rename sync failure with the platform-specific write-through rename, so it did not isolate the fault boundary.
- Correction: the `FaultPoint::ParentSync` test path now uses a direct same-directory rename and then injects the parent-sync error; real platform write-through rename remains exercised by normal promotion tests. Added assertion diagnostics showing the actual result variant if it fails again.
- Fix commit: `0bbda73c60cacbcbcc87d0d7f3ff222b59e3a0a5`.
- **Not yet verified:** fresh Windows Rust and full cross-platform matrix on this fix/evidence head. No gate marked PASS from the failed run; rerun evidence required.


## Corrective rerun after Windows durability-test repair — 2026-11-27

- Latest B4 implementation/evidence source at this checkpoint: `89ce951e51b98b6a837a98f2266889e72cfd6231`.
- Rust Run #136 (`46016198716`) **PASS** on exact SHA: locked metadata, rustfmt, workspace tests, Clippy.
- Cross-platform Run #95 (`46016198880`) **PASS** on exact SHA: Linux/macOS/Windows Rust portable-core jobs and Linux/Windows/macOS KMP host compile/test jobs all succeeded. The Windows `directory_sync_failure_reports_ambiguous_promotion` test passed after the test was isolated from platform-specific write-through rename.
- Android Vault Run #161 (`46016198883`) is **IN PROGRESS** on exact SHA; API 36 emulator Vault bridge was the active step at last poll. Do not mark Android gate complete until run conclusion is success.
- Earlier Windows failure Run #91 remains in history and is superseded only for this exact source by Run #95. Physical-device gates, SQVE v2 provider/security review, journal/durable recovery integration, and 16 KB device evidence remain open.
- The subsequent evidence-only commit will require another exact-head workflow check; preserve the above run references as evidence for this source SHA, not the later documentation commit.


## Exact-head verification closure — 2026-11-27 14:53 UTC

- Current PR #2 source SHA: `d550b32744bd17bfbdd62c4361ed6eca211f23f3`.
- Rust contract Run #159: **PASS** (locked metadata, rustfmt, workspace tests, Clippy).
- Cross-platform Run #118: **PASS** (all six Rust/KMP Linux, macOS, Windows jobs).
- Android Vault Run #184: **PASS** (native/JNI 16 KB checks, host contracts, app/unit build, API 36 emulator Vault bridge).
- These three workflows are confirmed completed/successful by GitHub Actions for the exact source SHA above. This closes the current CI verification wait for this B4 hardening slice; it does not close B4 release acceptance.
- **SQVE scope correction:** SQVE v1 remains immutable legacy compatibility only; SQVE v2 is the current write target. Owner-approved ADR 0002 is the only approved envelope-version revision: separately versioned SQVE v2, with schema, cryptographic golden vectors, provider conformance, migration and independent review still required. Do not change other locked blueprint decisions or treat v2 metadata contracts as complete crypto.
- B4 remains **IN PROGRESS / NOT 100%**: end-to-end secure capture finalization, signed journal/key-registry integration, crash/ENOSPC recovery matrix, final integrated CI, and required device acceptance remain open.


## Reconciled exact-head CI — 2026-11-27 23:xx UTC

- Live GitHub Actions API verification resolved the previous pending-evidence ambiguity. PR #2 head at this checkpoint was `81d8759df022c1f9a7f6a48b41b072a2094d0cdb`.
- Rust contract Run #160 (`46023749757`) **PASS**; cross-platform matrix Run #119 (`46023749508`) **PASS**; Android Vault contract Run #185 (`46023749577`) **PASS**. All three completed successfully on the exact same SHA.
- Therefore the B4 evidence/documentation head's Rust, six-platform Rust/KMP matrix, and Android Vault/API 36 emulator CI wait is **CLOSED** for that SHA. This is not a release-acceptance declaration.
- The current document-only update creates a new commit and must be validated by fresh exact-head CI. Keep PR #2 and tracking PR #3 draft/open/unmerged.


## Exact-head CI verification — 2026-11-28 (UTC)

- B4 source/evidence SHA before this refresh: `aa153091449a56e1a8b697cb78384266a87270b2`.
- Rust contract Run #162 (`46107670110`): **PASS**.
- Cross-platform matrix Run #121 (`46107670142`): **PASS**.
- Android Vault contract Run #188 (`46107670104`): **PASS**.
- GitHub Actions confirms all three completed successfully on the exact same source SHA. The B4 source-slice CI wait is closed for that commit; this documentation update advances the branch and requires fresh exact-head CI.
- B4 remains **not release-complete**: SQVE v2 cryptographic implementation/golden vectors/provider conformance, Android encrypted finalization wiring, SQJ durable journal/checkpoint and key-registry integration, encrypted durable promotion/recovery, crash-cut/ENOSPC/force-stop matrix, full combined-candidate CI, and physical-device acceptance remain open. SQVE v1 and all other blueprint decisions remain locked.


## SQVE v2 implementation + encrypted capture checkpoint — 2026-11-28

This supersedes the prior checkpoint wording that V2 cryptographic implementation and Android finalization wiring had not started. They are now **implemented as candidate slices**, not release-accepted:

- Rust core/vault-crypto/src/v2.rs: canonical fixed-length V2 header, authenticated HKDF/HMAC header, chunk AAD/nonce, AES-256-GCM streaming writer/verifier, strict footer/EOF, ECDH recipient record encoding and validation, deterministic fixed + streaming envelope golden vectors, and explicit RSA-3072 suite framing.
- Live capture: authenticated streaming flag/sentinels and SQVC records allow final byte/chunk counts in footer. Rust writer holds a bounded 1 MiB buffer and zeroizes it on drop. No plaintext file staging.
- Android: AudioRecord → bounded native queue → single consumer → SqveV2EncryptedWavSink writes SQVE v2 .sqve.part; native Rust chunk AES-GCM is used; header codec emits canonical HMAC; first chunk is reserved so WAV size fields are patched before encryption; buffers are scrubbed. App no longer writes plaintext .wav.part in this path.
- Android provider: API 31+ ECDH-P256 suite; API 23–30 explicit RSA-3072/OAEP-SHA256/MGF1-SHA1/empty-label suite 0x0003. This is an explicit V2 suite, never a V1 fallback. API23 emulator/provider verification and independent crypto review are still gates.
- Android tests now include independent header golden vectors and encrypted sink multi-chunk/footer assertions. Latest exact candidate head before this evidence edit: b9171e03c81c9ec139796d30ad3c05ec8691e5cf. Rust, cross-platform and Android workflows were started for that exact head; capture their final conclusions after the evidence commit, because this commit advances the head.

Still **NOT 100% / NOT release-accepted**: SQJ persisted events/checkpoints/final hash and idempotent journal-backed finalization; encrypted durable-store stage/verify/promote/reconcile and startup recovery; crash-cut/force-stop/ENOSPC/sink-failure/queue-overrun matrix; recording-list/playback/decryption/authenticated recovery UI; API23 + API31+ emulator and physical device matrix; independent crypto review; iOS V2 recipient provider and cross-provider vectors. PR #2 and controlled candidate PR #7 remain draft/open/unmerged.


## Exact-head CI restart requested — 2026-11-28

- Candidate head before this evidence-only update was `6d49f940927d0658318b5223b292a82c3c576ea4`; GitHub Actions workflow-run query returned zero runs and combined commit status returned no statuses. This was recorded as **not run/not verified**, never PASS.
- Updated the B4 evidence record to request a fresh CI cycle from the controlled candidate branch. This commit changes only validation evidence; it does not alter implementation and does not convert any gate to PASS.
- After this commit, fetch the new PR head and check Rust, cross-platform and Android workflow runs against that exact SHA. Keep the PR draft/open/unmerged. If path filters prevent a workflow from running, record it as not run and request a supported manual dispatch/re-run; do not infer success.


## Capture artifact no-clobber promotion hardening — 2026-11-28

- Fixed a destructive collision edge in the Android capture service: the encrypted `.sqve.part` is now created with exclusive `File.createNewFile()` before opening `RandomAccessFile("rw")`, so an orphaned stage is never silently reused/truncated.
- Final publication now uses a same-filesystem hard-link create (atomic destination-name creation that fails if the final name exists), directory sync, stage unlink, and a second directory sync. It avoids `ATOMIC_MOVE` provider semantics that may replace an existing target. A crash between link and unlink can leave both names for the same verified ciphertext; recovery preserves/reconciles them, never overwrites.
- Implementation commit: `bbbdde6cba02d7111d8245de03eddfb7e7b2837d`; follow-up removed the now-unused move import: `3ca7fe3b823098c6f35ca90943709634271b8532`.
- **Verification pending:** this relies on hard-link support for the app-private recording filesystem; Android API/device and crash-cut tests must validate link + directory-sync + unlink behavior. Do not mark durable promotion acceptance until those tests and exact-head CI pass.


## Follow-up source audit — canonical WAV metadata verification — 2026-11-28

- Audited the current Android capture sink and found its staged-envelope verifier checked the WAV signature and PCM data-length field, but did not compare the complete 44-byte RIFF/WAVE header. That left RIFF size and format metadata (sample rate, byte rate, channel/bit-depth fields, block alignment) outside the explicit verification assertion.
- Hardened `SqveV2EncryptedWavSink.verifyFinished()` to compare the authenticated first-chunk plaintext header byte-for-byte against `PcmWavHeader.create(sampleRateHz, pcmBytes)` before promotion. The temporary expected header is zeroized after comparison.
- Updated the encrypted sink host test to assert the full canonical header rather than only the RIFF signature/data size.
- Commits: verifier `16241e828fa1529ad124a0b10b3269e5c434de0f`; test `85f14fab1bfce40297bb70b5b3386bd94148fca1`.
- **CI: NOT RUN / NOT VERIFIED** for current SHA `85f14fab1bfce40297bb70b5b3386bd94148fca1`: Actions workflow lookup returned zero runs and combined commit status returned no checks. The connected GitHub actions expose failed-job rerun, but not workflow dispatch; no run was triggered here. Do not claim this Kotlin patch compiled or passed.
- PR #7 remains draft/open/unmerged. This source audit is a correctness hardening delta, not a gate closure. Exact-head CI, emulator and physical-device crash/storage testing, authenticated recovery/reconciliation, independent crypto review, and full B4/B5 acceptance remain open.


## Follow-on integration audit — SQJ timestamp ordering and orphan recovery — 2026-11-28

- Found a real ordering edge in Android capture: native integrity events are consumed/drained after the lifecycle thread can append `CAPTURE_STOP_REQUESTED`. The native event's original monotonic timestamp may therefore be earlier than the journal's latest record timestamp, causing the SQJ writer to reject an otherwise valid drain append and fail capture finalization.
- Corrected the append contract: SQJ record timestamp uses append-time `SystemClock.elapsedRealtimeNanos()`; original native event time is retained as the explicit `eventTimestampNs` payload field. This preserves source evidence while maintaining nondecreasing durable journal record order.
- Startup recovery inspection previously logged an unfinished session only when a partial/final artifact existed. It now reports every valid non-finalized journal, including a crash after durable session creation but before stage creation; finalized journal + missing final or lingering partial is also reported as an artifact/journal mismatch. Still read-only; no auto-delete, truncate, decrypt or promote.
- Hardened encrypted sink range validation against signed-int overflow in `offset + length`, and zeroizes temporary header-MAC input/actual/stored buffers on both success and failure paths.
- Added a host test that rejects journal timestamp regression before writing bytes, then confirms the next valid append preserves a valid sequence/digest chain; added a sink test for overflowed PCM offset.
- Commits: service/recovery `1d2d86b70f006fcbda05b369c3d5e05a1e2ea6d3`; sink `b338609dc6f63dce991f11ffa7930dcb969255df`; sink test `a500b84040c6f66c3ed0df1f6a905924de8d5e67`; journal test `adf90909c88c0b989c29576e56731c1598d1a3cd`.
- **Exact-head CI not run/not verified** at implementation head `adf90909c88c0b989c29576e56731c1598d1a3cd`: workflow lookup returned zero PR runs and combined status had no checks. No compilation/test pass is claimed. These fixes reduce failure/recovery ambiguity but do not close the authenticated recovery, fault-matrix, physical-device or release gates.


## SQJ recovery scanner lifecycle hardening — 2026-11-28

- The Android SQJ scanner previously validated record framing, canonical payloads, timestamps and the SHA-256 chain, but treated any occurrence of `FILE_FINALIZED` as terminal success regardless of lifecycle order. Because the chain digest is unkeyed, structural transition validation is also required; a recomputed chain must not bless a premature or duplicate finalization record.
- Added scanner transition checks: session-created must be first/unique; capture-start, stop-request, stop-complete, encryption-start, encryption-complete and file-finalized must occur in valid order and at most once; integrity/recovery/migration events cannot precede session creation or follow finalization; no record is accepted after file-finalized.
- Expanded host tests to exercise the full normal lifecycle and reject premature/post-finalization records, in addition to digest tampering and timestamp regression tests.
- Commits: scanner `fb0824a89ab9417d437224d81d88c3b7f2d2dc20`; lifecycle tests `53b040d370debc9ac1832930b41a55aac5e03300`; terminal-event tests `765e27918701d61b50ff9b2551e88701cc1a5d54`.
- This is fail-closed scanner hardening, not authenticated recovery. The Android SQJ remains unkeyed SHA-256 chained metadata, read-only startup scan; signed anchor/checkpoint binding, decrypt-and-verify recovery, journal resume/idempotent finalization, and crash-cut tests remain release blockers.
- Exact-head CI must run on the integrated candidate after this change. No compile/test pass is claimed from source edits alone.


## Empty-journal crash cut — 2026-11-28

- Final scanner edge: an exclusively created but zero-byte SQJ (power loss before the first durable `SESSION_CREATED` record) was previously reported as a valid empty chain. It now returns invalid/damaged-tail with an explicit missing-first-record reason; startup will preserve and surface it as recovery evidence.
- Added a host test for create/close-without-append and scanner rejection.
- Commits: scanner `fd383e4e7b63ecf89b79945a2adc899e87f4937b`; test `8ac7e160b04cfaeb12704ef639c995f49d768a5f`.
- Exact-head CI and all release/device gates remain pending. This is another fail-closed recovery correctness fix, not acceptance.


## SQJ signed checkpoint codec and exact-journal binding — 2026-11-28

- Added a portable canonical SQAC v1 checkpoint codec in core/session-journal/src/checkpoint.rs. It persists the full signed anchor fields without lossy conversion, bounds algorithm/key/signature lengths, rejects unsupported versions, malformed metadata, truncation and trailing bytes.
- Added verify_checkpoint_binding: it first requires the supplied journal to be a completely valid, non-truncated SQJ stream, then requires the anchor sequence and digest to match that journal's exact terminal record, and finally verifies the anchor signature against the append-only retained-key registry/provider. A valid signature over a stale/different journal is not accepted as current.
- Added round-trip, truncation/trailing-data, wrong-magic and zero-sequence codec tests. Exposed the API from the crate root.
- Commits: codec 8072345f434bbc1457a53bf61685b983a3a76edc; length-offset correction 0ae0e8cae04cea274795d764a55feec467aa8b9a; crate export 76fa8894f9e24bf891f8ae8b118f683f0ed32003.
- Scope boundary: this is portable verification/encoding, not platform durable checkpoint writing, signer/key lifecycle integration, automatic recovery, or atomic checkpoint replacement. Android must persist only after SQJ record sync, then checkpoint file + parent directory sync; stale checkpoint/journal mismatch must remain evidence and fail closed.
- Rust formatting, workspace tests, Clippy, Android integration, and exact-head CI are NOT RUN / NOT VERIFIED for the integrated head. PR remains draft/open/unmerged.


- Follow-up regression test added: a signed checkpoint is accepted only when sequence+digest bind to the exact fully verified journal head; stale digest and stale sequence are rejected before crypto-provider acceptance. Test commit: f427057e871eb7e279b02af7584c4aae773f0ba8. Rust formatting/build/tests and exact-head CI remain not verified.
