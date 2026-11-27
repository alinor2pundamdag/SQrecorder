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
- Rust FFI transient DEK copies now use RAII zeroization, including early-return/error paths during import and public-wrap copy.
- Added host tests for exact-window acceptance, overlong authorization rejection, revoked epochs, and expired contexts. Commit: `91b89fa7ab3bb5ab40dc7d146f47ae4ff3db7017` (implementation), `b017a778f0653dc7934a6d797d5cf91b9810045f` (tests), `93221e987ad2e0bd540e09287645efb3503120be` (anchor-signing integration), `2b5dcfe7f4eda492b58d0bd47c8f75448610b361` (FFI transient-key zeroization).

## Verification

- Historical baseline: Rust **Run #26 PASS** for workspace tests/Clippy and native ABI tests at source SHA `b6ca43124ec1ed9cf2a49e1090dc051a73ad9e06`; this is not evidence for current branch HEAD.
- Historical Android Gradle **Run #13 PASS** covered KMP/host crypto tests before later JNI/anchor/auth changes.
- Android Run #18 recorded transient Maven HTTP 429/502; bounded retry/cache mitigation remains in workflow.
- CI workflow hardening committed: Rust validation now targets `main` for PR #2, checks the event revision via pinned checkout, validates the committed lockfile (`cargo metadata --locked`), uses `cargo fmt --check`, and has read-only permissions (no bot formatting/lockfile pushes).
- Latest observed PR head at this audit: `3d2fb857642becfb928d2537bf457dd1b084aa02`. Re-queried PR metadata confirms this is the open draft PR #2 head (92 commits, 65 changed files). Commit status endpoint returned an empty status list, and the connector's PR-run query returned no runs. The connector run wrapper is PR-event-filtered; these empty results alone do not prove Actions never ran, so exact-head CI remains **UNVERIFIED** pending direct run/job evidence. Historical run results are not current-head acceptance.

## Locked-contract compatibility blocker

SQVE v1 specifies a **non-empty OAEP label** `SQREC-VAULT-DEK-v1` and MGF1-SHA256. Android Keystore exposes configurable MGF1 digest from API 35, but its RSA-OAEP private-key provider rejects non-empty `PSource.PSpecified` labels. The adapter fails closed with `UNSUPPORTED_PLATFORM` for key generation/wrap/unwrap/rotation; it does not alter the locked envelope or create keys that cannot decrypt.

This platform/format incompatibility requires explicit change control before production Android Vault acceptance.

## Remaining B4 acceptance

- Resolve OAEP-label compatibility through an approved versioned wrap-suite change or a verified compatible Keystore design.
- Verify anchor signatures cross-platform in Rust and maintain a durable signing-key registry.
- Connect and test the native library package on Android devices; verify API/auth, key invalidation/rotation, and lifecycle.
- Wire Android journal and durable file promotion to Rust recovery; complete crash-cut/ENOSPC tests and security review.
- Device evidence: locked encrypt-only capture, authenticated unwrap/playback/export, 16 KB page compliance across supported ABIs.

B4 remains **BLOCKED / NOT 100% accepted** until all gates pass.
