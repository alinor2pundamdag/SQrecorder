# B4 validation record

## Implemented and CI verified

- Approved B1 foundation retained: SQVE v1 chunked AES-256-GCM, RSA-OAEP SHA-256 wrap contract, KMP Vault/session/journal contracts.
- Rust vault writer, random DEK/nonce prefix, AEAD/AAD, ciphertext hash, zeroization, incomplete-file refusal.
- Rust SQJ append/hash chain and non-mutating recovery scanner; terminal writer after sink write/sync failure.
- JCS canonical payload enforcement (RFC 8785), escaped/nested duplicate-key detection, canonical recovery verification.
- Verified-only journal resume restores sequence/digest/timestamp; rejects damaged tails before append.
- Rust durable-store: staged write/sync/verify/rename/parent sync/journal callback, explicit ambiguous/pending outcomes, non-destructive recovery candidate discovery, fault injection.
- Rust CI **Run #19 PASS** at source SHA `edfb70005d5dedd400025416ec1bcad541306fd9`: strict format, workspace tests, Clippy with warnings denied.
- Android KMP module compiles and host cryptographic contract tests pass in Gradle **Run #13** (API 36, Gradle 9.5.0). Safe key-ID predicate fixed.
- Android P-256 journal-anchor signer and signature-preimage tests added; exact-head Gradle verification pending.

## Locked-contract compatibility blocker

SQVE v1 specifies a **non-empty OAEP label** `SQREC-VAULT-DEK-v1` and MGF1-SHA256. Android Keystore exposes configurable MGF1 digest from API 35, but its RSA-OAEP private-key provider rejects non-empty `PSource.PSpecified` labels. The adapter gates key generation, wrap, unwrap and rotation and returns `UNSUPPORTED_PLATFORM`; it does not silently change the locked envelope or create keys that cannot decrypt.

This is a platform/format incompatibility requiring explicit change control before production Android Vault acceptance. No fallback or envelope mutation was implemented.

## Remaining B4 acceptance

- Resolve the locked SQVE v1 OAEP-label incompatibility through an approved versioned contract change or an independently verified Android Keystore-compatible design.
- Implement and test the concrete Rust/JNI native bridge for opaque DEK handles and chunk operations.
- Verify journal anchors cross-platform in Rust and maintain the signing-key public registry.
- Wire platform journal and durable file promotion to the Rust recovery contract.
- Device tests: auth-bound unwrap, locked encrypt-only capture, key invalidation/rotation/recovery, crash-cut/ENOSPC, 16 KB page and security review.

B4 remains **BLOCKED / NOT 100% accepted** until those gates pass.
