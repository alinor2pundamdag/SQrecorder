# B4 validation record

## Implemented

- Defined SQVE v1 binary header, variable wrap table, chunk framing, footer, authenticated-data encoding, nonce uniqueness rules, and migration constraints.
- Added KMP Vault access/chunk/journal contracts and invariant tests.
- Added Rust `sqrec-vault-crypto` crate with AES-256-GCM chunk encryption/decryption in place, CSPRNG file-key/nonce-prefix generation, per-chunk nonce derivation, SHA-256, and zeroization of DEK memory on drop.
- Added NIST AES-256-GCM empty-message vector, round-trip/AAD, authentication-failure zeroization, and SHA-256 known-vector tests.
- Added a scoped GitHub Actions Rust validation workflow to resolve Cargo.lock and run format/tests/Clippy.

## CI correction

The first workflow run failed before compilation: the runner date was 2026-11-26, while Rust 1.100.1 was not yet published (the toolchain download returned HTTP 404). The toolchain pin is corrected to Rust 1.100.0, which was available at that runner date. This was a toolchain pin error, not a source/test result.

## Remaining security gate

Platform asymmetric public-key wrap/private-key authenticated unwrap, durable encrypted-file writer and atomic promotion, signed journal anchor, crash-recovery implementation, and Android/Windows key lifecycle tests remain unimplemented. B4 is not complete until the corrected workflow passes and these paths are implemented/tested.
