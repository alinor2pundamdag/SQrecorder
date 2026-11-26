# B4 validation record

## Implemented

- Defined SQVE v1 binary header, variable wrap table, chunk framing, footer, authenticated-data encoding, nonce uniqueness rules, and migration constraints.
- Added KMP Vault access/chunk/journal contracts and invariant tests.
- Added Rust `sqrec-vault-crypto` crate with AES-256-GCM chunk encryption/decryption in place, CSPRNG file-key/nonce-prefix generation, per-chunk nonce derivation, SHA-256, and zeroization of DEK memory on drop.
- Added NIST AES-256-GCM empty-message vector, round-trip/AAD, authentication-failure zeroization, and SHA-256 known-vector tests.
- Added a narrowly scoped GitHub Actions Rust validation workflow. It pins Rust 1.100.1, generates the dependency lock, runs format/tests/Clippy, and commits the Cargo-generated lock only after all checks pass.

## Remaining security gate

The platform asymmetric public-key wrap/private-key authenticated unwrap, durable encrypted-file writer and atomic promotion, signed journal anchor, crash-recovery implementation, and Android/Windows key lifecycle tests remain unimplemented. B4 is not yet complete.

## Verification status

No Rust tests have run locally; Rust/Cargo are absent. The GitHub Actions run is the next verification gate. Do not mark B4 PASS unless the workflow completes successfully and the remaining key-wrap/storage/recovery paths have implementation and tests.
