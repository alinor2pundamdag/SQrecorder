# B4 validation record

## Implemented

- Defined SQVE v1 binary header, variable wrap table, chunk framing, footer, exact AAD bytes, nonce uniqueness rules, and migration constraints.
- Added KMP Vault access/chunk/journal contracts and invariant tests.
- Added Rust `sqrec-vault-crypto` primitives: CSPRNG per-file DEK/prefix generation, AES-256-GCM in-place chunk encryption/decryption, SHA-256, and DEK zeroization on drop.
- Added Rust SQVE writer: validates declared length/chunk count, serializes fixed/variable headers, writes ordered chunk records and authenticated tags, hashes the ciphertext stream, and refuses to seal incomplete input.
- Added tests for the NIST AES-256-GCM empty-message vector, round-trip/AAD, authentication-failure zeroization, SHA-256 known vector, envelope header/footer sizes, and incomplete/wrong chunk rejection.
- Added exact-version Rust dependencies and a scoped GitHub Actions format/test/Clippy + lock-resolution gate.

## CI history

- Run 1 failed before compilation because Rust 1.100.1 had not yet been published on the runner date (HTTP 404). Pin corrected to 1.100.0.
- Run 2 reached formatting and failed only because committed Rust files were not rustfmt-formatted. Workflow changed to run rustfmt before tests and commit formatting/lock only after test+Clippy success.
- Run 3 is the current validation attempt; its result must be checked before any PASS claim.

## Remaining security gate

Platform asymmetric public-key wrap/private-key authenticated unwrap, durable encrypted-file writer promotion (fsync/atomic rename/directory fsync), signed journal anchor, crash recovery, and Android/Windows key lifecycle tests remain incomplete. B4 remains **BLOCKED** until the current workflow passes and these platform/storage paths are implemented and tested.
