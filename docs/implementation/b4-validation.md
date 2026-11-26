# B4 validation record

## Implemented

- SQVE v1 binary header, wrap table, chunk framing, footer, exact AAD, nonce rules, and migration constraints.
- KMP Vault access/chunk/journal contracts and invariant tests.
- Rust CSPRNG DEK/prefix generation, AES-256-GCM in-place chunk operations, SHA-256, and DEK zeroization.
- Rust SQVE writer validates declared length/order, serializes the envelope, encrypts each chunk, hashes the ciphertext stream, and refuses to seal incomplete input.
- Tests include the NIST AES-256-GCM empty-message vector, round-trip/AAD, authentication-failure zeroization, SHA-256 known vector, envelope framing, and incomplete/wrong chunk rejection.
- Pinned dependency manifest and branch-scoped Rust validation workflow.

## CI history and corrections

- Rust 1.100.1 was unavailable on the runner date; pin corrected to 1.100.0.
- Rustfmt was changed to run before tests and commit formatting only after all checks pass.
- Clippy found and corrected DSP graph issues.
- CI compiled the Vault crate and SQVE writer; the workspace unit tests **passed** in run 6.
- Clippy found a PCM fixed-chunk style lint and a needless borrow in the SQVE writer. Both are corrected; run 8 must confirm the full gate.

## Remaining security gate

Platform asymmetric public-key wrap/private-key authenticated unwrap, durable file promotion (fsync/atomic rename/directory fsync), signed journal anchor, crash recovery, and Android/Windows key lifecycle tests remain incomplete. B4 is still **BLOCKED** until the full Rust gate passes and these platform/storage paths are implemented and tested.
