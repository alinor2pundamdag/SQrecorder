# B4 validation record

## Implemented

- SQVE v1 binary header, wrap table, chunk framing, footer, exact AAD, nonce rules, and migration constraints.
- KMP Vault access/chunk/journal contracts, explicit expiring authentication context, signature-anchor metadata, and ordered finalization guard.
- Rust CSPRNG DEK/prefix generation, AES-256-GCM chunk operations, SHA-256, and DEK zeroization.
- Rust SQVE writer validates declared length/order, serializes the envelope, encrypts chunks, hashes the ciphertext stream, and refuses to seal incomplete input.
- Rust SQJ v1 append-only hash-chain writer and non-mutating recovery scanner; writer advances only after sink sync, and torn/corrupt tails are reported with verified-prefix offsets. Sink write/sync failures terminalize the writer to prevent unsafe retries.
- SQJ payload parsing now validates JSON object shape, schema version, and event-code binding; metadata payload is capped at 64 KiB to bound recovery/parser memory. Caller still must provide RFC 8785/JCS canonical bytes; this implementation does not canonicalize JSON itself.
- Added fault-injection coverage for partial writes, invalid JSON/schema, and a schema-tampered record whose digest was recomputed.
- Rust unit tests cover NIST AEAD vector, tamper zeroization, SHA-256, SQVE framing/incomplete files, journal chaining/tamper/torn tail/sync failure.
- Rust CI run 10 passed format, workspace tests, and Clippy with warnings denied on the earlier journal implementation. The new payload-schema, partial-write, and metadata-size-bound tests are pending the next CI run.

## Remaining security gate

Platform asymmetric public-key wrap/private-key authenticated unwrap, durable file promotion (fsync/atomic rename/directory fsync), signed journal anchor implementation, Android/Windows key lifecycle tests, and full crash-recovery integration remain incomplete. B4 is **BLOCKED** until these paths are implemented and tested.
