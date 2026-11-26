# SQJ v1 session journal

## Record encoding

Each record is length-prefixed and append-only:

- body length: u32 little-endian (includes digest, excludes prefix)
- magic `SQJR`, version 1, record type u16
- sequence u64, monotonic timestamp u64
- session UUID 16 bytes
- previous digest 32 bytes
- canonical JSON payload length u32 and UTF-8 payload
- current record digest 32 bytes

Minimum body length is 108 bytes. Digest is:

`SHA-256("SQJ1" || previous_digest || record_body_without_current_digest)`

The KMP producer must serialize metadata as RFC 8785/JCS canonical JSON and must never include audio, plaintext, key material, or authentication secrets.

## Durability and recovery

`JournalWriter` requires an append-only sink. Each append writes a complete record and calls the sink's sync operation before advancing its sequence/digest state. Write or sync failure makes that writer terminal; it must not retry against a potentially partial tail.

`verify_journal` scans without modifying input. It verifies magic/version/type, sequence, previous digest, payload length/UTF-8, and SHA-256. It reports the byte offset of the last fully verified prefix and distinguishes a truncated tail from corruption. The caller preserves original tail bytes and emits a recovery/integrity event; this module never truncates or silently repairs evidence.

The platform sink must implement write-all + fsync/FlushFileBuffers. Atomic promotion and parent-directory sync are performed by the Vault file-store adapter. Authenticated signature anchors are created by platform Keystore/CNG signing APIs after user authentication; this Rust hash chain alone is not authorship proof.
