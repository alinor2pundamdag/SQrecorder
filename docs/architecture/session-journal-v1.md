# SQJ session journal v1

## Authority and ordering

The journal and finalized file manifest are recovery authorities; database rows are projections. A single writer assigns strictly increasing 64-bit record sequences and monotonic timestamps. Capture callbacks never synchronously perform journal disk I/O.

## Canonical record

Each record contains:

- format version and stable event type
- sequence number and monotonic timestamp (never wall-clock time)
- session UUID
- previous-record SHA-256 digest (32 bytes; genesis is all zero)
- canonical UTF-8 metadata payload
- current record digest

Payload encoding is canonical JSON (RFC 8785/JCS); schema version and event code are explicit. Store integers that could exceed interoperable JSON precision as decimal strings. Payloads must not contain PCM/audio, plaintext, DEKs, private keys, tokens, or unnecessary personal data.

Digest is calculated over a domain separator `SQJ1`, previous digest bytes, and the canonical record bytes excluding the current digest field. The persisted record is length-delimited and digest appended. Readers reject sequence regression, previous-digest mismatch, malformed lengths, unsupported schema, or invalid digest.

## Durability and recovery

- Append, flush, and fsync before reporting a record durable.
- Never update or truncate a prior valid record.
- On a torn tail, preserve the original bytes, mark the journal damaged, and recover only the validated prefix with a new recovery record/sidecar; do not silently discard bytes.
- A journal write failure latches an integrity incident and triggers controlled capture stop.
- After authenticated finalization, sign/anchor the journal digest with a protected signing key. While locked, status remains `AUTHENTICATION_PENDING`; a plain hash chain alone is not a trusted signature.
- Database metadata is rebuilt from journal + manifest after a crash.
