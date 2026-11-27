# SQVE v2 envelope — implementation design and review checklist

**Decision:** SQVE v2 is authorized as a separately versioned path. This document is a design contract; production format acceptance remains gated on canonical schema, executable golden vectors, and independent review.

## Format and downgrade rules

- Magic: `SQVE`; explicit format version `2`; explicit suite IDs and lengths.
- Readers dispatch by version before cryptographic work. Unknown mandatory fields/suites are rejected.
- v1 is immutable and read-only during migration. No “try v1 then v2” downgrade behavior.
- A v2 file contains a random file identity, per-file salt, chunk parameters, authenticated header, and recipient/wrap records.
- Canonical binary encoding must define byte order, integer widths, length limits, duplicate-field rejection, and exact serialization. No ad hoc JSON or platform-native serialization.

## Data encryption

- Generate a cryptographically random 32-byte DEK for each file.
- Chunk encryption: AES-256-GCM, 12-byte nonce, 16-byte authentication tag.
- Nonce construction: a 4-byte random per-file prefix followed by the 8-byte chunk counter in big-endian order (12 bytes total); reject before counter wrap. The counter starts at zero and is strictly monotonic. Persist the counter/recovery state so crash recovery cannot reuse a nonce under the same DEK.
- Chunk AAD binds version, suite, file identity, chunk index, plaintext/ciphertext lengths, and immutable file metadata.
- On tag failure, return an integrity error; do not expose unauthenticated plaintext or continue as if the chunk were valid.

## DEK wrapping and metadata binding

- Wrap suite is explicit per recipient record. SQVE v2 may define platform-specific, named provider suites; never assume a single primitive is natively hardware-backed on every OS.
- Android RSA-OAEP suites must have distinct immutable IDs for their exact parameters. The API 23–34 provider default MGF1-SHA1 profile is not silently treated as MGF1-SHA256 and requires an explicit security-policy decision; if policy rejects it, those devices must use another reviewed provider suite or report the affected Vault capability unsupported. The SHA-256/MGF1-SHA256/empty-label profile is a candidate for API 35+ where MGF1 digest selection is supported. Android Keystore defaults MGF1 to SHA-1 when not explicitly configured; API 23–34 therefore require a separately identified, reviewed provider profile or another key-agreement/wrapping suite. No runtime parameter substitution or silent suite downgrade is allowed. The empty label fixes only the label incompatibility; it does not by itself resolve MGF1 interoperability.
- Other providers may use their supported hardware-backed key-agreement/wrapping mechanism only under a separately identified suite with exact parameters and test vectors.
- Each recipient record carries a stable key identifier/fingerprint, suite ID, and bounded wrapped-key bytes. Hardware private keys remain inside their provider.
- Derive a distinct header-authentication key from the DEK using HKDF-SHA256 with a fixed, versioned domain-separation info string and the file salt. Authenticate the canonical header and recipient records with HMAC-SHA256. Verify the header MAC in constant time before accepting metadata or decrypting chunks.
- The exact HKDF info label, header canonical bytes, MAC coverage, nonce byte layout, recipient semantics, and suite IDs must be frozen together in the executable spec/golden vectors. Any change requires a new suite/version.

## Multi-device and migration semantics

- Multiple recipient slots allow explicit authorized rewrap for a destination device/account. The same ciphertext DEK may be wrapped independently for each authorized recipient; recipient add/remove operations must be authenticated and journaled.
- Platform key stores are not portable. A copied vault without an authorized recipient key remains locked.
- v1→v2 migration: authenticate and read v1; write a separate v2 staging file; sync and verify all chunks/header; atomically promote and journal; preserve v1 until promotion is confirmed.
- Never log or serialize plaintext DEKs, private key bytes, auth tokens, or audio.

## Required tests before production

- Positive golden vectors generated independently by Rust and at least two provider implementations.
- Negative: bit flips in header/MAC/wrapped DEK/chunks, wrong key ID, wrong file ID, wrong suite, malformed/truncated lengths, duplicate recipient IDs, unknown critical field, downgrade attempt, nonce reuse/wrap, reordering/truncation, invalid tag, failed atomic promotion and recovery.
- Fuzz canonical parser and envelope boundary lengths; run sanitizers where available.
- Review HKDF/HMAC key separation, GCM nonce uniqueness and recipient rewrap protocol with a cryptography reviewer.
- Keep v1 fixture files and regression tests permanently.
