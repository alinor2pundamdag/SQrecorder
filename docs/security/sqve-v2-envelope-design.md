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
- The ECDH-P-256 suite contract is: generate an ephemeral P-256 key pair per recipient wrap; encode its public key as DER SubjectPublicKeyInfo; compute ECDH with the recipient public key; derive a 32-byte KEK with HKDF-SHA256 (IKM=ECDH secret, salt=fileSalt, info=`SQREC-SQVE2-ECDH-P256-DEK-WRAP-v1 || fileId[16] || recipientKeyIdLength:u16be || recipientKeyId:utf8`); AES-256-GCM-wrap the 32-byte DEK using a fresh 12-byte nonce; use AAD=`suiteId:u16be || fileId[16] || recipientKeyIdLength:u16be || recipientKeyId:utf8 || ephemeralPublicKeyDER`; store ciphertext+16-byte tag. This is a portable cryptographic profile; hardware-backed status depends on the platform's private-key provider.
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


## Canonical SQVE v2 wire profile — implementation baseline

The following byte profile closes the encoding ambiguities for implementation and vector generation. It does **not** waive independent cryptographic review or make V2 production-accepted before cross-provider vectors pass.

### Primitive encodings and bounds

- All integers in V2 are unsigned, fixed-width, **big-endian**. V1 remains byte-for-byte little-endian where its reader specifies it.
- Lengths are byte counts, not character counts. Parsers validate bounds and arithmetic before allocation; reject truncation, overflow, duplicate recipient IDs, unknown mandatory suite IDs, nonzero reserved fields, and trailing bytes.
- Recipient key IDs are canonical ASCII tokens, 1–128 bytes, limited to `A-Z a-z 0-9 . _ - :`. IDs are case-sensitive and unique within one header. Do not normalize or silently rewrite IDs.
- Header maximum: 65,535 bytes. Recipient count: 1–16. Wrapped-DEK record maximum: 8,192 bytes. Chunk size is exactly 1,048,576 bytes except the final chunk; zero-length files have zero chunk records.
- V2 content suite ID `0x0001`: AES-256-GCM, 12-byte nonce, 16-byte tag. Wrap suite IDs are scoped to V2 and immutable: `0x0001` RSA-OAEP-SHA256 with MGF1-SHA256 and empty label; `0x0002` ECDH-P-256/HKDF-SHA256/AES-256-GCM profile below. A provider that cannot implement the exact selected suite must fail capability negotiation; no parameter substitution.

### Header serialization

Serialize these fields in order:

1. magic `SQVE` (4 bytes)
2. version `u16be = 2`
3. total header length `u32be` (includes the final 32-byte MAC)
4. content suite `u16be = 0x0001`
5. flags `u16be`: `0x0000` fixed-length or `0x0001` streaming-capture; reject all other bits
6. file ID (16 random bytes)
7. file salt (32 random bytes)
8. nonce prefix (4 random bytes)
9. chunk size `u32be = 1,048,576`
10. declared plaintext length `u64be`
11. declared chunk count `u64be`
12. recipient count `u16be`
13. reserved `u16be = 0`
14. recipient records, sorted by recipient key ID's raw ASCII bytes ascending; each record is `wrapSuite:u16be || keyIdLength:u16be || wrappedLength:u32be || keyIdBytes || wrappedBytes`
15. header MAC (32 bytes)

For each record, `wrappedLength` is the exact byte length of `wrappedBytes`; the enclosing header length is computed with checked arithmetic. Reject non-canonical recipient ordering rather than sorting attacker-supplied data during parse.

The header MAC key is HKDF-SHA256(`IKM=DEK, salt=fileSalt, info=ASCII "SQREC-SQVE2-HEADER-MAC-v1", L=32`). The MAC is HMAC-SHA256 over every serialized header byte preceding the MAC field (including all recipient records and the declared header length). Verify in constant time before trusting header fields or invoking a unwrap provider. Header rewrap/add/remove operations must recompute this MAC and commit through the journal; the content DEK and chunk ciphertext remain unchanged.

### ECDH recipient wrapped-DEK bytes

For suite `0x0002`, the `wrappedBytes` are exactly:

`ephemeralSpkiLength:u16be || ephemeralSubjectPublicKeyInfoDER || wrapNonce[12] || encryptedDEK[32] || gcmTag[16]`.

The ephemeral SPKI length must be 1–2,048 bytes and decode as exactly one P-256 public key; reject trailing DER bytes and non-P-256 keys. The HKDF info and wrap AAD are the exact byte strings defined in “DEK wrapping and metadata binding” above. The nonce is freshly generated for every wrap. The wrapped plaintext is exactly the 32-byte DEK; ciphertext length is therefore exactly 32 bytes, followed by the 16-byte tag.

### Chunk framing and AAD

Each chunk record is:

`chunkIndex:u64be || plaintextLength:u32be || ciphertextLength:u32be || ciphertext[ciphertextLength-16] || tag[16]`.

Require index sequence 0..chunkCount-1 with no gaps or duplicates. `ciphertextLength = plaintextLength + 16`; plaintext length is 1..1,048,576 except a final shorter chunk. Nonce is the 4-byte header prefix followed by `chunkIndex:u64be`. Reject a chunk count/length pair that does not equal the checked ceiling of declared plaintext length / chunk size, or any index that could exceed the counter limit.

Chunk AAD is the concatenation, without separators:

`ASCII "SQREC-SQVE2-CHUNK-AAD-v1" || version:u16be(2) || contentSuite:u16be || fileId[16] || fileSalt[32] || noncePrefix[4] || chunkSize:u32be || declaredPlaintextLength:u64be || chunkIndex:u64be || plaintextLength:u32be`.

Recipient records are intentionally excluded from chunk AAD so an authenticated recipient rewrap does not require re-encrypting audio. The header MAC authenticates those records separately.

### Stream footer

After the declared chunk records, write exactly 56 bytes:

`magic "SQVF"[4] || version:u16be(2) || footerLength:u16be(56) || chunkCount:u64be || plaintextLength:u64be || streamDigest[32]`.

Do not truncate SHA-256; reject any other footer length. The digest is SHA-256 over the complete serialized header (including its MAC) and all chunk record bytes, excluding the footer. The footer digest is an integrity/consistency aid; AEAD tags and the authenticated header remain the cryptographic authenticity boundary.

### Implementation sequencing / safety

- Implement this profile in a new V2 module and parser; do not change V1 constants or reinterpret V1 bytes as V2.
- Generate deterministic fixtures with fixed test-only keys/IDs/salt/nonces and independently reproduce them in Rust plus at least two platform providers. Test fixtures must never be used as production randomness.
- Before shipping, a cryptography reviewer must confirm this serialization, HKDF domains, HMAC coverage, ECDH wrap profile, nonce uniqueness/recovery, and recipient rewrap semantics. If review changes any byte or cryptographic parameter, update the suite/version and vectors together; do not silently edit an already deployed suite.

### V2 streaming-capture mode (required for live microphone capture)

The fixed-length profile above cannot be used for an active take because its final WAV length is unknown at Start. Do not stage plaintext or claim a guessed length. V2 therefore defines the authenticated streaming flag `0x0001`:

- Header plaintext length and chunk count are both `u64be = 0xffffffffffffffff` sentinels; the header MAC authenticates the flag and sentinels.
- Chunk AAD binds those sentinel values exactly as serialized. Chunk indices remain consecutive; every chunk is authenticated before acceptance.
- Streaming output emits full 1 MiB chunks as available; only the final chunk may be shorter. Zero-byte capture has zero chunk records.
- The 56-byte footer carries actual plaintext length and chunk count. Verification streams to the footer, checks actual count/length against the chunk sequence, authenticates every GCM tag and the stream digest, then requires EOF.
- Fixed-length mode (`flags=0`) retains declared count/length checks. A parser must require the flag and both sentinels to agree.

This pre-release profile addition enables encrypted live capture without plaintext staging. It requires deterministic vectors, crash/recovery tests and independent cryptographic review before production acceptance. V1 remains unchanged.
