# SQVE Vault envelope v1 — security contract

**Implementation status:** serialized format and policy contract; cryptographic engine and platform key integration are not yet verified.

## Key hierarchy

- Generate a cryptographically random 256-bit data-encryption key (DEK) for every finalized recording file. Never reuse a DEK across files.
- Encrypt file content with AES-256-GCM in independently authenticated 1 MiB chunks; each chunk carries a 128-bit authentication tag.
- Wrap the DEK with an asymmetric public key. The matching private key unwraps it only in an authenticated Vault session. Public-key encryption is permitted in `ENCRYPT_ONLY` mode so locked Quick Capture can encrypt without decrypting.
- Current wrap-suite ID is RSA-OAEP-SHA-256 (OAEP and MGF1 both SHA-256; key size is capability-checked and exact key version is identified). OAEP label is the fixed UTF-8 string `SQREC-VAULT-DEK-v1`.
- Optional recovery recipient uses a separate public/private recovery key pair. The private recovery key is user-held/offline; it is never uploaded or embedded in the application.
- App Lock is not a Vault key. Key invalidation is a distinct surfaced state; never silently generate a replacement key and imply old files are readable.

## Nonce uniqueness

For each new DEK, generate a fresh 4-byte random nonce prefix from the operating-system CSPRNG. For chunk index `i`, nonce is `prefix[4] || uint64_be(i)[8]`. The index starts at zero, increases strictly, and must never wrap. Since each file has a unique DEK, a nonce is never reused with that key for different plaintext. RNG failure aborts encryption; there is no weak fallback. Never restart chunk numbering while continuing with the same DEK.

AES-GCM requires strict key/nonce uniqueness. See NIST SP 800-38D and the RustCrypto AES-GCM security guidance.

## Binary layout

All integers are unsigned little-endian. Reserved bytes must be zero. This layout is serialized explicitly; never write a native struct image.

### Fixed 64-byte header

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `SQVE` |
| 4 | 2 | envelope version = 1 |
| 6 | 2 | total header bytes, including key ID and wrap table |
| 8 | 2 | cipher suite ID = 1 (AES-256-GCM chunked) |
| 10 | 2 | flags = 0 in v1 |
| 12 | 4 | chunk size = 1,048,576 |
| 16 | 8 | plaintext byte length |
| 24 | 8 | chunk count |
| 32 | 16 | file UUID bytes |
| 48 | 4 | random nonce prefix |
| 52 | 2 | UTF-8 file-key ID length |
| 54 | 2 | wrap-entry count |
| 56 | 8 | reserved zero |

The fixed header is followed by the file-key ID (UTF-8, non-empty, <=128 bytes), then each wrap entry:

`wrap_suite:u16 || recipient_key_id_len:u16 || wrapped_DEK_len:u32 || recipient_key_id:bytes || wrapped_DEK:bytes`

Wrap entries are bounded by the parser's configured maximum header size and validated before allocation. Key-wrap metadata can be appended/replaced during rewrap without changing ciphertext.

### Chunk record

For each chunk in ascending index order:

`chunk_index:u64 || plaintext_len:u32 || ciphertext_len:u32 || ciphertext_and_tag`

`ciphertext_len = plaintext_len + 16`. Empty plaintext files have zero chunks. The last chunk length must exactly match the header's declared total length. No trailing bytes are allowed before the footer.

### Footer (56 bytes)

`SQVF[4] || version:u16 || footer_bytes:u16(56) || chunk_count:u64 || plaintext_bytes:u64 || ciphertext_stream_sha256[32]`

The SHA-256 covers the serialized header, wrap table, and chunk records. It detects accidental damage/incomplete writes; it is not a signature and cannot alone prove authorship.

## Authenticated data (AAD)

For every chunk, AAD is the exact concatenation:

`"SQVE-AAD1" || header[0..52] || file_key_id_len:u16LE || file_key_id_UTF8 || chunk_index:u64LE || plaintext_len:u32LE || final_chunk:u32LE`

The wrap count and wrap entries are excluded so DEK rewrap does not require content re-encryption. File UUID, cipher suite, key ID, nonce prefix, chunk index, length, and final-chunk status are authenticated.

## File and crash protocol

- Encrypt only finalized source WAV; never modify or replace the plaintext evidence source during capture.
- Write to a unique temporary file in the destination directory. Write header, wrap table, ordered chunks, and footer.
- Flush and fsync the temporary file, atomically rename to the sealed destination, then fsync the directory. Append the durable journal completion record only after rename durability.
- Recovery distinguishes sealed, incomplete, corrupt, and authentication-required files. Missing/truncated chunks are never presented as complete.
- Authentication/tag failure returns no plaintext and marks the file corrupt/tampered; never continue with unauthenticated bytes.

## Migration rules

Envelope, cipher, wrap, and key IDs are immutable versioned identifiers. Migration is append-only: preserve old verification material, rewrap the existing DEK where possible, do not re-encrypt or alter ciphertext solely for a key-wrap migration, append a signed migration event, and never overwrite historical signatures.

## Security limits

A hash chain detects accidental damage/reordering but is not by itself an authenticated defense against an attacker who can rewrite the entire journal. Locked capture records an unsigned/pending-authentication status until a protected signature/anchor can be produced. Never describe unanchored hashes as proof of authorship.
