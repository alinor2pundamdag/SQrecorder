# SQVE Vault envelope v1 — security contract

**Implementation status:** format and policy contract; cryptographic implementation and platform key integration are not yet verified.

## Key hierarchy

- Generate a cryptographically random 256-bit data-encryption key (DEK) for every finalized recording file. Never reuse a DEK across files.
- Encrypt file content with AES-256-GCM in independently authenticated 1 MiB chunks; each chunk carries a 128-bit authentication tag.
- Wrap the DEK with an asymmetric public key. The matching private key unwraps it only in an authenticated Vault session. Public-key encryption is permitted in `ENCRYPT_ONLY` mode so locked Quick Capture can encrypt without decrypting.
- Current wrap suite identifier is RSA-OAEP-SHA-256 (SHA-256 for OAEP and MGF1; RSA key size is capability-checked and the key identifier records the exact key version). OAEP label is the fixed UTF-8 string `SQREC-VAULT-DEK-v1`.
- Optional recovery recipient uses a separate public/private recovery key pair. The private recovery key is user-held/offline; it is never uploaded or embedded in the application.
- App Lock is not a Vault key. Key invalidation is a distinct, surfaced state; never silently generate a replacement key and imply old files are readable.

## Nonce uniqueness

For each new DEK, generate a fresh 4-byte random nonce prefix from the operating-system CSPRNG. For chunk index `i`, nonce is:

`prefix[4] || uint64_be(i)[8]`

The 64-bit chunk index starts at zero, increases strictly, and must never wrap. The file DEK is unique, so a nonce is not reused under a different plaintext with the same key. RNG failure aborts encryption; there is no weak fallback. Never restart chunk numbering while continuing with the same DEK.

AES-GCM requires strict key/nonce uniqueness. See NIST SP 800-38D and the RustCrypto AES-GCM security guidance.

## Authenticated data

The canonical AAD for every chunk binds:

- envelope magic/version and cipher-suite ID
- immutable file UUID and file-key ID
- chunk index and plaintext length
- declared total plaintext length and chunk size
- final-chunk marker

Key-wrap entries are not part of chunk AAD, so key migration can append a new DEK wrap without changing ciphertext. Every wrap entry is independently validated and identified by immutable algorithm/key IDs.

## File and crash protocol

- Encrypt only finalized source WAV; never modify or replace the plaintext evidence source during capture.
- Write to a unique temporary file in the destination directory. Write header, wrap table, ordered chunks, and authenticated footer.
- Flush and fsync the temporary file, atomically rename to the sealed destination, then fsync the directory. Append the durable journal completion record only after the rename is durable.
- Recovery distinguishes sealed, incomplete, corrupt, and authentication-required files. A missing/truncated final chunk is never presented as a complete verified file.
- Authentication/tag failure returns no plaintext and marks the file corrupt/tampered; do not continue with unauthenticated bytes.

## 2049 migration rules

Envelope, cipher, wrap, and key IDs are immutable versioned identifiers. Migration is append-only: preserve old verification material, rewrap the existing DEK where possible, do not re-encrypt or alter ciphertext solely for a key-wrap migration, append a signed migration event, and never overwrite historical signatures.

## Security limits

A hash chain detects accidental damage/reordering but is not by itself an authenticated defense against an attacker who can rewrite the entire journal. Locked capture records an unsigned/pending-authentication status until a protected signature/anchor can be produced. Never describe unanchored hashes as proof of authorship.
