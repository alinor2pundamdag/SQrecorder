# Vault crypto implementation dependencies

B4 pins the following Rust crates in the Vault crypto crate:

- `aes-gcm = 0.11.1` — audited RustCrypto AEAD; use only on supported constant-time CPU/provider paths.
- `getrandom = 0.4.3` — OS CSPRNG; failure aborts key/nonce generation, with no fallback.
- `sha2 = 0.11.2` — SHA-256 for content/journal digests.
- `zeroize = 1.9.2` — explicit secret-memory clearing.

All are exact-version requirements and are resolved into the committed Cargo.lock by the pinned Rust validation workflow. No cryptographic algorithm is implemented from scratch.
