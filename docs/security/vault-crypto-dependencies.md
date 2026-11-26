# Vault crypto implementation dependencies

B4 pins exact Rust crate versions:

- `aes-gcm = 0.11.1` — RustCrypto AEAD; use only on supported constant-time CPU/provider paths.
- `getrandom = 0.4.3` — OS CSPRNG; failure aborts key/nonce generation, with no fallback.
- `sha2 = 0.11.2` — SHA-256 for content/journal digests.
- `zeroize = 1.9.2` — explicit secret-memory clearing.

The GitHub validation workflow resolves Cargo.lock with the pinned Rust toolchain and commits the lock only after format, test, and Clippy checks succeed. No cryptographic algorithm is implemented from scratch.
