# B4 validation record

## Contract work committed

- Defined a versioned chunked Vault envelope model, per-file key-wrap metadata, authenticated chunk descriptors, nonce derivation, access modes, and opaque provider-owned file-key handles.
- Defined asymmetric key-wrap contract: the public key wraps the per-file DEK; private-key unwrap is authenticated. Encrypt-only capture cannot decrypt or release plaintext.
- Defined append-only journal record metadata, sequence/previous-digest validation, durable-append semantics, and recovery/security limitations.
- Added common tests for envelope length/chunk invariants, nonce construction, and journal chain metadata.

## Security review and current dependency references

- AES-GCM is the selected authenticated encryption mode. The current RustCrypto `aes-gcm` crate is 0.11.1 and reports an NCC Group audit with no significant findings; its documented nonce requirement is uniqueness per key. [RustCrypto AES-GCM](https://docs.rs/aes-gcm/0.11.1/aes_gcm/)
- Current `zeroize` is 1.9.2 (Rust 1.85+ MSRV). [zeroize 1.9.2](https://docs.rs/zeroize/1.9.2)
- Android Keystore can require user authentication for private-key/secret-key use; authorization and invalidation must be surfaced, not bypassed. [Android Keystore](https://developer.android.com/privacy-and-security/keystore)

## BLOCKER — crypto engine not implemented/verified

The Rust AES-GCM chunk engine, CSPRNG integration, asymmetric wrap adapter, file writer/fsync/rename protocol, authenticated journal seal, crash recovery, and crypto/tamper tests are **not yet implemented**. No dependency was added to the workspace without a generated and verified Cargo lock update. Rust/Cargo and Android build tooling are unavailable in this environment.

B4 remains **BLOCKED** at its critical exit gate. The committed files are contracts, not a completed Vault implementation. Dependent capture/Vault integration must not claim the B4 security gate has passed.
