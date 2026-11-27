# B4 — Journal, Vault, and durable recovery acceptance gate

Status: **BLOCKED / NOT ACCEPTED**. A green journal test is not full B4.

## Implemented in this branch — pending CI verification
- `core/vault-core`: AES-256-GCM encrypted envelope, random per-file DEK and nonce, AAD authentication, wrapped-DEK interface, zeroization, tamper tests.
- `core/durable-store`: staged write, file sync, staged validation, atomic rename, parent sync, journal callback after promotion, non-destructive recovery inspection, basic tests.
- CI now compiles and tests all workspace crates and checks formatting.

## Remaining blockers
- DekWrapper is an interface only. Android Keystore, auth-bound unwrap, key invalidation/rotation/recovery, and device tests are not implemented.
- Test XOR key wrapper is test-only and is NOT production key custody.
- Fault injection still needed for ENOSPC, short writes, sync/rename failures and crash points.
- Cargo.lock is not committed; locked reproducible CI remains pending.
- Journal canonical JSON enforcement and full journal/session/database reconciliation remain pending.
- No full B4 acceptance or Android platform evidence yet.

B4 remains blocked until security review, comprehensive fault tests, lockfile/locked CI, and Android Keystore/auth/device evidence pass at exact HEAD. Do not start B5 on assumption of acceptance.
