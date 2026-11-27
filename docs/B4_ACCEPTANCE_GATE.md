# B4 — Journal, Vault, and durable recovery acceptance gate

Status: **BLOCKED / NOT ACCEPTED**. A green journal test is not full B4.

## Implemented in this branch — pending CI verification
- Vault DEK is now guarded by `Zeroizing` so early errors do not bypass explicit clearing.
- Durable promotion returns a distinct `JournalCommitPending` state when file+directory durability succeeded but journal commit failed; callers must reconcile rather than report success.
- CI toolchain pinned to Rust 1.85.1; verification runs are no longer cancelled by same-branch concurrency.
- CI generates Cargo.lock for the run and uses `--locked`; the tracked-lock check intentionally blocks acceptance until Cargo.lock is committed.
- `core/vault-core`: AES-256-GCM encrypted envelope, random per-file DEK and nonce, AAD authentication, wrapped-DEK interface, zeroization, tamper tests.
- `core/durable-store`: staged write, file sync, staged validation, atomic rename, parent sync, journal callback after promotion, non-destructive recovery inspection, basic tests.
- CI now compiles and tests all workspace crates and checks formatting.

## Remaining blockers
- **Plan gap surfaced:** this repository branch contains only the Rust workspace and no Android/KMP Gradle module or Android source set. A real Android Keystore adapter cannot be added safely into a nonexistent platform module. The Rust contract remains an interface; auth-bound unwrap, key invalidation/rotation/recovery, and device tests are not implemented.
- The plan must explicitly include an Android/KMP platform integration subtask (without changing locked capture/splash/vault architecture) before production Vault acceptance.
- Test XOR key wrapper is test-only and is NOT production key custody.
- Fault injection still needed for ENOSPC, short writes, sync/rename failures and crash points. Journal callback failure now has an explicit pending-reconciliation error and regression test.
- Cargo.lock is not committed; locked reproducible CI remains pending. Toolchain is pinned, but dependency resolution is not fully reproducible until the generated lockfile is checked in.
- Journal canonical JSON enforcement and full journal/session/database reconciliation remain pending.
- No full B4 acceptance or Android platform evidence yet.

B4 remains blocked until security review, comprehensive fault tests, committed lockfile/locked CI, journal/session reconciliation, and Android Keystore/auth/device evidence pass at exact HEAD. Do not start dependent B5 capture integration on assumption of acceptance.

## Plan integrity / architecture guard
The Keystore adapter is a missing implementation layer, not permission to change the approved Vault design. Keep auth-bound Android Keystore custody, per-file random AES-256 DEK, AES-GCM, offline-first behavior, and locked Quick Capture semantics. Any deviation requires a separate blueprint decision and user approval.
