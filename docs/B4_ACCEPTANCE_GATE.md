# B4 — Journal, Vault, and durable recovery acceptance gate

Status: **BLOCKED / NOT ACCEPTED**. This document is the single B4 evidence gate; a green journal test alone is not full B4.

## Required scope

### 1. Journal integrity
- Versioned, bounded, append-only record format; explicit byte layout and digest domain.
- Strict schema/event-type binding, monotonic sequence and timestamp checks.
- Duplicate JSON object keys rejected before semantic decoding (including escaped-equivalent keys).
- Canonical payload representation is enforced, not merely assumed from the caller.
- SHA-256 chain verification, valid-prefix reporting, non-destructive truncated-tail detection.
- Sink write/sync failures latch the writer terminal; recovery owns partial-tail handling.
- Tests cover malformed framing, payload limits, duplicate/escaped keys, digest and previous-link tampering, timestamp/sequence regressions, partial write, sync failure, and restart/recovery.

### 2. Vault lifecycle
- Per-file random DEK; AES-256-GCM authenticated encryption with unique nonce per key.
- DEK wrapped by a Keystore-backed master key; key version and algorithm metadata persisted.
- Authentication-bound unwrap/decrypt; lock, timeout, cancellation, auth failure, key invalidation and restore paths defined.
- Quick Capture while locked is encrypt-only; no plaintext fallback, key export, or plaintext temporary files.
- AAD binds stable file/session identity and immutable metadata; tamper and wrong-key tests fail closed.
- Key generation/wrapping/rotation/recovery state machine has crash-safe transitions and no orphaned plaintext.

### 3. Durability and recovery
- Stage -> write -> flush/sync -> atomic promotion -> directory sync where supported -> journal commit.
- Idempotent recovery for every crash point; never overwrite a valid final artifact with incomplete data.
- File/database/journal reconciliation and explicit recovery incidents; no silent deletion or false “finalized” state.
- Fault-injection tests for short write, ENOSPC, sync failure, rename failure, process death, and interrupted encryption/finalization.

### 4. Acceptance evidence
- Reproducible workspace build and committed dependency lockfile.
- CI compile, formatting, unit/integration tests, and security-focused tests on the exact HEAD.
- Static audit of crypto choices, nonce lifecycle, key custody, filesystem semantics, concurrency, and error propagation.
- Platform integration tests for Android Keystore/auth and real filesystem durability; synthetic data only.
- Each acceptance claim cites the exact commit and passing CI/device evidence.

## Current verified repository gap (2026-11-27)
- Journal implementation exists at `core/session-journal/src/lib.rs`.
- Root Cargo workspace, journal crate manifest, and a journal CI workflow have now been added.
- Current repo tree previously contained no Vault module, persistence/recovery module, lockfile, or CI workflow. These remain implementation blockers.
- CI execution has not yet been observed for the latest commits; connector-authored pushes may not dispatch Actions. Do not treat missing run/status as pass.

## Release rule
B4 remains blocked until every section above is implemented and verified. B5 Android capture integration must not begin on the assumption that B4 passed.
