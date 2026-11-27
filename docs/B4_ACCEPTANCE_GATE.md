# B4 — Journal, Vault, and durable recovery acceptance gate

Status: **BLOCKED / NOT ACCEPTED**. Rust B4 foundation is implemented and exact-head CI verified; remaining acceptance requires the approved Android/KMP baseline and end-to-end platform/device evidence.

## Exact source verification — PASS
- Source SHA: `81d0c45ed02401a67f40d9c994b89fc124642b43`
- GitHub Actions **Run #51** (`45954763730`): **SUCCESS**
- Passed: strict rustfmt; locked workspace check; all workspace tests.
- This verifies the Rust source SHA above. It is not Android/device acceptance.

## B4-R implemented
- AES-256-GCM envelope, random per-file DEK/nonce, AAD authentication, zeroization, platform wrapping boundary.
- Durable stage write/sync/verify/rename/parent-sync/journal callback with explicit pending/unknown outcomes.
- Non-destructive staged-file discovery and filesystem/journal reconciliation decision.
- Fault injection for partial write, simulated ENOSPC, file sync, rename, parent sync, and journal failure.
- Journal append/hash-chain verification; partial-write/sync failure latches writer terminal.
- Duplicate-key scanner now correctly traverses nested objects and compares decoded escaped keys.
- Payload bytes are enforced as RFC 8785/JCS canonical JSON using pinned `serde_json_canonicalizer 0.3.2`; writer and recovery verifier reject noncanonical bytes.
- Writer can resume sequence, digest, and monotonic timestamp only from a fully verified intact journal; damaged/truncated tails return recovery-required and are never appended in place.
- Rust toolchain/Cargo.lock locked; roadmap + RTM maintained.

## Remaining B4 acceptance
- Restore/create the approved Android/KMP baseline; implement platform integration and run its compile/security tests.
- Complete platform journal/session/filesystem reconciliation and crash-cut recovery tests.
- Verify Keystore auth-bound unwrap, locked decrypt denial, invalidation/rotation/recovery behavior.
- Run device storage-pressure/ENOSPC, lifecycle, vault and security review; record exact device/API evidence.
- Complete RTM evidence and acceptance sign-off.

## Architecture guard
Locked blueprint decisions remain unchanged. B4 stays blocked until platform, security, journal/recovery and device gates pass. Keep PR draft/unmerged; do not infer 100% acceptance from Rust CI.
