# B4 — Journal, Vault, and durable recovery acceptance gate

Status: **BLOCKED / NOT ACCEPTED**. Rust foundation is verified; full B4 acceptance is not.

## Latest exact-head verification — PASS
- PR #1 head: `6df129392cdb83871123e5a7c4bf5baa17bd5082`
- GitHub Actions Run **#39** (`45952859449`): **SUCCESS**
- Passed jobs: workspace compile + journal/Vault/durability tests; Rust formatting.
- Run #39 validates this exact head. It does not validate Android/device behavior.

## Implemented
- AES-256-GCM envelope; random per-file DEK and nonce; caller AAD; DEK zeroization; platform wrapping boundary.
- Durable stage write, file sync, validation, atomic promotion, parent sync, journal callback; explicit journal-pending and durability-unknown outcomes.
- Non-destructive recovery inspection and deterministic stage-file discovery; regular matching files only, symlinks/unrelated files excluded.
- Fault-injection coverage for partial write, simulated ENOSPC, file-sync, rename, parent-sync, and journal failure.
- Reproducible locked Rust CI; roadmap and RTM documented.

## Remaining B4 work
- Restore/create the approved Android/KMP project baseline, then implement and verify the approved Android security/platform path.
- Complete canonical journal validation and end-to-end journal/session/filesystem reconciliation.
- Add crash-cut and real-device storage-pressure/recovery evidence; preserve ambiguous artifacts and prevent silent evidence loss.
- Complete security review and final acceptance evidence matrix.

## Architecture guard
No locked blueprint decision changed. Keep the approved per-file AES-256 DEK/AES-GCM, authenticated Keystore custody, offline-first behavior, and locked Quick Capture semantics. Any proposed deviation requires explicit change control.

B4 stays blocked until all required platform, journal/recovery, security, and device gates pass. Do not claim acceptance from Rust CI alone.
