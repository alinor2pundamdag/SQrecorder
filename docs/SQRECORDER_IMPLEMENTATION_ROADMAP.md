# SQRecorder Implementation Roadmap & Acceptance Traceability

Status: working roadmap for the existing SQRecorder Premium Master Blueprint v4.0 and locked architecture decisions recorded in project history.

This document organizes implementation and verification. It does not replace, relax, or silently modify the blueprint. Any proposal that changes a locked decision must be recorded as a separate change request with impact analysis and explicit user approval before implementation.

## Planning terminology
- **Product/technical roadmap:** sequencing approved features and dependencies across batches.
- **Requirements traceability matrix (RTM):** mapping each blueprint requirement to implementation location, batch, test/evidence, and acceptance status.
- **Acceptance gate:** a release/batch checklist deciding whether evidence is sufficient to call a batch accepted.
- **Change control:** documenting proposed deviation, affected locked decisions, risk, migration, rollback, and approval before changing scope.

## Locked architecture — preserved
- Audio/voice recorder only; no screen recording.
- KMP owns semantic/session state; platform adapters own native capabilities.
- Rust core owns deterministic low-level journal, cryptographic primitives, and durability mechanisms.
- WAV primary capture at 48 kHz mono S16 PCM; 44.1 kHz fallback.
- Offline-first, crash-safe, evidence-safe, bounded/preallocated audio queues; overflow is a controlled stop plus journal incident, never a silent drop.
- Lifecycle and Integrity remain orthogonal.
- Vault uses per-file random AES-256 DEK, authenticated encryption, and platform Keystore-bound wrapping; locked Quick Capture is encrypt-only, while playback/export/decrypt require authentication.
- Finalization remains idempotent; hash and journal evidence retained.
- Splash contract remains pre-rendered 7 s / 60 fps silent H.264 MP4 with native MediaPlayer/SurfaceView adapter; no Rive, custom shader, or ExoPlayer.
- Platform, release signing, storage, privacy, and performance constraints remain as specified in the master blueprint.

## Traceability and batch sequence

| Batch / work package | Blueprint scope | Implementation dependency | Required evidence | Acceptance status |
|---|---|---|---|---|
| B0 — repository audit | Repository structure, scope and contracts | Repository baseline | Inventory + architecture audit | Previously reported complete; retain original evidence |
| B1 — build foundation | KMP/Gradle/build scaffolding | Project baseline | Reproducible Android/KMP build, dependency and config checks | Previously PASS WITH LIMITATIONS; runtime acceptance still required |
| B2 — native ABI / PCM | Canonical PCM and native boundary | B1 + Rust toolchain/NDK | ABI tests, PCM golden tests, device capture checks | Prior CI evidence only; revalidate exact current tree |
| B3 — session lifecycle | KMP semantic state and lifecycle | B1/B2 | State-transition tests, lifecycle/device evidence | Runtime acceptance pending |
| B4 — integrity, journal, Vault and durability | Evidence journal, encryption, crash-safe file promotion and recovery | Rust core + actual platform adapter | Strict locked CI; crypto/tamper tests; journal continuity; crash/fault tests; Android Keystore auth/invalidation; recovery/device evidence | Rust foundation CI verified; full batch BLOCKED on platform integration and device acceptance |
| B5 — Android capture integration | Native microphone/capture pipeline and lifecycle integration | B1–B4 accepted interfaces | Android permission/lifecycle tests; 48 kHz/44.1 kHz behavior; bounded queue/overflow; real-device audio recordings | Not started/accepted on this GitHub implementation branch; do not claim complete |
| B6 — DSP/audio base | Approved DSP, VAD/voice focus and capture processing | B2/B5 stable audio stream | Deterministic DSP tests, VAD timing, quality/performance, thermal/battery tests | Existing prior work needs exact-tree and device revalidation |
| B7+ — remaining blueprint features | Features explicitly listed in blueprint | Their declared prerequisites | Per-feature RTM entry, tests, security/privacy/performance and acceptance evidence | Schedule only after dependencies; never infer scope |

Batch numbering above is a sequencing/traceability view, not permission to alter the locked feature plan. If existing canonical documents define a different batch boundary, preserve that definition and add a cross-reference rather than renumbering.

## B4 completion plan (no architecture change)

### B4-R — Rust core foundation (implemented)
- AES-256-GCM file envelope with version/magic and nonce.
- Random per-file DEK; guarded zeroization; AAD authenticated by the cipher.
- Platform DEK-wrapping interface; test-only XOR wrapper is explicitly not production.
- Durable stage → sync → verify → rename → parent sync → journal callback.
- Explicit states for journal-commit-pending and ambiguous directory-sync failure.
- Non-destructive recovery inspection and filesystem/journal reconciliation decision.
- Fault-injection coverage includes partial write, simulated ENOSPC, file-sync, rename, and parent-directory-sync failure.
- Reproducible workspace CI: pinned Rust toolchain, committed Cargo.lock, locked dependencies, strict rustfmt, SHA-pinned actions.

### B4-P — Android/KMP platform integration (required; not yet implemented)
The repository branch currently has no Android/KMP Gradle project/source set. Restore/create the real project baseline from the approved repository plan before placing Android implementation code. Do not fabricate a minimal replacement app or change package/architecture to make the gate appear green.

Implement within the approved design:
1. Keystore-backed wrapping key lifecycle and auth policy; no export of master key.
2. Auth-bound DEK unwrap for playback/export/decrypt.
3. Locked Quick Capture path permits encryption/wrapping only; no plaintext/decrypt capability.
4. Key invalidation, rotation, recovery, and loss behavior with explicit journal events and user-safe failure modes.
5. Platform durable-store/journal adapter with correct filesystem guarantees.
6. Session/journal reconciliation at startup and after promotion/journal failure.
7. Android 16 KB page compliance and supported API/device checks where relevant.

### B4-A — final acceptance gate
- [ ] Rust strict CI green on the exact PR head SHA.
- [ ] Android/KMP project baseline and adapter compile.
- [ ] Keystore auth-bound unwrap tests; locked-state decrypt denial.
- [ ] Key invalidation/rotation/recovery tests and documented failure behavior.
- [ ] Journal schema/digest/duplicate-key/continuity tests.
- [ ] Crash-cut tests at stage write, file sync, verification, rename, directory sync, and journal commit.
- [ ] ENOSPC and storage-pressure test; no silent evidence loss.
- [ ] Recovery idempotency and preservation of ambiguous artifacts.
- [ ] Real-device capture/vault/lifecycle tests; security review.
- [ ] RTM and acceptance record reference exact commit, CI run, device/model/API, test result, known limitations.
- [ ] Only then mark B4 accepted and allow dependent batch acceptance.

## Evidence record format
For each requirement, record:
- Blueprint section / requirement ID
- Batch and dependency
- Source path + commit SHA
- Test name and command
- CI run URL/ID and result
- Device/OS/API evidence when applicable
- Failure modes tested
- Known limitations / waiver (if any)
- Acceptance owner and date

A CI pass for Rust is not evidence of Android Keystore, microphone, lifecycle, device durability, or release-signing acceptance.

## Change-control rule
If a needed fix preserves the locked design, implement it and record the evidence. If a fix would change a locked architecture decision, pause that specific change, explain the conflict and options, and request approval. Do not silently drop a planned feature, change the splash/capture/Vault contract, or call an unimplemented feature accepted.
