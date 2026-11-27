# B5 native bounded PCM ingress — implementation slice

## Implemented
- Added `core/native-abi/src/bounded_capture.rs` and `core/native-abi/src/capture_ffi.rs`; the safe queue is exported through an operational C ABI handle/lifecycle and PCM ingress/egress API.
- Queue capacity and each slot's PCM storage are allocated at construction; submissions copy into fixed slots and do not grow queue storage. Aggregate queue allocation is capped at 8 MiB (also bounded per-block and by slot count).
- Validates supported rate (48 kHz/44.1 kHz), mono S16, frame/payload agreement, and block capacity.
- Queue overflow and producer lock contention fail closed, expose a terminal failure/integrity flag, and never silently overwrite/drop. The producer uses `try_lock` so it does not wait behind the consumer; contention is a controlled integrity failure.
- Stop transition requires draining queued PCM before terminal `Stopped`.
- Unit tests cover FIFO payload integrity, overflow fail-closed behavior, invalid payload shape, drain-before-stop, and rejection of configurations exceeding the memory budget.
- Exact-head verification on PR head `9200621807e4eb22c0106a8058cfa073e93cc591` (2026-11-27): Rust contract Run #72 (`45996507523`) **PASS** — lockfile metadata, rustfmt, workspace tests, and Clippy. Android Vault contract Run #97 (`45996507513`) **PASS** — JDK/SDK/Gradle setup, pinned Rust Android targets, 16 KB-aligned JNI libraries, Vault adapter/host contracts, app assembly/unit tests, and API 36 emulator native Vault bridge. All reported job steps succeeded.

## Boundary / not yet complete
- C ABI v1 functions implement ABI info, create/start, validated PCM submit/read, bounded event push/read, request-stop, drained finish, state, and destroy. A fixed 64-entry metadata-only event ring preserves order; event overflow fails closed and requires event drain before successful finish. Header declarations and PCM/event round-trip tests are included.
- The Android PR #4 service remains a plaintext app-private prototype. This queue does not make that service production-secure.
- Exact current PR #5 head `9b5507ebf5da893741ad1207365cbfeea602b4a0`: Rust contract Run #92 (`46008909465`) **PASS** — lockfile, rustfmt, workspace tests (including C ABI lifecycle/PCM round-trip, producer-contention fail-closed, and slot-zeroization tests), and Clippy. Android Vault Run #117 (`46008909415`) is pending/queued at this checkpoint; do not mark its gate passed until its job result is returned. Physical-device gates remain outstanding.


## Current integration boundary

- C ABI is implemented and CI-tested, but there is no JNI capture bridge or Kotlin adapter wired into Android `AudioRecord` yet. The Android PR #4 service still writes plaintext app-private WAV directly and does not use this queue; this is a release-blocking security/integration gap.
- Canonical Rust WAV writing, authenticated Vault chunk encryption, SQJ event/checkpoint writes, durable-store promotion/reconciliation, capture-recovery UX, and crash/ENOSPC end-to-end tests remain open.
- Queue producer contention is explicitly fail-closed; this is not a measured real-time audio certification. Event ABI returns unsupported rather than pretending to persist events.

## Latest Android workflow status

- Android Vault contract Run #117 (`46008909415`) was cancelled before a job was provisioned on source head `9b5507ebf5da893741ad1207365cbfeea602b4a0`; it is **not a pass**.
- The earlier Android Run #97 passed on the earlier bounded-queue-only SHA, before the operational C ABI and contention/zeroization hardening. It is historical and does not validate this integrated source revision.
- Triggering a fresh Android contract run on the updated evidence/source commit is required before this B5 slice has a current Android CI attestation.

## Current exact-head verification — 2026-11-27

- PR #5 evidence/source head before this doc refresh: `a32c46dc69964582b81e7db9aa936f3ec7979a91`.
- Rust contract Run #95 (`46009272259`) passed on that exact commit: lockfile, rustfmt, full workspace tests, and Clippy.
- Android Vault Run #120 (`46009272161`) remains pending with no job provisioned in the latest poll; no Android acceptance is claimed. Earlier Run #117 was cancelled before provisioning.
- This documentation refresh creates a new commit and therefore requires its own exact-head Rust + Android workflow checks. The queue/C ABI implementation is not release-complete until that current CI is green and all remaining integration gates below are closed.

## Bounded event queue addition

- Added a preallocated 64-event metadata ring; it performs no heap allocation per event.
- C ABI event push/read now operate on the ring. Queue overflow is a terminal integrity failure, and finish requires both PCM blocks and events to be drained.
- Rust tests cover ordered event readback, event overflow fail-closed behavior, and the stop/drain contract. Exact-head CI for this latest event implementation is pending; earlier Run #100 does not include this event-queue commit.
