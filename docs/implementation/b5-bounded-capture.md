# B5 native bounded PCM ingress — implementation slice

## Implemented
- Added `core/native-abi/src/bounded_capture.rs` and exported its safe Rust API from the native ABI crate.
- Queue capacity and each slot's PCM storage are allocated at construction; submissions copy into fixed slots and do not grow queue storage. Aggregate queue allocation is capped at 8 MiB (also bounded per-block and by slot count).
- Validates supported rate (48 kHz/44.1 kHz), mono S16, frame/payload agreement, and block capacity.
- Queue overflow transitions to terminal `Failed` and records an explicit integrity-overflow flag. Subsequent submission is rejected; no silent overwrite/drop.
- Stop transition requires draining queued PCM before terminal `Stopped`.
- Unit tests cover FIFO payload integrity, overflow fail-closed behavior, invalid payload shape, drain-before-stop, and rejection of configurations exceeding the memory budget.
- Exact-head verification on PR head `9200621807e4eb22c0106a8058cfa073e93cc591` (2026-11-27): Rust contract Run #72 (`45996507523`) **PASS** — lockfile metadata, rustfmt, workspace tests, and Clippy. Android Vault contract Run #97 (`45996507513`) **PASS** — JDK/SDK/Gradle setup, pinned Rust Android targets, 16 KB-aligned JNI libraries, Vault adapter/host contracts, app assembly/unit tests, and API 36 emulator native Vault bridge. All reported job steps succeeded.

## Boundary / not yet complete
- This is a **safe Rust queue core**, not yet exported as operational C ABI functions nor connected to Android AudioRecord/JNI, Rust canonical WAV, Vault chunk encryption, SQJ journal, durable-store promotion, or crash recovery.
- The Android PR #4 service remains a plaintext app-private prototype. This queue does not make that service production-secure.
- CI passed for the code head listed above. This documentation-only evidence update does not alter Rust or Android source; confirm the resulting branch head and its check association before treating it as final evidence. Physical-device gates remain outstanding.
