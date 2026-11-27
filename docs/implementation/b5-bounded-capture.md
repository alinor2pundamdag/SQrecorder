# B5 native bounded PCM ingress — implementation slice

## Implemented
- Added `core/native-abi/src/bounded_capture.rs` and exported its safe Rust API from the native ABI crate.
- Queue capacity and each slot's PCM storage are allocated at construction; submissions copy into fixed slots and do not grow queue storage.
- Validates supported rate (48 kHz/44.1 kHz), mono S16, frame/payload agreement, and block capacity.
- Queue overflow transitions to terminal `Failed` and records an explicit integrity-overflow flag. Subsequent submission is rejected; no silent overwrite/drop.
- Stop transition requires draining queued PCM before terminal `Stopped`.
- Unit tests cover FIFO payload integrity, overflow fail-closed behavior, invalid payload shape, and drain-before-stop.

## Boundary / not yet complete
- This is a **safe Rust queue core**, not yet exported as operational C ABI functions nor connected to Android AudioRecord/JNI, Rust canonical WAV, Vault chunk encryption, SQJ journal, durable-store promotion, or crash recovery.
- The Android PR #4 service remains a plaintext app-private prototype. This queue does not make that service production-secure.
- CI and exact-head tests must pass before treating this slice as verified. Physical-device gates remain outstanding.
