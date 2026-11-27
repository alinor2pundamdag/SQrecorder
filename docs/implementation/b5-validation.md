# Android B5 — capture adapter and service

## Source slice
- Native Android app module: `:android:app`, application ID `com.alinor.sqrecorder`, target SDK 36, min SDK 23.
- Explicit Start UI requests microphone permission; capture is not auto-started.
- Microphone capture runs in a foreground service with declared `microphone` type and persistent Stop notification action.
- `AudioRecord` chooses 48 kHz mono PCM16 first, then attempts 44.1 kHz if the first recorder cannot initialize.
- Writes app-private `files/recordings/*.wav.part`; finalizes RIFF sizes, fsyncs file, and only then renames to `.wav`. Failure retains a partial recovery artifact and never reports successful finalization.
- Controlled low-storage stop begins at 50 MiB available.
- WAV header isolated and unit-tested for format/rate/length boundaries.
- Android CI now assembles the app and runs its JVM unit tests alongside Vault/JNI/API 36 emulator checks.

## Security / correctness boundary
- No external storage permission, cloud upload, screen capture, hidden microphone start, or plaintext public export.
- This slice records plaintext in app-private storage. It is **not yet Vault-encrypted**, journaled, or integrated with the Rust durable-store/recovery protocol; do not call these files finalized evidence recordings for production.
- Stop is cooperative at the next blocking read boundary. Force-stop, process death, power loss, and ENOSPC still require crash-cut recovery tests and integration with the existing journal/durable-store.
- Physical Android tests are not run in this environment.

## Verification

- Latest Android app branch head includes shared `SessionLifecycle` reducer integration. Exact-head CI Run #86 was started and Run #87 queued after this implementation commit; verify Run #87 before marking this source compiled.
- Source branch: `android-b5-capture`, forked from verified B4 SHA `6759dce49c2bd13ee4665560833e5d5d6492e23a`.
- **CI pending:** PR CI must compile `:android:app:assembleDebug`, pass `:android:app:testDebugUnitTest`, and rerun native 16 KB/JNI + API 36 emulator tests on this exact branch head.
- No physical-device pass or B5 completion is claimed.

## Remaining B5/B8 gates
1. SessionLifecycle reducer, capture epoch, monotonic timestamps, stop/finalization events are now wired in-memory. Remaining: durable SQJ journal integration and integrity incidents for input overrun, route changes, permission revocation, and storage pressure.
2. Replace standalone file output with bounded PCM pipeline → Rust canonical WAV writer → durable-store staging/promotion + SQJ journal; prove no silent loss.
3. Add idempotent stop/finalization, file integrity hash, crash recovery scan, partial artifact recovery UI, and fault-injection tests.
4. Add device matrix for API 23 minimum, API 34+ foreground permission restrictions, API 36 target behavior, wired/Bluetooth route changes, interruption, reboot/force-stop and ENOSPC.
5. Physical-device acceptance: actual mic capture, background recording notification, WAV decode/metadata, lifecycle/thermal/storage limits, and hardware-backed Vault/key policy.
6. App integration B8: recording list/detail, settings/capability state, session journal and Vault lifecycle, accessibility, error surfaces, and release packaging/signing.
