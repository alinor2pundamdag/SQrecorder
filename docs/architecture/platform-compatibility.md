# Platform compatibility and capability contract

SQRecorder is designed for multiple installable platform shells around one portable audio/evidence core. “Compatible” means a tested build and explicit capability behavior for a declared OS/device target—not that every OS exposes identical APIs or permits identical background behavior.

## Target tiers

| Target | Application shell / integration | Core path | Required acceptance evidence |
|---|---|---|---|
| Android phones/tablets | Kotlin/KMP + Android native audio, lifecycle, storage and Keystore adapters | Rust ABI for supported Android ABIs | API-level CI, emulator contract tests, physical-device audio/auth/Keystore and 16 KB page tests |
| Wear OS | Dedicated Wear OS shell; bounded quick capture and remote controls | Shared domain + Rust where ABI/RAM/battery budgets permit | Watch-specific lifecycle, audio route, battery and storage tests; companion integration |
| iPhone/iPad | KMP shared domain with Swift/native UI and AVFoundation, Keychain/Secure Enclave adapters | Rust Apple targets via stable C ABI | macOS-hosted Apple compile, simulator tests, signed physical-device test, background/audio policy tests |
| watchOS | Companion/watch-specific UI and capture contract; do not assume iOS APIs or runtime limits are identical | Shared semantic contracts; Rust only after size/performance validation | watchOS compile/simulator and supported-device tests; explicit reduced-feature profile |
| Windows | JVM/KMP or native shell as selected by product packaging; WASAPI, filesystem and CNG/TPM adapter | Rust Windows target(s), versioned ABI | Windows CI build/test, audio-device and installer/signing tests, TPM optional-capability tests |
| macOS | Native/JVM shell and CoreAudio, Keychain/Secure Enclave integration | Rust Apple target | macOS CI, signing/notarization, audio and key-provider tests |
| Linux | JVM/native shell and ALSA/PipeWire adapter | Rust Linux target | distro/architecture build matrix, audio permissions, packaging and key-provider tests |
| Java/JVM integrations | Published JVM API with stable semantic types; no Android-only classes in common/JVM API | Rust JNI or supported native loader per JVM OS/architecture | Java API compatibility, JVM version matrix, native library loading and lifecycle tests |

## Layering rules

- `commonMain`: domain/session state, serialized contracts, capability negotiation, validation, state machines. No platform API imports.
- `rust`: deterministic PCM, DSP, vault primitives, journal, durable-store protocol, recovery and format validation. No UI, OS key store, or lifecycle assumptions.
- Platform source sets/adapters: microphone permission, foreground/background policy, audio route/device, filesystem sandbox, key storage/authentication, app lifecycle, accessibility, notifications, native loading and UI.
- Stable C ABI: explicit version/size/status, fixed-width types, bounded buffers, documented ownership; no Kotlin/Swift/Java object pointers cross the boundary.
- Feature availability is computed from a runtime capability record. Never infer hardware-backed key protection from brand/model alone.
- Shared UI may be used where mature and accessible; native shell/interoperability remains an allowed path. Avoid forcing watch UI through phone/desktop layouts.

## Security and portability

- Vault files/journals are format-portable; hardware-protected wrapping keys are normally device/account/provider-bound.
- Cross-device access requires an explicit authenticated transfer/rewrap or separately provisioned recipient record. Never copy a private hardware key.
- A platform that cannot meet a required security or capture capability reports unsupported and preserves data; it does not silently downgrade encryption or integrity.
- The same golden vectors and adversarial tests run against every provider. OS-specific tests supplement—not replace—the portable Rust contract tests.

## Support-status policy

A target is not “supported” merely because source code compiles. Publish target status as: **planned**, **build verified**, **CI tested**, **physical-device verified**, or **production supported**. Each release must link the exact OS/architecture, CI run, and device evidence. The shared domain Gradle target declarations now include JVM, Android, Linux x64, Windows MinGW x64, iOS arm64/simulator, macOS arm64, and watchOS device/simulator. These are compile targets, not completed platform apps. The new CI matrix must pass before any target is marked build-verified; physical and production status remains separate.
