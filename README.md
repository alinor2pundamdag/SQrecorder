# SQRecorder

**SQRecorder** is an offline-first audio/voice recorder and evidence-preserving audio workflow project. Its scope is audio capture and audio processing—not screen recording. Cloud services are not required for core capture.

## Architecture

- **Kotlin Multiplatform (KMP):** platform-independent domain, Vault v1/v2 metadata, lifecycle, and workflow contracts. The shared capability selector is a compiled Gradle module (not an orphan source tree).
- **Rust:** portable, performance-sensitive audio and processing core behind a versioned C ABI.
- **Platform adapters:** Android, Wear OS, iOS/iPadOS, watchOS, Windows, macOS, and Linux own OS-specific capture, lifecycle, storage, secure-key, accessibility, and UI integration. Java/JVM integrations use a deliberate JVM API rather than Android-only APIs.
- **Cross-platform Vault (LOCKED):** SQVE v2 is the sole current encrypted-write/capture-finalization target. SQVE v1 is immutable legacy read/verification compatibility only; no new V1 writes or downgrade. V2 production use remains gated on canonical wire schema, golden vectors, provider conformance, and independent security review. See [platform compatibility](docs/architecture/platform-compatibility.md), [ADR 0002](docs/decisions/0002-cross-platform-sqve-v2.md), and [SQVE v2 design](docs/security/sqve-v2-envelope-design.md).
- **Evidence authority:** finalized source WAV, integrity metadata, and append-only session journal; derived media never silently replaces source evidence.

Platform code must not leak into shared domain or Rust core. The core must not depend on UI frameworks or platform services.

## Locked capture baseline

- Primary capture container: WAV.
- Canonical PCM: 48 kHz, mono, signed 16-bit little-endian; 44.1 kHz is the explicit compatibility fallback.
- Original capture is finalized and integrity-recorded before optional derived export.
- No screen capture, no MediaProjection, and no hidden microphone auto-start.

See [architecture boundaries](docs/architecture/system-boundaries.md), [decision record](docs/decisions/0001-stack-and-boundaries.md), and [batch roadmap](docs/implementation/batch-roadmap.md).

## Repository status

This repository is being built in auditable batches. The B1 commit establishes the repository and build baseline only; it does not claim recording, Vault, DSP, platform integration, or runtime acceptance are implemented.

## Build prerequisites

- JDK 17 or newer (the selected Gradle distribution's runtime requirement must be met).
- Gradle 9.7.0 for the initial Kotlin build baseline.
- Rust toolchain pinned in `rust-toolchain.toml`.

The Gradle wrapper JAR and launch scripts are not checked in until they can be sourced and checksum-verified from the official distribution. Do not generate or trust wrapper binaries from unverified sources.

## Security

Never commit credentials, signing keys, local configuration, user recordings, or decrypted Vault material. Keep secrets in local environment/secret stores. See [security baseline](docs/security/baseline.md).
