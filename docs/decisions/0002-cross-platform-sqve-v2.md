# ADR 0002: SQVE v2 — authoritative locked write format and cross-platform Vault

- **Status:** LOCKED TARGET — SQVE v2 is the authoritative format for all new encrypted capture/finalization and migration writes. V1 is legacy compatibility/read-only only. V2 production acceptance remains gated on canonical schema, executable golden vectors, provider conformance, and independent security review.
- **Date:** 2026-11-27
- **Authority:** Project owner explicitly approved option B (separately versioned SQVE v2) and the cross-platform compatibility goal in the SQRecorder project conversation.

## Context

The project owner has explicitly replaced the prior SQVE v1 lock with the SQVE v2 lock. This document is the repository's authoritative cross-model/contributor instruction for that version decision. Older B1/B4 notes describing V1 as the locked/current write format are superseded by this directive.


SQVE v1 fixes a non-empty RSA-OAEP label `SQREC-VAULT-DEK-v1`. Android Keystore's RSA-OAEP provider requires an empty `PSource.PSpecified` label for the supported operation and defaults MGF1 to SHA-1 unless a digest is explicitly configured (configurable MGF1 digests are available from API 35). Changing v1 in place would break interoperability and violate the locked format. SQRecorder must target more than Android: iOS/iPadOS, Wear OS and watchOS companions, Windows, macOS, Linux, and JVM/Java integrations are in scope, subject to OS/API/device constraints.

## Locked implementation directive

**SQVE v2 is the sole current write target.** New recordings, encrypted capture finalization, durable promotion, and migration output MUST use SQVE v2 after its conformance gates pass. SQVE v1 is retained only as immutable legacy read/verification compatibility; do not create new v1 files, use v1 as the finalization target, or silently downgrade. A V1 source remains preserved during migration until its distinct V2 staged output is fully verified and durably journaled.

## Decision

1. Preserve the historical SQVE v1 bytes and strict reader solely for existing-file compatibility; no new V1 writes.
2. Use SQVE v2 as the explicit, separately versioned current format with named cryptographic suite identifiers. No implicit format detection based only on successful decryption, no downgrade, and no rewriting of v1 files in place.
3. Use a platform-neutral envelope/chunk contract and platform-specific key-protection providers. The envelope supports one or more recipient/wrapping records so a user-authorized transfer can add a destination device's key without exporting a platform private key.
4. Bind all security-relevant envelope metadata (format, suite, file identity, key identifier, nonce parameters, wrapped DEK and recipient record) to a DEK-derived header authenticator and bind each chunk to the file identity, format, index, and lengths through AEAD associated data. Exact canonical encoding and HKDF/HMAC labels are fixed by the SQVE v2 implementation spec and golden vectors before code release.
5. Use a fresh random 256-bit DEK per file; AES-256-GCM with a 128-bit tag for chunks; a unique per-file nonce construction with monotonic chunk index and a hard pre-wrap limit. Never reuse a nonce under the same DEK.
6. Implement the same Rust portable core and C ABI on supported architectures. KMP owns shared semantic state and capability contracts; native adapters own OS permissions, lifecycle, UI/accessibility, secure-key APIs, audio devices, and file-provider integration.
7. Hardware-backed protection is a capability, not a universal guarantee. Platform providers report security level and limitations; they must fail closed for unsupported required operations, never silently downgrade.

## Migration

- Read v1 without mutation; authenticate and verify all chunks/journal before migration.
- Write v2 to a distinct staged destination, sync, verify, and atomically promote using the existing durable-store protocol.
- Keep the source v1 artifact until v2 verification and journal commit are durable.
- A failed migration leaves the source readable and discoverable; recovery never guesses or silently completes an unauthenticated migration.
- Device-to-device transfer is an authenticated, explicit rewrap/add-recipient operation. Private hardware keys never leave their OS key store.

## Required implementation gates

- Canonical binary schema and version/suite registry; reject unknown mandatory values.
- Cross-language/platform golden vectors for envelope, header MAC, chunk AAD, nonce derivation, wrap/unwrap, and migration.
- Negative tests for tampering, wrong file/key identity, malformed lengths, recipient mismatch, downgrade, truncation, nonce exhaustion, and corrupted chunk ordering.
- Provider conformance tests for Android Keystore, Apple Keychain/Secure Enclave where available, Windows CNG/TPM where available, JVM/software provider, and Rust test provider.
- Independent cryptographic review before production acceptance.

## Non-goals

- Do not promise identical hardware security, background recording policy, or feature availability on every OS/device.
- Do not export raw private keys or plaintext DEKs in logs, crash reports, or public APIs.
- Do not change SQVE v1 constants or existing v1 ciphertext.
