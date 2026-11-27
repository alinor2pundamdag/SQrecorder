# System boundaries

## Ownership

| Layer | Owns | Must not own |
|---|---|---|
| KMP shared domain | semantic state, lifecycle rules, capability and workflow contracts | OS APIs, UI, direct audio-device access, secrets |
| Rust core | deterministic/bounded audio algorithms and portable processing | UI, Android lifecycle, filesystem authority, network |
| Native ABI | versioned C-compatible boundary, explicit ownership and status | language-specific objects crossing the boundary |
| Android adapter | AudioRecord, foreground-service policy, Android storage/Keystore integration | shared semantic policy duplicated ad hoc |
| Wear adapter | bounded quick-capture and remote-control integration | full editor/heavy processing |
| Windows adapter | WASAPI, filesystem and accelerator discovery | shared domain policy duplicated ad hoc |
| Evidence/data layer | durable file manifest and recovery journal | claims unsupported by durable records |
| UI | presentation, accessibility, user intent | capture-thread work, crypto key authority |

## Dependency direction

Platform adapters and app shells depend inward on shared contracts and native interfaces. Shared domain and Rust core remain platform-neutral. Native calls are versioned and bounded; no callback or pointer may outlive its documented ownership window.

## Capture invariants

- WAV is the authoritative source recording.
- Canonical PCM is 48 kHz mono S16LE; 44.1 kHz is the explicit fallback.
- Audio capture feeds a bounded queue and sequential writer; disk, inference, UI, and database work never block the capture callback.
- Queue pressure is surfaced as a controlled integrity event/stop, never a silent loss.
- Session lifecycle and integrity status are separate dimensions.
- Finalization is idempotent and journals observable discontinuities.
- Derived outputs are traceable and never overwrite source evidence.

## Scope exclusions

No screen recording or MediaProjection. No hidden microphone activation. No cloud dependency for core recording. These exclusions are architectural, not optional feature flags.


## Cross-platform target extension

The architecture covers Android/phone/tablet, Wear OS, iOS/iPadOS, watchOS, Windows, macOS, Linux, and Java/JVM integration. Shared KMP contracts and Rust portable logic do not replace native audio, permissions, lifecycle, key-storage, accessibility, or packaging adapters. Refer to [platform compatibility](platform-compatibility.md) and [SQVE v2 ADR](../decisions/0002-cross-platform-sqve-v2.md).

Vault bytes and journals are designed for portable formats; hardware-bound wrapping keys remain provider/device-bound. Explicit authenticated recipient rewrap is required for device transfer. Feature/security capability gaps must be reported rather than silently downgraded.
