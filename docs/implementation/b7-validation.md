# B7 validation record

## Implemented

- KMP capability manifest model and structural validation for immutable tool IDs, semantic API/engine versions, ABI, formats, features, providers, profiles, and SHA-256 digest syntax.
- Runtime selector requires verified trust, ABI/API/platform/format/feature compatibility, discovered providers, installed model refs, and observed resource availability.
- Deterministic quality/latency/energy profile ranking; no device-tier or arbitrary global model ceiling.
- Non-realtime work is deferred during active capture and under critical thermal state.
- Selection output captures manifest digest, tool/API/algorithm revision, model/profile/provider, and ABI for provenance.
- Model manifest contract covers artifact size/hash, license/provenance, runtime compatibility, publisher/signature metadata.
- Install planner requires 2× artifact size free, rejects size overflow/untrusted manifests, reuses only digest-verified installs, and schedules partial cleanup/restart.
- Added common tests for trust/ABI filtering, profile selection, capture deferral, 2× storage, interrupted partials, and overflow.

## Not run

Kotlin/Gradle tests and model signature/hash verification were not run. This commit contains selector/planner contracts, not a downloader, cryptographic verifier, or filesystem installer. Those require verified crypto/storage backends and a build-capable environment.
