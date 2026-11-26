# Capability manifest v1 and runtime selection

## Manifest authority

Tool manifests are immutable, versioned artifacts. Canonical serialization is UTF-8 JSON using RFC 8785 (JCS); digest is SHA-256 over canonical bytes, and publisher signature verification is performed by the trusted manifest verifier before selection. A digest alone is not publisher authenticity.

A manifest declares:

- namespaced immutable tool ID and semantic API version
- engine minimum and native ABI major
- immutable algorithm revision
- supported platform IDs, input/output formats, required features
- provider IDs, execution class, and quality/resource profiles
- canonical digest and publisher signature metadata

A tool ID is never repurposed. API-breaking changes require a major version; algorithm changes receive a new immutable revision. Model artifacts are separate manifests and are referenced by immutable model ID/version/digest.

## Runtime discovery and selection

The selector requires verified trust, valid schema, compatible API major/minimum version, exact ABI major, platform, input/output format, requested features, and a provider actually discovered at runtime. Provider availability is not inferred from device marketing/model names.

Profiles are filtered against verified installed model references and current observed memory/storage. Estimates are advisory ranking/resource hints, not global hardware ceilings. There is no hard-coded device tier or arbitrary support cap.

Ranking is deterministic:
- quality-first: higher quality rank, then lower latency, then lower energy estimate
- latency-first: lower latency, then quality, then energy
- energy-first: lower energy, then quality, then latency

Non-realtime work is deferred during active capture. Critical thermal state defers non-realtime selection. Selection records tool/API/revision, manifest digest, profile, model, provider, and ABI so processing provenance can be reproduced.

## Trust failure

Invalid signatures, unknown publishers, digest mismatch, unsupported schema, incompatible ABI, or unavailable runtime requirements fail closed. Do not silently select an unverified manifest or substitute a different model without recording the choice.
