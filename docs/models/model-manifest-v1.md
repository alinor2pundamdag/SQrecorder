# Model artifact manifest v1

A model manifest binds immutable model ID/version to:

- exact artifact byte length and SHA-256
- license identifier and source/provenance
- runtime API and minimum engine version
- publisher key ID and detached signature

The manifest must be verified before installation. A hash checks artifact integrity; the publisher signature authenticates the manifest and its digest. Unknown publishers or signature/digest failures are rejected, not treated as warnings.

## Install protocol

- Require at least **2 × artifact size** free space for staging, verification, and atomic promotion.
- Download/write only to a temporary staging path; verify exact byte length and SHA-256, then signature/provenance and runtime compatibility.
- Promote atomically only after verification; never expose partial artifacts as installed.
- On interrupted installation, delete the partial artifact and restart from a clean staging file.
- Preserve the previous verified model until the replacement is fully verified and promoted.
- The registry stores immutable model reference, digest, license, provenance, runtime compatibility, and installation state.

Core model discovery/selection is offline. No cloud service is required for recording or for using already-installed models.
