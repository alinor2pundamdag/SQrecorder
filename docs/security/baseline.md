# Security baseline

- Do not store credentials, signing keys, access tokens, or private user data in source control.
- Use environment variables or a managed secret store for local/CI secrets; provide only non-secret examples in tracked files.
- Validate all untrusted lengths, versions, paths, and serialized inputs at boundaries.
- Prefer least privilege and explicit permission checks; do not infer a capability from a device model or API level alone.
- Capture and evidence paths must fail closed on integrity, storage, and key errors; preserve recoverable data where possible.
- Keep logs useful for diagnosis but exclude audio content, key material, authentication tokens, and unnecessary personal data.
- Dependency and toolchain versions are pinned; binary provenance and checksums are required before committing generated executables or wrapper artifacts.
