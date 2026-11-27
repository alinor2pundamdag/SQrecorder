# Android release-signing continuity (non-negotiable)

## Goal
An installed SQRecorder must receive future updates in place, preserving app data. Android accepts an update only when the application ID and signing identity remain compatible. A signature mismatch is not repairable by app code and ordinarily requires uninstall/reinstall, risking local recordings and vault state.

## Permanent signing identity
- Treat the Android app-signing certificate/private key as a long-lived release identity, not a per-build artifact.
- Never generate a fresh release key for each version or CI run.
- Keep the release private key outside Git, source archives, APK/AAB assets, and the application runtime. Use a protected offline/controlled signing workstation or approved signing service.
- Maintain at least two encrypted, independently stored backups of the keystore and a separately secured record of alias/password recovery. Test restoration periodically without exposing credentials.
- Restrict release signing access; audit who signs which version. Store only non-secret certificate fingerprints and signing metadata in repository/release records.
- Pin the expected release certificate SHA-256 fingerprint in release verification. Verify package ID, version, signer certificate, and artifact integrity before publishing.

## Google Play versus direct APK distribution
- For Google Play, enable Play App Signing and preserve the Play-managed app-signing-key continuity. The upload key authenticates uploads; it is not the certificate Android users see. Upload-key reset/rotation must not be confused with app-signing-key replacement.
- For direct/sideload distribution, every upgrade APK must use the same retained app-signing private key/certificate as the installed release.
- Do not change application ID (com.alinor.sqrecorder) for a normal upgrade. A new ID is a separate app installation.
- Key rotation is not routine. Use only a platform-supported signing-key upgrade path after documenting OS compatibility and validating upgrades from every supported installed version.

## Mandatory release gate
1. Build the release artifact using the controlled signing path; secrets come from protected environment/secret storage, never source literals.
2. Inspect artifact signer and compare its certificate fingerprint against the approved identity / Play Console configuration.
3. Verify application ID and upgrade compatibility.
4. Install the prior signed release on a test device, then install the candidate over it without uninstalling.
5. Confirm Android accepts the update and app-private files, database, journal, and vault metadata remain present and readable. Use synthetic test data, never real user recordings.
6. Record artifact SHA-256, version, signer fingerprint, CI run, and upgrade-test result in release evidence.

## Scope and hard limits
The app cannot preserve update continuity if the signing private key is lost, the distribution signing identity changes incompatibly, or the application ID changes. Backups, access controls, signing checks, and release gates prevent avoidable failures; they cannot recreate a lost private key. Never promise an update independent of Android signing rules.
