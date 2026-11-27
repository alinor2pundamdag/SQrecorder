# PR #3 — verifier integration tracking

**Disposition:** The verifier implementation and its host tests were transplanted into the B4 integration branch `b4-hardening-approved-foundation` and are present in PR #2. PR #3 is retained as a draft tracking/evidence PR only; do not cherry-pick or merge the original verifier changes again.

## Integrated source
- `AndroidJournalAnchorVerifier.kt`
- `AndroidJournalAnchorVerifierTest.kt`
- `AndroidKeystoreJournalAnchorPublicKeyResolver.kt`
- `AndroidKeystoreJournalAnchorPublicKeyResolverTest.kt`

## Evidence and gate
- Android Run #36 passed for the earlier PR #3 merge ref `7053602107e085990209d33d577d9c60516d2d22`.
- Run #36 does not validate the current PR #2 head after later KMP target/test wiring and retained-key resolver additions.
- Latest exact B4 CI, cross-platform anchor verifier/golden vectors, durable cross-platform key registry/export-recovery, and physical-device gates remain outstanding.
- This tracking file is deliberately the only change unique to PR #3; source implementations are maintained once on the B4 branch.
