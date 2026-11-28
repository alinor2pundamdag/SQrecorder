# B4/B5 candidate — current verification checkpoint

Date: 2026-11-28 (UTC date; no time asserted)
Branch: `b4-b5-controlled-validation-candidate`
Repository: `alinor2pundamdag/SQRecorder`

## Exact branch snapshot before this checkpoint

- Observed branch HEAD: `5806f784325e4e7fda7b7ec566ca6ae1ad04190e`
- PR #7: open, draft, unmerged; head is the candidate branch.
- PR #2: open, draft, unmerged.
- Combined commit status at the observed HEAD: empty (no status entries).
- Workflow-run query scoped to the observed HEAD: zero runs returned.
- Therefore this snapshot is **not CI-verified**. Earlier SHA passes are not current-head evidence.

## Verified scope / limits

The candidate includes the SQVE v2 writer/verifier and encrypted Android capture staging path, SQJ append-only journal/scanner, checkpoint store/coordinator, and supporting tests as documented in the PR history. These repository contents have not been compiled or exercised by this checkpoint agent in a local checkout.

Still release-blocking until demonstrated on an exact candidate SHA:
- complete SQJ journal-to-finalized-artifact lifecycle and crash-window reconciliation;
- authenticated startup recovery (read/verify, no unauthenticated promotion or destructive repair);
- failure-injection coverage for crash cuts, ENOSPC, force-stop, sink errors, queue saturation/overrun, and publication cleanup;
- Android API-level emulator and physical-device matrix;
- iOS provider/target integration if cross-platform release remains in scope;
- independent cryptographic/security review;
- required CI workflows passing on the same final SHA and reviewed merged diff.

## Safe merge policy

Keep PRs #7 and #2 open, draft, and unmerged until all required exact-head CI, review, and physical-device acceptance gates are evidenced. A successful workflow on a prior commit does not satisfy the final-head gate. Do not claim 100% completion from implementation notes or documentation.

This file records the current verification state; it does not itself complete a release gate.
