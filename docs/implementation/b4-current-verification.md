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


## CI-trigger and host-test corrections — 2026-11-28

- Added the controlled candidate branch to push triggers for Rust contract and Android Vault contract workflows. This closes the direct-push CI trigger gap for the validation branch.
- Corrected Rust formatting reported by workflow run [46152996776](https://github.com/alinor2pundamdag/SQrecorder/actions/runs/46152996776): the CI rustfmt output affected `core/session-journal/src/checkpoint.rs` and `core/session-journal/src/lib.rs`. Applied the reported formatting changes in commits `896ef64a255db3613281ce8c59432823586fdcb8` and `2362d1cea2bb283122fa6f2832ab4848b91088a5`.
- Corrected JUnit host-test discovery by nesting `FixedDekBridge` in `AndroidSqveV2HeaderCodecTest`; this avoids the top-level fixture being independently discovered as a zero-test JUnit class. Commit `a504aa4966caefad1a6df80f99d30e54a4ee70d4`.
- Current exact branch HEAD at this checkpoint: `2362d1cea2bb283122fa6f2832ab4848b91088a5`.
- Exact-HEAD Rust workflow: [46153148664](https://github.com/alinor2pundamdag/SQrecorder/actions/runs/46153148664), in progress when recorded.
- Exact-HEAD Android workflow: [46153148666](https://github.com/alinor2pundamdag/SQrecorder/actions/runs/46153148666), pending when recorded.
- No combined commit statuses were present at query time. Do not call CI green until both workflows and all required matrix jobs complete successfully on this SHA.


## Cross-platform candidate push trigger — final workflow maintenance

- Added `b4-b5-controlled-validation-candidate` to `.github/workflows/platform-compatibility.yml` push branches as well. All three validation workflows (Rust, Android Vault, cross-platform matrix) now explicitly include this controlled candidate branch for relevant path-filtered pushes.
- This workflow change advanced the branch after the previous evidence snapshot. Re-query exact HEAD and wait for all three workflows; prior run links are diagnostic only and not evidence for the new SHA.
- Draft/open/unmerged remains mandatory until exact-head CI and the non-CI release gates pass.


## Current source and final evidence refresh — 2026-11-28

- Current implementation head before this evidence refresh: `f3bae85e68c36e115b17a297fb3f44ee85feefe2`; this document commit is the final evidence-only change and requires its own exact-head workflows.
- SQVE sink state machine corrected: finished-but-open permits staged read-back verification; writes/repeated finish are blocked; close performs final cleanup.
- Capture service compiler issues identified from run `46153414046` and corrected: missing `CaptureSessionJournal` import and mutable nullable journal captured by consumer callback. The callback now uses a stable non-null journal reference.
- Rust contract and cross-platform matrix were green on unchanged Rust/KMP source SHA `2657d5ff11d3ba55bbbe9565a423c9b9c0e1c2bc`; this is not a substitute for the latest final evidence SHA.
- Latest Android app/emulator workflow before evidence commit: `46153810154`, targeting `bef7e321edfd44fde27576b5160e702d19df3ba2`, was in progress; it must finish and then the evidence-commit SHA must be checked again.
- PR #7 and #2 are still open/draft/unmerged. No release/acceptance gate is marked complete.
