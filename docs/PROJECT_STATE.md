# Project State — append-only ledger

Repository: https://github.com/alinor2pundamdag/SQRecorder
Branch: `b4-b5-controlled-validation-candidate`

## Ledger entry — ORD-G-003 disclosure

- Timestamp: 2026-11-28T23:07:21+08:00
- Source audited: `450fabc9263368a9e366df834e1aad9c3815f425`, branch `b4-b5-controlled-validation-candidate`
- Report: `docs/audit/ORD-G-003-disclosure.md` (16 sections; 113 tracked artifacts inventoried)
- Governance bootstrap files: AGENTS.md; docs/PROJECT_STATE.md; docs/ORDERS.md; docs/AMENDMENTS.md; docs/REVIEWS.md; docs/MASTER_PLAN.md.
- Exact-head evidence: Rust 46156388703 PASS; cross-platform 46156388734 PASS (6/6); Android 46156388675 FAIL at API23 emulator Package Manager/install stage. App assemble/unit and API36 bridge passed.
- Local build/test and physical-device evidence: NONE. ORD-G-001 original, master plan and A1–A33 canonical texts: UNKNOWN/absent at source.
- Next: clean API23 emulator rerun; verify CI on post-bootstrap exact SHA; continue finalization/recovery and release gates.

## Ledger entry — governance bootstrap byte/hash verification

- Timestamp: 2026-11-28T23:07:21+08:00 (audit timestamp; bootstrap commit was authored at repository current time, UTC timestamp is in Git commit metadata).
- Governance commit: `80abe5ba44d1a991a5654c211c78133777b3aff9`, parent `450fabc9263368a9e366df834e1aad9c3815f425`.
- Files added and UTF-8 bytes at bootstrap commit: `AGENTS.md` 1,123; `docs/PROJECT_STATE.md` 1,042; `docs/ORDERS.md` 589; `docs/AMENDMENTS.md` 317; `docs/REVIEWS.md` 341; `docs/MASTER_PLAN.md` 557; `docs/audit/ORD-G-003-disclosure.md` 28,592. Blob IDs recorded in GitHub tree/commit.
- Disclosure content at bootstrap commit blob: `cbc9815e651203c1aad5c50be55f105509c6ab64`. The following report revision embeds this ledger snippet; Git object identity of that subsequent revision is independently recorded in repository history (self-hash is not embedded).
- No protocol/security contract changed. New governance/docs paths trigger fresh workflows; the prior evidence remains tied to source SHA `450fabc9263368a9e366df834e1aad9c3815f425`.
