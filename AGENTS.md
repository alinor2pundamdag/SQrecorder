# SQRecorder execution and governance rules

- Planner-of-record is QWEN-PRIME per project order; implementer executes approved work. This file does not invent planner approvals.
- Do not alter locked contracts without canonical, recorded approval. SQVE V2 is current write/finalization; V1 legacy read-only per `docs/decisions/0002-cross-platform-sqve-v2.md`.
- Audio recorder only; no screen recording or hidden microphone auto-start (`README.md`). Keep shared domain portable and OS behavior in adapters (`docs/architecture/system-boundaries.md`).
- Preserve evidence, fail closed, no silent downgrade/sample loss/destructive journal repair. Never commit secrets, signing keys or recordings.
- Keep PRs draft/open/unmerged until exact final SHA CI, review, security and physical-device gates pass.
- Claims require path, SHA, CI ID or output. Use UNKNOWN/NONE where absent. Never claim local/device execution without it.
- Append timestamped evidence/blockers/next action to `docs/PROJECT_STATE.md`. Canonical ORD-G-001, master plan and A1–A33 were missing at source snapshot; restore them rather than reconstructing.
