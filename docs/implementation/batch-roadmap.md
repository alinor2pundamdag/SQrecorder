# Implementation roadmap

Batch order is fixed. A batch may be marked blocked or limited; later dependent batches do not silently bypass its exit criteria.

| Batch | Scope | Exit evidence |
|---|---|---|
| B0 | Repository audit and baseline | tree, branch, HEAD, scope audited |
| B1 | Monorepo/build foundation | scaffold commit, static configuration review |
| B2 | Native ABI and canonical PCM | ABI/PCM contracts, compile and contract tests |
| B3 | KMP domain and session lifecycle | state-machine tests and lifecycle contracts |
| B4 | Evidence storage, journal, Vault crypto | recovery, crypto and tamper tests |
| B5 | Android capture adapter/service | capture, permission, FGS and fault tests |
| B6 | DSP graph and audio-quality base | DSP correctness/quality/resource tests |
| B7 | Capability system and model management | capability selection, integrity and resource tests |
| B8 | Android app integration (assistant track) | adapter-to-domain integration tests |
| B9 | Wear OS capture/control | continuity, permissions and control tests |
| B10 | Windows platform adapter | WASAPI and storage contract tests |
| B11 | Processing/editor workflows | derived-media provenance and workflow tests |
| B12 | Cross-platform integration/fault testing | fault matrix and cross-platform contracts |
| B13 | CI, release and supply chain | reproducible CI, dependency and artifact checks |
| B14 | Final architecture/security/acceptance audit | evidence-backed acceptance report |

Each batch report records commit, changed paths, checks actually run, limitations, risks, and next dependency. No device/runtime result is claimed without execution on the relevant environment.
