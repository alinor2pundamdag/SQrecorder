# ADR 0001: Stack and system boundaries

- **Status:** Accepted (project-level decision)
- **Date:** 2026-11-27

## Decision

Use Kotlin Multiplatform for shared semantic/domain contracts, Rust for portable performance-sensitive core processing, and native platform adapters for OS-specific capabilities. Expose Rust through a versioned C ABI. Keep platform UI and OS dependencies out of shared domain and Rust.

The assistant's repository implementation and the user's independent AndroidIDE implementation remain separate tracks. This repository does not require code handoff or shared implementation between those tracks.

## Consequences

- Contracts are designed before cross-layer implementations.
- Platform behavior is tested through adapter and contract suites.
- The initial build scaffold is deliberately minimal; platform modules and production dependencies enter only in their scheduled batches.
- Dependency versions must be selected from official compatibility data and pinned reproducibly.
