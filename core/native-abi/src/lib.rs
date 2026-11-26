//! SQRecorder native ABI crate foundation.
//!
//! The stable, versioned C ABI and PCM contract are implemented in B2.
//! This crate intentionally exports no platform-specific or capture behavior yet.
#![forbid(unsafe_code)]

/// Foundation smoke test; ABI symbols are introduced with the B2 contract.
pub const FOUNDATION_VERSION: &str = "B1";
