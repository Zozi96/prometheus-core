//! prometheus-core: the deterministic engine behind Prometheus's check runner
//! and `PreToolUse` hook fast path.
//!
//! The crate owns the tree fingerprint, the scan and classification
//! primitives, the impact graph, test-log parsing, the receipt store with
//! its host-wide check slot, and the two native binaries. Under ADR-0010 the
//! gate modules and every Python-monolith parity obligation are gone:
//! `prometheus-check` is the standalone check runner and `prometheus-hook`
//! answers the retained hook guards.

#[cfg(feature = "python")]
use pyo3::prelude::*;

pub mod check;
pub mod classify;
pub mod fingerprint;
pub mod hooks;
pub mod impact;
pub mod logs;
#[cfg(feature = "python")]
pub mod scan;
pub mod store;

/// The engine API this build speaks. The module is optional: the native
/// binaries never load it, and nothing negotiates a verdict through it.
pub const ENGINE_API: u32 = 5;

#[cfg(feature = "python")]
#[pymodule]
fn prometheus_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    fingerprint::register(m)?;
    impact::register(m)?;
    logs::register(m)?;
    scan::register(m)?;
    store::register(m)
}
