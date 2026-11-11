//! prometheus-core: the in-process deterministic engine for the Prometheus gate.
//!
//! One engine, one seam: the Python gate runtime negotiates `ENGINE_API`
//! and either calls these primitives in process or reruns the whole call on
//! its own route. The engine owns the tree fingerprint and, under spec #43 /
//! ADR-0007, the scan, classification, impact, log-parsing, receipt-store,
//! brief, settlement, and decide modules plus the `prometheus-hook` binary.
//! Under ADR-0010 the `check` module and the `prometheus-check` binary are
//! the standalone check runner over the same primitives, with no Python
//! gate runtime involved.

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
pub mod brief;
pub mod check;
pub mod classify;
#[cfg(feature = "python")]
pub mod decide;
pub mod fingerprint;
pub mod hooks;
pub mod impact;
pub mod logs;
#[cfg(feature = "python")]
pub mod scan;
#[cfg(feature = "python")]
pub mod settle;
pub mod store;

/// The engine API this build speaks. The gate runtime loads the module only
/// when this equals the API it was written against; any other value keeps
/// the runtime on its own route.
pub const ENGINE_API: u32 = 4;

#[cfg(feature = "python")]
#[pymodule]
fn prometheus_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    fingerprint::register(m)?;
    impact::register(m)?;
    logs::register(m)?;
    scan::register(m)?;
    brief::register(m)?;
    settle::register(m)?;
    store::register(m)?;
    decide::register(m)
}
