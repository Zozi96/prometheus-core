//! prometheus-core: the in-process deterministic engine for the Prometheus gate.
//!
//! One engine, one seam: the Python gate runtime negotiates `ENGINE_API`
//! and either calls these primitives in process or reruns the whole call on
//! its own route. Today the engine owns the tree fingerprint; the scan,
//! classification, log-parsing, brief, and settlement modules are scaffolded
//! beside it and land one ticket at a time under spec #43 / ADR-0007.

use pyo3::prelude::*;

pub mod brief;
pub mod classify;
pub mod fingerprint;
pub mod logs;
pub mod scan;
pub mod settle;
pub mod store;

/// The engine API this build speaks. The gate runtime loads the module only
/// when this equals the API it was written against; any other value keeps
/// the runtime on its own route.
pub const ENGINE_API: u32 = 3;

#[pymodule]
fn prometheus_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    fingerprint::register(m)?;
    store::register(m)
}
