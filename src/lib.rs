//! Deterministic engine for `prometheus-check` and `prometheus-kit`.

pub mod budget;
pub mod check;
pub mod check_run;
pub mod classify;
pub mod compact;
pub mod diff;
pub mod droid_mode;
pub mod fingerprint;
pub mod gather;
pub mod hook;
pub mod hook_decide;
pub mod hook_rewrite;
pub mod impact;
pub mod kit_util;
pub mod logs;
pub mod map;
pub mod metrics;
pub mod outline;
pub mod search;
pub mod selection;
pub mod slice;
pub mod store;
