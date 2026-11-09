//! prometheus-hook: the native fast path for per-tool-call hook events
//! (spec #43, ticket #51).
//!
//! Usage: `prometheus-hook <host> [--active] [--shadow-log <path>]`
//!
//! Reads one hook event JSON from stdin (the exact bytes the host would
//! send its Python adapter) and prints the reply JSON on stdout, always
//! exiting 0 — the same contract the adapters keep. Shadow mode is the
//! default: decisions are computed and optionally logged, session state is
//! never written, and the Python hook keeps governing. `--active` enables
//! the state writes for parity testing; no host configuration points here
//! yet, by design.

use std::io::{Read, Write};
use std::time::Instant;

fn main() {
    let started = Instant::now();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut host = "claude";
    let mut opts = prometheus_core::hooks::Options { active: false, shadow_log: None };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--active" => opts.active = true,
            "--shadow" => opts.active = false,
            "--shadow-log" => {
                if index + 1 < args.len() {
                    opts.shadow_log = Some(args[index + 1].clone());
                    index += 1;
                }
            }
            other if !other.starts_with('-') => host = other,
            _ => {}
        }
        index += 1;
    }
    if opts.shadow_log.is_none() {
        opts.shadow_log = std::env::var("PROMETHEUS_HOOK_SHADOW_LOG")
            .ok()
            .filter(|value| !value.is_empty());
    }

    let mut raw = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut raw);

    // A panic anywhere in the decision is a bug, but a hook must still
    // answer: fall back to the empty reply and log the delegate record,
    // exactly the posture a missing binary leaves (Python governs).
    let (outcome, ms) = match std::panic::catch_unwind(|| {
        prometheus_core::hooks::handle(host, &raw, &opts, started)
    }) {
        Ok(pair) => pair,
        Err(_) => (
            prometheus_core::hooks::Outcome {
                reply: serde_json::json!({}),
                decision: "delegate",
                reason: "binary-panic".into(),
                event_name: String::new(),
                tool: String::new(),
            },
            started.elapsed().as_secs_f64() * 1000.0,
        ),
    };

    let session_id = prometheus_core::hooks::session_id_of(&raw);
    if let Some(path) = &opts.shadow_log {
        let record = prometheus_core::hooks::log_record(host, &session_id, &outcome, ms);
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{record}");
        }
    }
    println!("{}", outcome.reply);
}
