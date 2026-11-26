//! The hook decision as one module (ADR-0017, #103): `decide` takes a
//! normalized event plus the ambient facts and returns a decision that names
//! what to do in no host's wire format, plus the metrics the decision
//! produced as data. Each host is an adapter (raw event → normalized event;
//! decision → host reply) with a capabilities record of exactly three
//! capabilities: `rewrite`, `ask`, and `deliver_context` (deliver
//! non-blocking context). `decide` reads capabilities and never compares a
//! host name. It reads and writes session state (Guided deny-once marker,
//! reread advisory, Use-time hint) under the root in the ambient facts, so it
//! is deterministic over its declared inputs, not pure.

use crate::hook::{
    as_str, casefold, check_keys_for_secret, check_keys_for_secret_with_prompt,
    command_token_denied, cursor_deny_reply, cursor_roots, cursor_secret_denied, devin_candidate,
    event_name_normalized, get, normalize_secret_candidate, omp_block_reply, omp_secret_denial,
    opencode_deny_reply, opencode_secret_denial, problem_reply, py_or, read_failure_allows,
    resolve_candidate_against_root, resolve_dir, resolve_optional_root, resolve_secret_root,
    secret_path_denied, secret_tool_denial, tool_name, valid_session_id_str, AmbientFacts,
    SYMLINK_BLOCK_REASON,
};
use crate::hook_rewrite::{evaluate_shell_policy_attributed, ShellAction, ShellPolicyTier};
use crate::metrics::MetricRecord;
use serde_json::{json, Map, Value};
use std::path::PathBuf;

/// The three capabilities a host adapter declares. `decide` branches only on
/// these, never on a host name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Tier-1 shell auto-rewrite (vs Tier-2 Guided deny-once when false).
    pub rewrite: bool,
    /// The host's block reply asks for consent (vs an outright deny when false).
    pub ask: bool,
    /// The host delivers non-blocking `PreToolUse` context to the model.
    pub deliver_context: bool,
}

/// A hook host. The single home for host names in the hook path (#106): a
/// host name is parsed from a string in exactly one place (`Host::parse`),
/// and every other hook use is a typed `Host` value. Each `Host` gives its
/// adapter and its capabilities record. (`metrics::Host` is a separate
/// storage vocabulary for the metrics log, mapped from this one in
/// `Host::metrics_host`.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Host {
    Claude,
    Muse,
    Droid,
    Devin,
    Cursor,
    Omp,
    Opencode,
    Antigravity,
    Grok,
}

impl Host {
    /// THE single parse site for host names.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "claude" => Some(Self::Claude),
            "muse" => Some(Self::Muse),
            "droid" => Some(Self::Droid),
            "devin" => Some(Self::Devin),
            "cursor" => Some(Self::Cursor),
            "omp" => Some(Self::Omp),
            "opencode" => Some(Self::Opencode),
            "antigravity" => Some(Self::Antigravity),
            "grok" => Some(Self::Grok),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Muse => "muse",
            Self::Droid => "droid",
            Self::Devin => "devin",
            Self::Cursor => "cursor",
            Self::Omp => "omp",
            Self::Opencode => "opencode",
            Self::Antigravity => "antigravity",
            Self::Grok => "grok",
        }
    }

    /// All supported hosts; the supported-host list is derived from this.
    pub fn all() -> [Self; 9] {
        [
            Self::Claude,
            Self::Muse,
            Self::Droid,
            Self::Devin,
            Self::Cursor,
            Self::Omp,
            Self::Opencode,
            Self::Antigravity,
            Self::Grok,
        ]
    }

    /// This host's capabilities record (exactly three capabilities).
    pub fn capabilities(self) -> Capabilities {
        match self {
            Self::Claude | Self::Muse => Capabilities {
                rewrite: true,
                ask: true,
                deliver_context: true,
            },
            Self::Droid | Self::Devin => Capabilities {
                rewrite: true,
                ask: true,
                deliver_context: false,
            },
            Self::Cursor | Self::Omp => Capabilities {
                rewrite: true,
                ask: false,
                deliver_context: false,
            },
            Self::Antigravity => Capabilities {
                rewrite: true,
                ask: true,
                deliver_context: false,
            },
            Self::Opencode | Self::Grok => Capabilities {
                rewrite: false,
                ask: false,
                deliver_context: false,
            },
        }
    }

    /// This host's identity in the metrics vocabulary.
    pub fn metrics_host(self) -> crate::metrics::Host {
        match self {
            Self::Claude => crate::metrics::Host::Claude,
            Self::Muse => crate::metrics::Host::Muse,
            Self::Droid => crate::metrics::Host::Droid,
            Self::Devin => crate::metrics::Host::Devin,
            Self::Cursor => crate::metrics::Host::Cursor,
            Self::Omp => crate::metrics::Host::Omp,
            Self::Opencode => crate::metrics::Host::Opencode,
            Self::Antigravity => crate::metrics::Host::Antigravity,
            Self::Grok => crate::metrics::Host::Grok,
        }
    }

    /// Run one raw event through this host's adapter and `decide`.
    pub fn run(self, raw: &[u8], ambient: &AmbientFacts) -> Value {
        let caps = self.capabilities();
        let metrics_host = Some(self.metrics_host());
        match self {
            Self::Claude => run_adapter(
                &ClaudeAdapter {
                    family: ClaudeFamily::Claude,
                },
                caps,
                raw,
                ambient,
                metrics_host,
            ),
            Self::Muse => run_adapter(
                &ClaudeAdapter {
                    family: ClaudeFamily::Muse,
                },
                caps,
                raw,
                ambient,
                metrics_host,
            ),
            Self::Droid => run_adapter(&DroidAdapter, caps, raw, ambient, metrics_host),
            Self::Devin => run_adapter(&DevinAdapter, caps, raw, ambient, metrics_host),
            Self::Cursor => run_adapter(&CursorAdapter, caps, raw, ambient, metrics_host),
            Self::Omp => run_adapter(&OmpAdapter, caps, raw, ambient, metrics_host),
            Self::Opencode => run_adapter(&OpenCodeAdapter, caps, raw, ambient, metrics_host),
            Self::Antigravity => run_adapter(&AntigravityAdapter, caps, raw, ambient, metrics_host),
            Self::Grok => run_adapter(&GrokAdapter, caps, raw, ambient, metrics_host),
        }
    }

    /// Fail-closed fallback reply if hook evaluation panics.
    pub fn panic_fallback(self) -> Value {
        match self {
            Self::Cursor => cursor_deny_reply("the secret guard failed"),
            Self::Omp => omp_block_reply("consent could not be evaluated"),
            // `{}` denies on Antigravity, so its panic fallback must be
            // explicit; `ask` keeps the secret guard fail-closed without an
            // outright deny.
            Self::Antigravity => json!({
                "decision": "ask",
                "reason": "consent could not be evaluated",
            }),
            Self::Grok | Self::Opencode => json!({
                "decision": "deny",
                "reason": "consent could not be evaluated",
            }),
            _ => crate::hook::ask_reply("consent could not be evaluated"),
        }
    }
}

/// A host event translated by an adapter into the shared shape `decide`
/// consumes. Secret-path resolution already happened in the adapter (each
/// host keeps its own keys and resolution rules there), so the decision sees
/// only the resulting `secret_reason`.
#[derive(Clone, Debug)]
pub struct NormalizedEvent {
    /// The shared-shape event JSON (shell policy, hint, and read advisory
    /// still read tool name / tool input / cwd from it).
    pub event: Value,
    pub is_pretool: bool,
    pub session_id: String,
    /// Resolved workspace root for the read advisory.
    pub root: Option<PathBuf>,
    /// Cwd the shell policy evaluates against (per-host: raw event cwd,
    /// or the resolved root — the adapter preserves its handler's choice).
    pub shell_cwd: Option<PathBuf>,
    /// Non-empty when the adapter's secret check blocks this event.
    pub secret_reason: String,
    /// The shell tool's input map, when the event carries one.
    pub shell_input: Option<Map<String, Value>>,
    pub tool_name: String,
    /// RTK deferral for this host, resolved by the adapter from the ambient
    /// facts (ADR-0013 D7).
    pub rtk_active: bool,
}

/// What to do, in no host's wire format. Adapters translate it into replies.
#[derive(Clone, Debug, PartialEq)]
pub enum Decision {
    Pass,
    /// Block the tool call for `reason` (the adapter renders ask vs deny
    /// from its own wire format; the capabilities record's `ask` capability
    /// is what the adapter declares for it).
    Block {
        reason: String,
    },
    /// Replace the shell command in the tool input.
    RewriteShell {
        command_key: String,
        rewritten: String,
    },
    /// Guided deny-once (ADR-0014): deny this attempt with `reason`.
    DenyOnce {
        reason: String,
    },
    /// Deliver non-blocking context text to the model.
    Context {
        text: String,
    },
}

/// A decision plus the metrics it produced, as data. The entry point is the
/// only place that records them.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    pub decision: Decision,
    pub metrics: Vec<MetricRecord>,
}

fn pass() -> Outcome {
    Outcome {
        decision: Decision::Pass,
        metrics: Vec::new(),
    }
}

/// The shared hook decision: secret block, shell rewrite or Guided
/// deny-once, Use-time hint, reread advisory, pass — in that order.
pub fn decide(normalized: &NormalizedEvent, ambient: &AmbientFacts, caps: Capabilities) -> Outcome {
    decide_impl(normalized, ambient, caps, None)
}

pub(crate) fn decide_with_metrics_host(
    normalized: &NormalizedEvent,
    ambient: &AmbientFacts,
    caps: Capabilities,
    metrics_host: Option<crate::metrics::Host>,
) -> Outcome {
    decide_impl(normalized, ambient, caps, metrics_host)
}

fn decide_impl(
    normalized: &NormalizedEvent,
    ambient: &AmbientFacts,
    caps: Capabilities,
    metrics_host: Option<crate::metrics::Host>,
) -> Outcome {
    if !normalized.is_pretool {
        return pass();
    }
    if !normalized.secret_reason.is_empty() {
        return Outcome {
            decision: Decision::Block {
                reason: normalized.secret_reason.clone(),
            },
            metrics: Vec::new(),
        };
    }
    let mut extra_metrics: Vec<MetricRecord> = Vec::new();
    if let Some(inp) = &normalized.shell_input {
        let tier = if caps.rewrite {
            ShellPolicyTier::Rewrite
        } else {
            ShellPolicyTier::DenyOnce
        };
        match evaluate_shell_policy_attributed(
            ambient,
            normalized.rtk_active,
            tier,
            &normalized.tool_name,
            inp,
            &normalized.session_id,
            normalized.shell_cwd.as_deref(),
            metrics_host,
        ) {
            ShellAction::Rewrite {
                command_key,
                rewritten,
                metrics,
                ..
            } => {
                return Outcome {
                    decision: Decision::RewriteShell {
                        command_key,
                        rewritten,
                    },
                    metrics,
                };
            }
            ShellAction::DenyOnce {
                reason, metrics, ..
            } => {
                return Outcome {
                    decision: Decision::DenyOnce { reason },
                    metrics,
                };
            }
            ShellAction::PassWithMetrics(metrics) => {
                extra_metrics.extend(metrics);
            }
            ShellAction::Pass => {}
        }
    }
    if caps.deliver_context {
        if let Some((hint, metrics)) =
            crate::hook::use_time_hint(&normalized.event, &normalized.session_id, ambient)
        {
            extra_metrics.extend(metrics);
            return Outcome {
                decision: Decision::Context { text: hint },
                metrics: extra_metrics,
            };
        }
        let (guard, metrics) = crate::hook::read_guard(
            &normalized.event,
            &normalized.session_id,
            normalized.root.as_deref(),
            ambient,
        );
        if let crate::hook::ReadGuard::Warn(text) = guard {
            extra_metrics.extend(metrics);
            return Outcome {
                decision: Decision::Context { text },
                metrics: extra_metrics,
            };
        }
    }
    Outcome {
        decision: Decision::Pass,
        metrics: extra_metrics,
    }
}

/// A host adapter: two translations. Its capabilities record lives on
/// its `Host` value.
pub trait HostAdapter {
    /// Raw event bytes → normalized event. `Err(reply)` is a final host reply
    /// (malformed event, missing cwd, invalid session, fail-closed guards).
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value>;
    /// Decision → host reply wire format.
    fn reply(&self, decision: &Decision, normalized: &NormalizedEvent) -> Value;
}

/// Run one event through an adapter and `decide`, recording the returned
/// metrics exactly once here at the entry point.
pub fn run_adapter<A: HostAdapter>(
    adapter: &A,
    caps: Capabilities,
    raw: &[u8],
    ambient: &AmbientFacts,
    metrics_host: Option<crate::metrics::Host>,
) -> Value {
    let normalized = match adapter.normalize(raw, ambient) {
        Ok(normalized) => normalized,
        Err(reply) => return reply,
    };
    let outcome = decide_with_metrics_host(&normalized, ambient, caps, metrics_host);
    if let Some(host) = metrics_host {
        for metric in &outcome.metrics {
            crate::metrics::record_metric(host, *metric);
        }
    }
    adapter.reply(&outcome.decision, &normalized)
}

// ---------------------------------------------------------------------------
// Claude and Muse adapters (#103). Both share the `hookSpecificOutput`
// envelope, ask-on-secret, Tier-1 rewrite, and context delivery; they differ
// only in the other-host short-circuit, which is Claude-only and lives in
// its adapter's normalization.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeFamily {
    Claude,
    Muse,
}

pub struct ClaudeAdapter {
    pub family: ClaudeFamily,
}

impl ClaudeAdapter {
    fn host(&self) -> Host {
        match self.family {
            ClaudeFamily::Claude => Host::Claude,
            ClaudeFamily::Muse => Host::Muse,
        }
    }
}

impl HostAdapter for ClaudeAdapter {
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value> {
        if self.family == ClaudeFamily::Claude && ambient.other_host_markers_present {
            return Err(json!({}));
        }
        let parsed: Option<Value> = serde_json::from_slice(raw).ok();
        let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
            let problem = if parsed.is_some() {
                "event-malformed"
            } else {
                "invalid-json"
            };
            return Err(problem_reply(self.host(), None, problem));
        };
        let event = event.clone();
        let cwd = as_str(get(&event, "cwd"));
        if cwd.is_empty() {
            return Err(problem_reply(self.host(), Some(&event), "cwd-missing"));
        }
        let session_id = as_str(get(&event, "session_id")).to_string();
        if !valid_session_id_str(&session_id) {
            return Err(problem_reply(
                self.host(),
                Some(&event),
                "session-id-invalid",
            ));
        }
        let root = match resolve_dir(cwd) {
            Ok(root) => root,
            Err(problem) => return Err(problem_reply(self.host(), Some(&event), problem)),
        };
        let shell_input = get(&event, "tool_input")
            .and_then(Value::as_object)
            .or_else(|| get(&event, "input").and_then(Value::as_object))
            .cloned();
        Ok(NormalizedEvent {
            is_pretool: event_name_normalized(&event) == "pretooluse",
            session_id,
            shell_cwd: Some(PathBuf::from(cwd)),
            root: Some(root),
            secret_reason: secret_tool_denial(&event),
            shell_input,
            tool_name: tool_name(&event).to_string(),
            rtk_active: ambient.rtk_active(self.host()),
            event,
        })
    }

    fn reply(&self, decision: &Decision, normalized: &NormalizedEvent) -> Value {
        match decision {
            Decision::Pass | Decision::DenyOnce { .. } => json!({}),
            Decision::Block { reason } => crate::hook::ask_reply(reason),
            Decision::RewriteShell {
                command_key,
                rewritten,
            } => {
                let mut updated = normalized.shell_input.clone().unwrap_or_default();
                updated.insert(command_key.clone(), Value::String(rewritten.clone()));
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecisionReason": "prometheus-kit auto-rewrite",
                        "updatedInput": Value::Object(updated),
                    }
                })
            }
            Decision::Context { text } => crate::hook::warn_reply(text),
        }
    }
}

// ---------------------------------------------------------------------------
// Droid, Devin, and Cursor adapters (#104). Every difference from the shared
// middle is listed on issue #104 with where it landed.
// ---------------------------------------------------------------------------

/// The `hookSpecificOutput` rewrite envelope shared by Claude, Muse, Droid,
/// and Devin replies.
fn shared_envelope_reply(decision: &Decision, normalized: &NormalizedEvent) -> Value {
    match decision {
        Decision::Pass | Decision::DenyOnce { .. } => json!({}),
        Decision::Block { reason } => crate::hook::ask_reply(reason),
        Decision::RewriteShell {
            command_key,
            rewritten,
        } => {
            let mut updated = normalized.shell_input.clone().unwrap_or_default();
            updated.insert(command_key.clone(), Value::String(rewritten.clone()));
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecisionReason": "prometheus-kit auto-rewrite",
                    "updatedInput": Value::Object(updated),
                }
            })
        }
        Decision::Context { text } => crate::hook::warn_reply(text),
    }
}

fn shell_input_of(event: &Value) -> Option<Map<String, Value>> {
    get(event, "tool_input")
        .and_then(Value::as_object)
        .or_else(|| get(event, "input").and_then(Value::as_object))
        .cloned()
}

pub struct DroidAdapter;

impl HostAdapter for DroidAdapter {
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value> {
        let parsed: Option<Value> = serde_json::from_slice(raw).ok();
        let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
            return Err(json!({"systemMessage": "Hook warning: invalid-json"}));
        };
        let event = event.clone();
        let session_id = as_str(get(&event, "session_id")).to_string();
        if !valid_session_id_str(&session_id) {
            return Err(problem_reply(
                Host::Droid,
                Some(&event),
                "session-id-invalid",
            ));
        }
        let cwd = as_str(get(&event, "cwd"));
        if cwd.is_empty() {
            return Err(problem_reply(Host::Droid, Some(&event), "cwd-missing"));
        }
        if let Err(problem) = resolve_dir(cwd) {
            return Err(problem_reply(Host::Droid, Some(&event), problem));
        }
        Ok(NormalizedEvent {
            is_pretool: event_name_normalized(&event) == "pretooluse",
            session_id,
            shell_cwd: Some(PathBuf::from(cwd)),
            root: None,
            secret_reason: secret_tool_denial(&event),
            shell_input: shell_input_of(&event),
            tool_name: tool_name(&event).to_string(),
            rtk_active: ambient.rtk_active(Host::Droid),
            event,
        })
    }

    fn reply(&self, decision: &Decision, normalized: &NormalizedEvent) -> Value {
        shared_envelope_reply(decision, normalized)
    }
}

pub struct DevinAdapter;

impl HostAdapter for DevinAdapter {
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value> {
        let parsed: Option<Value> = serde_json::from_slice(raw).ok();
        let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
            return Err(json!({"systemMessage": "Hook warning: invalid-json"}));
        };
        let event = event.clone();
        let is_pretool = event_name_normalized(&event) == "pretooluse";
        let base = NormalizedEvent {
            is_pretool,
            session_id: String::new(),
            shell_cwd: None,
            root: None,
            secret_reason: String::new(),
            shell_input: shell_input_of(&event),
            tool_name: tool_name(&event).to_string(),
            rtk_active: ambient.rtk_active(Host::Devin),
            event: event.clone(),
        };
        if !is_pretool {
            return Ok(base);
        }
        if casefold(tool_name(&event)) == "read" && read_failure_allows(Host::Devin, &event) {
            return Err(json!({}));
        }
        let session_id = as_str(get(&event, "session_id")).to_string();
        if !valid_session_id_str(&session_id) {
            return Err(problem_reply(
                Host::Devin,
                Some(&event),
                "session-id-invalid",
            ));
        }
        let Some(candidate) = devin_candidate(&event, ambient) else {
            return Err(problem_reply(Host::Devin, Some(&event), "root-invalid"));
        };
        let root = match std::fs::canonicalize(&candidate) {
            Ok(resolved) if resolved.is_dir() => resolved,
            Ok(_) => {
                return Err(problem_reply(
                    Host::Devin,
                    Some(&event),
                    "root-not-directory",
                ))
            }
            Err(_) => return Err(problem_reply(Host::Devin, Some(&event), "root-invalid")),
        };
        Ok(NormalizedEvent {
            session_id,
            shell_cwd: Some(root),
            secret_reason: secret_tool_denial(&event),
            ..base
        })
    }

    fn reply(&self, decision: &Decision, normalized: &NormalizedEvent) -> Value {
        shared_envelope_reply(decision, normalized)
    }
}

pub struct CursorAdapter;

impl HostAdapter for CursorAdapter {
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value> {
        let parsed: Option<Value> = serde_json::from_slice(raw).ok();
        let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
            return Err(json!({}));
        };
        let event = event.clone();
        let name = event_name_normalized(&event);
        if name == "beforesubmitprompt" {
            return Err(json!({"continue": true}));
        }
        if name != "pretooluse" {
            return Err(json!({}));
        }
        let session_id = as_str(py_or(
            get(&event, "session_id"),
            get(&event, "conversation_id"),
        ))
        .to_string();
        if !valid_session_id_str(&session_id) {
            if read_failure_allows(Host::Cursor, &event) {
                return Err(json!({}));
            }
            return Err(cursor_deny_reply("the secret guard failed"));
        }
        let roots = cursor_roots(&event, ambient);
        let root = roots.first().cloned();
        let shell_input = shell_input_of(&event).or_else(|| {
            get(&event, "command")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(|cmd| {
                    let mut m = Map::new();
                    m.insert("command".to_owned(), Value::String(cmd.to_owned()));
                    m
                })
        });
        Ok(NormalizedEvent {
            is_pretool: true,
            session_id,
            shell_cwd: root.clone(),
            root,
            secret_reason: cursor_secret_denied(&event),
            shell_input,
            tool_name: tool_name(&event).to_string(),
            rtk_active: ambient.rtk_active(Host::Cursor),
            event,
        })
    }

    fn reply(&self, decision: &Decision, normalized: &NormalizedEvent) -> Value {
        match decision {
            Decision::Block { reason } => cursor_deny_reply(reason),
            Decision::RewriteShell {
                command_key,
                rewritten,
            } => {
                let mut updated = normalized.shell_input.clone().unwrap_or_default();
                updated.insert(command_key.clone(), Value::String(rewritten.clone()));
                json!({
                    "permission": "allow",
                    "updated_input": Value::Object(updated),
                })
            }
            _ => json!({}),
        }
    }
}

// ---------------------------------------------------------------------------
// omp, OpenCode, Antigravity, and Grok adapters (#105). Every difference
// from the shared middle is listed on issue #105 with where it landed.
// Antigravity and Grok keep their own file-tool lists and secret-bearing
// keys inside their adapters, below.
// ---------------------------------------------------------------------------

pub struct OmpAdapter;

impl HostAdapter for OmpAdapter {
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value> {
        let parsed: Option<Value> = serde_json::from_slice(raw).ok();
        let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
            let problem = if parsed.is_some() {
                "event-malformed"
            } else {
                "invalid-json"
            };
            return Err(omp_block_reply(&format!(
                "Hook warning: {problem} — consent could not be evaluated"
            )));
        };
        let event = event.clone();
        let root = match resolve_secret_root(as_str(get(&event, "cwd")), ambient) {
            Ok(root) => root,
            Err(()) => return Err(omp_block_reply(SYMLINK_BLOCK_REASON)),
        };
        let prompt = as_str(py_or(
            get(&event, "lastPrompt"),
            py_or(get(&event, "last_prompt"), get(&event, "prompt")),
        ))
        .to_string();
        let secret_reason = omp_secret_denial(&event, &prompt, root.as_deref(), ambient);
        let session_id =
            as_str(py_or(get(&event, "sessionId"), get(&event, "session_id"))).to_string();
        if secret_reason.is_empty() && !session_id.is_empty() && !valid_session_id_str(&session_id)
        {
            if read_failure_allows(Host::Omp, &event)
                && omp_secret_denial(&event, "", root.as_deref(), ambient).is_empty()
            {
                return Err(json!({}));
            }
            return Err(omp_block_reply(
                "Hook warning: session-id-invalid — consent could not be evaluated",
            ));
        }
        let canonical_root = root
            .as_ref()
            .and_then(|p| std::fs::canonicalize(p).ok())
            .filter(|d| d.is_dir());
        let inp = get(&event, "input")
            .and_then(Value::as_object)
            .or_else(|| get(&event, "tool_input").and_then(Value::as_object));
        let explicit_shell_cwd = inp
            .and_then(|m| m.get("cwd"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let (shell_root, shell_cwd_is_secret) = match explicit_shell_cwd {
            Some(sub) => {
                let sub_norm = normalize_secret_candidate(sub);
                let raw_secret = !command_token_denied(&sub_norm).is_empty();
                let resolved_loose =
                    resolve_candidate_against_root(&sub_norm, root.as_deref(), ambient);
                if matches!(resolved_loose, Some(Err(()))) {
                    return Err(omp_block_reply(SYMLINK_BLOCK_REASON));
                }
                let resolved_secret = resolved_loose
                    .as_ref()
                    .and_then(|res| res.as_ref().ok())
                    .is_some_and(|p| !secret_path_denied(&p.to_string_lossy()).is_empty());
                let canonical = resolved_loose
                    .and_then(Result::ok)
                    .and_then(|p| std::fs::canonicalize(p).ok())
                    .filter(|d| d.is_dir());
                (canonical, raw_secret || resolved_secret)
            }
            None => {
                let root_secret = root
                    .as_ref()
                    .is_some_and(|p| !secret_path_denied(&p.to_string_lossy()).is_empty());
                (canonical_root.clone(), root_secret)
            }
        };
        Ok(NormalizedEvent {
            // omp's handler never gated on the event name.
            is_pretool: true,
            session_id,
            shell_cwd: shell_root,
            root: None,
            secret_reason,
            shell_input: if shell_cwd_is_secret {
                None
            } else {
                inp.cloned()
            },
            tool_name: tool_name(&event).to_string(),
            rtk_active: ambient.rtk_active(Host::Omp),
            event,
        })
    }

    fn reply(&self, decision: &Decision, normalized: &NormalizedEvent) -> Value {
        match decision {
            Decision::Block { reason } => omp_block_reply(reason),
            Decision::RewriteShell {
                command_key,
                rewritten,
            } => {
                let mut updated = normalized.shell_input.clone().unwrap_or_default();
                updated.insert(command_key.clone(), Value::String(rewritten.clone()));
                json!({ "input": Value::Object(updated) })
            }
            _ => json!({}),
        }
    }
}

pub struct OpenCodeAdapter;

impl HostAdapter for OpenCodeAdapter {
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value> {
        let parsed: Option<Value> = serde_json::from_slice(raw).ok();
        let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
            return Err(opencode_deny_reply("the secret guard failed"));
        };
        let event = event.clone();
        let is_pretool = event_name_normalized(&event) == "pretooluse";
        let mut normalized = NormalizedEvent {
            is_pretool,
            session_id: as_str(get(&event, "session_id")).to_string(),
            shell_cwd: None,
            root: None,
            secret_reason: String::new(),
            // OpenCode never evaluates shell rewrite/deny-once; its only
            // shell handling is the secret token scan inside its secret
            // check during this normalization.
            shell_input: None,
            tool_name: tool_name(&event).to_string(),
            rtk_active: false,
            event: event.clone(),
        };
        if !is_pretool {
            return Ok(normalized);
        }
        let root = match resolve_secret_root(as_str(get(&event, "cwd")), ambient) {
            Ok(root) => root,
            Err(()) => return Err(opencode_deny_reply(SYMLINK_BLOCK_REASON)),
        };
        normalized.secret_reason = opencode_secret_denial(&event, root.as_deref(), ambient);
        Ok(normalized)
    }

    fn reply(&self, decision: &Decision, _normalized: &NormalizedEvent) -> Value {
        match decision {
            Decision::Block { reason } => opencode_deny_reply(reason),
            _ => json!({}),
        }
    }
}

/// Antigravity's own file-tool list, kept inside its adapter (#105).
const ANTIGRAVITY_FILE_TOOLS: [&str; 10] = [
    "view_file",
    "read_file",
    "write_to_file",
    "write_file",
    "replace_file_content",
    "multi_replace_file_content",
    "edit_file",
    "list_dir",
    "find_by_name",
    "grep_search",
];

/// Antigravity's own secret-bearing keys, kept inside its adapter (#105).
const ANTIGRAVITY_SECRET_KEYS: [&str; 10] = [
    "AbsolutePath",
    "Path",
    "TargetFile",
    "DirectoryPath",
    "SearchDirectory",
    "SearchPath",
    "file_path",
    "path",
    "pattern",
    "glob",
];

/// Normalize an Antigravity camelCase payload (`toolCall.{name,args}`,
/// `conversationId`, `workspacePaths`) into the shared event shape.
fn antigravity_event(event: &Value) -> Value {
    let mut normalized = match event.as_object() {
        Some(map) => map.clone(),
        None => Map::new(),
    };
    let tool_call = get(event, "toolCall").cloned().unwrap_or(Value::Null);
    let name = as_str(get(&tool_call, "name")).to_string();
    let args = get(&tool_call, "args")
        .cloned()
        .unwrap_or_else(|| json!({}));
    normalized.insert("tool_name".to_string(), Value::String(name));
    normalized.insert("tool_input".to_string(), args);
    let session = as_str(py_or(
        get(event, "conversationId"),
        get(event, "session_id"),
    ))
    .to_string();
    normalized.insert("session_id".to_string(), Value::String(session));
    if as_str(get(event, "cwd")).is_empty() {
        if let Some(Value::Array(paths)) = get(event, "workspacePaths") {
            if let Some(first) = paths.iter().find_map(Value::as_str) {
                if !first.is_empty() {
                    normalized.insert("cwd".to_string(), Value::String(first.to_string()));
                }
            }
        }
    }
    Value::Object(normalized)
}

fn antigravity_allow() -> Value {
    json!({"decision": "allow"})
}

pub struct AntigravityAdapter;

impl HostAdapter for AntigravityAdapter {
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value> {
        let parsed: Option<Value> = serde_json::from_slice(raw).ok();
        let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
            // Malformed payload: never emit `{}` (that denies on
            // Antigravity); `ask` is the fail-closed secret-safe fallback.
            return Err(json!({
                "decision": "ask",
                "reason": "Hook warning: consent could not be evaluated",
            }));
        };
        let event = event.clone();
        let is_pretool = event_name_normalized(&event) == "pretooluse";
        let normalized_event = antigravity_event(&event);
        let tool = casefold(tool_name(&normalized_event));
        let prompt = as_str(get(&event, "lastUserInput")).to_string();
        let mut secret_reason = String::new();
        if ANTIGRAVITY_FILE_TOOLS.contains(&tool.as_str()) {
            if let Some(inp) = get(&normalized_event, "tool_input").and_then(Value::as_object) {
                secret_reason =
                    check_keys_for_secret_with_prompt(inp, &ANTIGRAVITY_SECRET_KEYS, &prompt);
            }
        }
        let root = resolve_optional_root(as_str(get(&normalized_event, "cwd")), ambient);
        Ok(NormalizedEvent {
            is_pretool,
            session_id: as_str(get(&normalized_event, "session_id")).to_string(),
            shell_cwd: root.clone(),
            root,
            secret_reason,
            shell_input: if tool == "run_command" {
                get(&normalized_event, "tool_input")
                    .and_then(Value::as_object)
                    .cloned()
            } else {
                None
            },
            tool_name: tool_name(&normalized_event).to_string(),
            rtk_active: ambient.rtk_active(Host::Antigravity),
            event: normalized_event,
        })
    }

    fn reply(&self, decision: &Decision, _normalized: &NormalizedEvent) -> Value {
        match decision {
            Decision::Block { reason } => json!({"decision": "ask", "reason": reason}),
            Decision::RewriteShell { rewritten, .. } => json!({
                "decision": "allow",
                "overwrite": {"CommandLine": rewritten},
            }),
            _ => antigravity_allow(),
        }
    }
}

/// Grok's own secret-bearing keys, kept inside its adapter (#105).
const GROK_SECRET_KEYS: [&str; 10] = [
    "file_path",
    "filePath",
    "path",
    "AbsolutePath",
    "target_file",
    "TargetFile",
    "pattern",
    "glob",
    "directory",
    "dir",
];

/// Grok's own file-tool list, kept inside its adapter (#105).
const GROK_FILE_TOOLS: [&str; 12] = [
    "read_file",
    "read",
    "write_file",
    "edit_file",
    "create_file",
    "list_dir",
    "grep",
    "search",
    "glob",
    "view_file",
    "replace_file_content",
    "multi_replace_file_content",
];

/// Normalize a Grok Build camelCase payload (`toolName`, `toolInput`,
/// `sessionId`, `workspaceRoot`) into the shared event shape.
fn grok_event(event: &Value) -> Value {
    let mut normalized = match event.as_object() {
        Some(map) => map.clone(),
        None => Map::new(),
    };
    normalized.insert(
        "tool_name".to_string(),
        Value::String(as_str(get(event, "toolName")).to_string()),
    );
    normalized.insert(
        "tool_input".to_string(),
        get(event, "toolInput")
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    normalized.insert(
        "session_id".to_string(),
        Value::String(as_str(get(event, "sessionId")).to_string()),
    );
    if as_str(get(event, "cwd")).is_empty() {
        let root = as_str(get(event, "workspaceRoot"));
        if !root.is_empty() {
            normalized.insert("cwd".to_string(), Value::String(root.to_string()));
        }
    }
    Value::Object(normalized)
}

pub struct GrokAdapter;

impl HostAdapter for GrokAdapter {
    fn normalize(&self, raw: &[u8], ambient: &AmbientFacts) -> Result<NormalizedEvent, Value> {
        let parsed: Option<Value> = serde_json::from_slice(raw).ok();
        let Some(event) = parsed.as_ref().filter(|v| v.is_object()) else {
            return Err(json!({}));
        };
        let event = event.clone();
        let is_pretool = event_name_normalized(&event) == "pretooluse";
        let normalized_event = grok_event(&event);
        let tool = casefold(tool_name(&normalized_event));
        let mut secret_reason = String::new();
        if GROK_FILE_TOOLS.contains(&tool.as_str()) {
            if let Some(inp) = get(&normalized_event, "tool_input").and_then(Value::as_object) {
                secret_reason = check_keys_for_secret(inp, &GROK_SECRET_KEYS);
            }
        }
        let root = resolve_optional_root(as_str(get(&normalized_event, "cwd")), ambient);
        let is_shell = crate::hook_rewrite::is_shell_tool(tool_name(&normalized_event));
        Ok(NormalizedEvent {
            is_pretool,
            session_id: as_str(get(&normalized_event, "session_id")).to_string(),
            shell_cwd: root.clone(),
            root,
            secret_reason,
            shell_input: if is_shell {
                get(&normalized_event, "tool_input")
                    .and_then(Value::as_object)
                    .cloned()
            } else {
                None
            },
            tool_name: tool_name(&normalized_event).to_string(),
            rtk_active: ambient.rtk_active(Host::Grok),
            event: normalized_event,
        })
    }

    fn reply(&self, decision: &Decision, _normalized: &NormalizedEvent) -> Value {
        match decision {
            Decision::Block { reason } | Decision::DenyOnce { reason } => {
                json!({"decision": "deny", "reason": reason})
            }
            _ => json!({}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Rule;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_amb(tag: &str) -> (AmbientFacts, PathBuf) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("prom_decide_{tag}_{}_{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let mut amb = crate::hook::AmbientFacts {
            other_host_markers_present: false,
            devin_project_dir: None,
            rewrite_disabled: false,
            rtk_coexist: Some("0".to_string()),
            rtk_config_active: Default::default(),
            xdg_runtime_dir: None,
            temp_dir: std::env::temp_dir(),
            session_parent: dir.join("sessions"),
            process_cwd: Some(dir.clone()),
            home_dir: None,
            xdg_config_home: None,
            agy_config_dir: None,
            exe_path: PathBuf::from("/bin/prometheus-kit"),
        };
        amb.session_parent = dir.join("sessions");
        (amb, dir)
    }

    fn normalized(event: Value, root: &std::path::Path, secret_reason: &str) -> NormalizedEvent {
        let shell_input = get(&event, "tool_input")
            .and_then(Value::as_object)
            .cloned();
        NormalizedEvent {
            is_pretool: true,
            session_id: "s-decide".to_string(),
            shell_cwd: Some(root.to_path_buf()),
            root: Some(root.to_path_buf()),
            secret_reason: secret_reason.to_string(),
            shell_input,
            tool_name: tool_name(&event).to_string(),
            rtk_active: false,
            event,
        }
    }

    const COMBOS: [(&str, Capabilities); 4] = [
        (
            "rewrite+ask+context (claude/muse)",
            Capabilities {
                rewrite: true,
                ask: true,
                deliver_context: true,
            },
        ),
        (
            "rewrite+ask (droid/devin/antigravity)",
            Capabilities {
                rewrite: true,
                ask: true,
                deliver_context: false,
            },
        ),
        (
            "rewrite only (cursor/omp)",
            Capabilities {
                rewrite: true,
                ask: false,
                deliver_context: false,
            },
        ),
        (
            "no rewrite, no ask, no context (grok/opencode)",
            Capabilities {
                rewrite: false,
                ask: false,
                deliver_context: false,
            },
        ),
    ];

    #[test]
    fn decide_table_secret_rewrite_deny_once_advisory_hint_pass() {
        for (label, caps) in COMBOS {
            let (amb, root) = temp_amb("table");
            // Secret path -> Block, no metrics, for every combination.
            let ev = json!({"tool_name": "Read", "tool_input": {"file_path": ".env"}, "cwd": root});
            let out = decide(
                &normalized(ev, &root, "secret path '.env' is blocked"),
                &amb,
                caps,
            );
            assert!(
                matches!(out.decision, Decision::Block { .. }),
                "{label}: {out:?}"
            );
            assert!(out.metrics.is_empty(), "{label}");

            // Covered shell command -> rewrite, or Guided deny-once when the
            // host has no rewrite capability; retry then passes.
            let ev =
                json!({"tool_name": "Bash", "tool_input": {"command": "cargo test"}, "cwd": root});
            let n = normalized(ev, &root, "");
            let out = decide(&n, &amb, caps);
            if caps.rewrite {
                match &out.decision {
                    Decision::RewriteShell { rewritten, .. } => {
                        assert!(
                            rewritten.contains("compact --mode test"),
                            "{label}: {rewritten}"
                        );
                    }
                    other => panic!("{label}: expected rewrite, got {other:?}"),
                }
                assert!(
                    out.metrics.is_empty(),
                    "{label}: rewrite rows are recorded by the executed kit command"
                );
            } else {
                match &out.decision {
                    Decision::DenyOnce { reason } => {
                        assert!(reason.contains("denied once"), "{label}: {reason}");
                    }
                    other => panic!("{label}: expected deny-once, got {other:?}"),
                }
                assert_eq!(1, out.metrics.len(), "{label}");
                assert_eq!(Rule::ShellDenial, out.metrics[0].rule, "{label}");
                let retry = decide(&n, &amb, caps);
                assert_eq!(Decision::Pass, retry.decision, "{label} retry");
                assert_eq!(1, retry.metrics.len(), "{label}");
                assert_eq!(Rule::AllowedRetry, retry.metrics[0].rule, "{label}");
            }

            // Reread advisory and Use-time hint: Context only when the host
            // delivers non-blocking context.
            let file = root.join("a.py");
            fs::write(&file, "x = 1\n").unwrap();
            let ev = json!({"tool_name": "Read", "tool_input": {"file_path": "a.py"}, "cwd": root});
            let n = normalized(ev, &root, "");
            assert_eq!(
                Decision::Pass,
                decide(&n, &amb, caps).decision,
                "{label} first read"
            );
            let second = decide(&n, &amb, caps);
            if caps.deliver_context {
                match &second.decision {
                    Decision::Context { text } => {
                        assert_eq!(crate::hook::REREAD_MESSAGE, text, "{label}");
                    }
                    other => panic!("{label}: expected reread context, got {other:?}"),
                }
                assert_eq!(Rule::RereadWarning, second.metrics[0].rule, "{label}");
            } else {
                assert_eq!(Decision::Pass, second.decision, "{label} no-context reread");
            }

            let ev = json!({"tool_name": "Bash", "tool_input": {"command": "jq '.users | length' data.json"}, "cwd": root});
            let n = normalized(ev, &root, "");
            let hint = decide(&n, &amb, caps);
            if caps.deliver_context {
                match &hint.decision {
                    Decision::Context { text } => {
                        assert!(text.contains("@count"), "{label}: {text}")
                    }
                    other => panic!("{label}: expected hint context, got {other:?}"),
                }
                assert_eq!(Rule::UseTimeHint, hint.metrics[0].rule, "{label}");
                // Once per session.
                assert_eq!(
                    Decision::Pass,
                    decide(&n, &amb, caps).decision,
                    "{label} hint once"
                );
            } else {
                assert_eq!(Decision::Pass, hint.decision, "{label} no-context hint");
            }

            // Plain pass: an edit to a normal file.
            let ev =
                json!({"tool_name": "Edit", "tool_input": {"file_path": "src/a.rs"}, "cwd": root});
            let out = decide(&normalized(ev, &root, ""), &amb, caps);
            assert_eq!(Decision::Pass, out.decision, "{label} pass");
            assert!(out.metrics.is_empty(), "{label}");

            let _ = fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn droid_devin_cursor_adapters_translate_events_and_replies() {
        let (amb, root) = temp_amb("adapters104");
        let cwd = root.to_string_lossy().into_owned();
        // Droid: secret -> ask envelope; shell -> shared updatedInput envelope.
        let droid = DroidAdapter;
        let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": ".env"}, "cwd": cwd, "session_id": "s-decide"});
        let n = droid.normalize(ev.to_string().as_bytes(), &amb).unwrap();
        assert!(!n.secret_reason.is_empty());
        let reply = droid.reply(
            &Decision::Block {
                reason: n.secret_reason.clone(),
            },
            &n,
        );
        assert_eq!("ask", reply["hookSpecificOutput"]["permissionDecision"]);
        let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cargo test"}, "cwd": cwd, "session_id": "s-decide"});
        let reply = Host::Droid.run(ev.to_string().as_bytes(), &amb);
        assert!(
            reply["hookSpecificOutput"]["updatedInput"]["command"]
                .as_str()
                .is_some_and(|c| c.contains("compact --mode test")),
            "{reply}"
        );
        // Droid malformed event -> systemMessage (adapter translation).
        assert_eq!(
            json!({"systemMessage": "Hook warning: invalid-json"}),
            Host::Droid.run(b"{", &amb)
        );

        // Devin: non-PreToolUse passes before validation; secret -> ask.
        assert_eq!(
            json!({}),
            Host::Devin.run(br#"{"hook_event_name":"Stop"}"#, &amb)
        );
        let ev = json!({"hook_event_name": "PreToolUse", "tool_name": "read", "tool_input": {"file_path": ".env"}, "cwd": cwd, "session_id": "s-decide"});
        let reply = Host::Devin.run(ev.to_string().as_bytes(), &amb);
        assert_eq!("ask", reply["hookSpecificOutput"]["permissionDecision"]);

        // Cursor: beforeSubmitPrompt -> continue; secret -> Cursor deny
        // wording; shell -> flat updated_input allow envelope.
        let cursor = CursorAdapter;
        assert_eq!(
            json!({"continue": true}),
            Host::Cursor.run(br#"{"hook_event_name":"beforeSubmitPrompt"}"#, &amb)
        );
        let ev = json!({"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"relative_workspace_path": ".env"}, "workspace_roots": [cwd], "conversation_id": "s-decide"});
        let n = cursor.normalize(ev.to_string().as_bytes(), &amb).unwrap();
        assert!(
            !n.secret_reason.is_empty(),
            "cursor key list must catch relative_workspace_path"
        );
        let reply = cursor.reply(
            &Decision::Block {
                reason: n.secret_reason.clone(),
            },
            &n,
        );
        assert_eq!("deny", reply["permission"]);
        assert!(
            reply["user_message"]
                .as_str()
                .is_some_and(|t| t.starts_with("Prometheus: ")),
            "{reply}"
        );
        let ev = json!({"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "cargo test"}, "workspace_roots": [cwd], "conversation_id": "s-decide"});
        let reply = Host::Cursor.run(ev.to_string().as_bytes(), &amb);
        assert_eq!("allow", reply["permission"]);
        assert!(
            reply["updated_input"]["command"]
                .as_str()
                .is_some_and(|c| c.contains("compact --mode test")),
            "{reply}"
        );
        // Cursor malformed event passes silently (adapter translation).
        assert_eq!(json!({}), Host::Cursor.run(b"{", &amb));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn omp_opencode_antigravity_grok_adapters_translate_events_and_replies() {
        let (amb, root) = temp_amb("adapters105");
        let cwd = root.to_string_lossy().into_owned();
        // omp: secret -> block envelope; rewrite -> {"input": ...}; malformed -> block.
        let ev = json!({"tool_name": "read", "input": {"path": ".env"}, "cwd": cwd, "sessionId": "s-decide"});
        let reply = Host::Omp.run(ev.to_string().as_bytes(), &amb);
        assert_eq!(true, reply["block"], "{reply}");
        let ev = json!({"tool_name": "bash", "input": {"command": "cargo test"}, "cwd": cwd, "sessionId": "s-decide"});
        let reply = Host::Omp.run(ev.to_string().as_bytes(), &amb);
        assert!(
            reply["input"]["command"]
                .as_str()
                .is_some_and(|c| c.contains("compact --mode test")),
            "{reply}"
        );
        let reply = Host::Omp.run(b"{", &amb);
        assert_eq!(true, reply["block"], "{reply}");

        // OpenCode: secret -> deny envelope with Prometheus prefix; shell
        // commands are never rewritten or denied-once (pass), malformed -> deny.
        let ev = json!({"event_name": "pretooluse", "tool_name": "read", "tool_input": {"path": ".env"}, "cwd": cwd, "session_id": "s-decide"});
        let reply = Host::Opencode.run(ev.to_string().as_bytes(), &amb);
        assert_eq!("deny", reply["decision"], "{reply}");
        assert!(
            reply["reason"]
                .as_str()
                .is_some_and(|r| r.starts_with("Prometheus: ")),
            "{reply}"
        );
        let ev = json!({"event_name": "pretooluse", "tool_name": "bash", "tool_input": {"command": "cargo test"}, "cwd": cwd, "session_id": "s-decide"});
        assert_eq!(
            json!({}),
            Host::Opencode.run(ev.to_string().as_bytes(), &amb)
        );
        let reply = Host::Opencode.run(b"{", &amb);
        assert_eq!("deny", reply["decision"], "{reply}");

        // Antigravity: secret -> ask with raw reason; run_command rewrite ->
        // allow + overwrite; pass -> allow; malformed -> ask.
        let agy = AntigravityAdapter;
        let ev = json!({"hookEventName": "PreToolUse", "conversationId": "s-decide", "workspacePaths": [cwd], "toolCall": {"name": "view_file", "args": {"AbsolutePath": ".env"}}});
        let n = agy.normalize(ev.to_string().as_bytes(), &amb).unwrap();
        assert!(
            !n.secret_reason.is_empty(),
            "antigravity key list must catch AbsolutePath"
        );
        let reply = agy.reply(
            &Decision::Block {
                reason: n.secret_reason.clone(),
            },
            &n,
        );
        assert_eq!("ask", reply["decision"]);
        assert_eq!(n.secret_reason, reply["reason"]);
        let ev = json!({"hookEventName": "PreToolUse", "conversationId": "s-decide", "workspacePaths": [cwd], "toolCall": {"name": "run_command", "args": {"CommandLine": "cargo test"}}});
        let reply = Host::Antigravity.run(ev.to_string().as_bytes(), &amb);
        assert_eq!("allow", reply["decision"], "{reply}");
        assert!(
            reply["overwrite"]["CommandLine"]
                .as_str()
                .is_some_and(|c| c.contains("compact --mode test")),
            "{reply}"
        );
        let ev = json!({"hookEventName": "PreToolUse", "conversationId": "s-decide", "workspacePaths": [cwd], "toolCall": {"name": "list_dir", "args": {"DirectoryPath": "src"}}});
        assert_eq!(
            json!({"decision": "allow"}),
            Host::Antigravity.run(ev.to_string().as_bytes(), &amb)
        );
        let reply = Host::Antigravity.run(b"{", &amb);
        assert_eq!("ask", reply["decision"], "{reply}");

        // Grok: secret -> deny with raw reason; covered shell -> Guided
        // deny-once from the capabilities record (no rewrite), retry passes.
        let grok = GrokAdapter;
        assert_eq!(
            Capabilities {
                rewrite: false,
                ask: false,
                deliver_context: false
            },
            Host::Grok.capabilities()
        );
        let ev = json!({"hookEventName": "PreToolUse", "sessionId": "s-decide", "workspaceRoot": cwd, "toolName": "read_file", "toolInput": {"file_path": ".env"}});
        let n = grok.normalize(ev.to_string().as_bytes(), &amb).unwrap();
        assert!(
            !n.secret_reason.is_empty(),
            "grok key list must catch file_path"
        );
        let reply = grok.reply(
            &Decision::Block {
                reason: n.secret_reason.clone(),
            },
            &n,
        );
        assert_eq!("deny", reply["decision"]);
        assert_eq!(n.secret_reason, reply["reason"]);
        let ev = json!({"hookEventName": "PreToolUse", "sessionId": "s-decide-grok", "workspaceRoot": cwd, "toolName": "bash", "toolInput": {"command": "cargo test"}});
        let first = Host::Grok.run(ev.to_string().as_bytes(), &amb);
        assert_eq!("deny", first["decision"], "{first}");
        assert!(
            first["reason"]
                .as_str()
                .is_some_and(|r| r.contains("denied once")),
            "{first}"
        );
        assert_eq!(json!({}), Host::Grok.run(ev.to_string().as_bytes(), &amb));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_and_muse_adapters_reply_in_the_shared_envelope() {
        let (amb, root) = temp_amb("adapter");
        for host in [Host::Claude, Host::Muse] {
            let name = host.name();
            let ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": ".env"},
                "cwd": root,
                "session_id": "s-decide",
            });
            let reply = host.run(ev.to_string().as_bytes(), &amb);
            assert_eq!(
                "ask", reply["hookSpecificOutput"]["permissionDecision"],
                "{name}: {reply}"
            );
            let ev = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "cargo test"},
                "cwd": root,
                "session_id": "s-decide",
            });
            let reply = host.run(ev.to_string().as_bytes(), &amb);
            assert!(
                reply["hookSpecificOutput"]["updatedInput"]["command"]
                    .as_str()
                    .is_some_and(|c| c.contains("compact --mode test")),
                "{name}: {reply}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }
}
