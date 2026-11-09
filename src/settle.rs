//! Findings and evidence settlement (spec #43, ticket #54): round-to-round
//! settlement of findings, round accounting, and coverage reconciliation
//! over fresh facts.
//!
//! Settlement is always recomputed over fresh facts and never cached
//! (ADR-0005). Materiality is an INPUT to every function in this module —
//! the reviewer's recorded flag on each finding, consumed exactly as
//! `sureforge_model` consumes it — and never an output: no document here
//! classifies a finding as material or non-material. The Python runtime
//! (`sureforge_hook._python_settle_*`, composing `sureforge_model`) stays
//! the behavioural oracle (ADR-0007 D5): the gate negotiates
//! `SETTLE_SCHEMA` before delegating, validates each returned document,
//! and reruns the whole call on the Python route on any failure here.

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFrozenSet, PyInt, PyList, PySet, PyString, PyTuple};
use std::collections::{BTreeMap, HashSet};

/// The settlement document schema this build speaks. The gate runtime
/// delegates only when this equals the schema it was written against; any
/// other value keeps the runtime on its own route.
pub const SETTLE_SCHEMA: u32 = 1;

/// Tier round caps (sureforge_model.ROUND_CAP — the configuration table).
fn round_cap(tier: &str) -> Option<i64> {
    match tier {
        "light" => Some(3),
        "standard" => Some(3),
        "full" => Some(5),
        _ => None,
    }
}

fn type_err(message: &str) -> PyErr {
    PyTypeError::new_err(message.to_string())
}

/// True when `value` is exactly a Python int (a bool is not an int here,
/// exactly as `type(value) is int` judges in the oracle).
fn exact_int(value: &Bound<'_, PyAny>) -> Option<i64> {
    if value.is_instance_of::<PyBool>() {
        return None;
    }
    value.cast::<PyInt>().ok()?.extract::<i64>().ok()
}

fn text(value: &Bound<'_, PyAny>) -> Option<String> {
    let string = value.cast::<PyString>().ok()?;
    let owned = string.to_string_lossy().into_owned();
    if owned.trim().is_empty() {
        None
    } else {
        Some(owned)
    }
}

// ---------------------------------------------------------------------------
// Round accounting: model.parse_history + model._rounds_blocked, plus the
// hook-owned round counter (_owned_round).

enum ParsedHistory {
    Absent,
    Tampered,
    Present(BTreeMap<i64, HashSet<String>>),
}

/// model.parse_history over the raw phase value: None is absent; any
/// non-map value is ill-shaped, hence tampered (the wrapper encodes the
/// hook's TAMPERED sentinel as the string "tampered", itself not a map).
fn parse_history(history: &Bound<'_, PyAny>) -> ParsedHistory {
    if history.is_none() {
        return ParsedHistory::Absent;
    }
    let Ok(map) = history.cast::<PyDict>() else {
        return ParsedHistory::Tampered;
    };
    let mut parsed: BTreeMap<i64, HashSet<String>> = BTreeMap::new();
    for (key, reasons) in map.iter() {
        let number = if let Some(value) = exact_int(&key) {
            value
        } else if let Ok(string) = key.cast::<PyString>() {
            let raw = string.to_string_lossy().into_owned();
            // `key.isdigit() and str(int(key)) == key`: canonical ASCII
            // digits only ("03", "+3", and blank keys are all ill-shaped).
            if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                return ParsedHistory::Tampered;
            }
            match raw.parse::<i64>() {
                Ok(value) if value.to_string() == raw => value,
                _ => return ParsedHistory::Tampered,
            }
        } else {
            return ParsedHistory::Tampered;
        };
        if number < 1 || parsed.contains_key(&number) {
            return ParsedHistory::Tampered;
        }
        let iterable = reasons.is_instance_of::<PyList>()
            || reasons.is_instance_of::<PyTuple>()
            || reasons.is_instance_of::<PySet>()
            || reasons.is_instance_of::<PyFrozenSet>();
        if !iterable {
            return ParsedHistory::Tampered;
        }
        let Ok(items) = reasons.try_iter() else {
            return ParsedHistory::Tampered;
        };
        let mut cleaned: HashSet<String> = HashSet::new();
        for item in items {
            let Ok(item) = item else {
                return ParsedHistory::Tampered;
            };
            let Some(reason) = text(&item) else {
                return ParsedHistory::Tampered;
            };
            if !cleaned.insert(reason) {
                return ParsedHistory::Tampered; // a repeated reason
            }
        }
        parsed.insert(number, cleaned);
    }
    ParsedHistory::Present(parsed)
}

fn previous_reasons<'a>(
    parsed: &'a ParsedHistory,
    round_number: i64,
) -> Option<&'a HashSet<String>> {
    match parsed {
        ParsedHistory::Present(map) if !map.is_empty() => map.get(&(round_number - 1)),
        _ => None,
    }
}

fn strict_subset(current: &HashSet<String>, previous: &HashSet<String>) -> bool {
    current.len() < previous.len() && current.iter().all(|gap| previous.contains(gap))
}

/// model._rounds_blocked: block when the cap is hit, the reason set
/// stalled or grew, or the history is unusable.
fn rounds_blocked(
    tier: &str,
    cap: i64,
    round_number: i64,
    current: &HashSet<String>,
    parsed: &ParsedHistory,
) -> bool {
    if tier == "light" {
        return round_number >= cap;
    }
    if let ParsedHistory::Tampered = parsed {
        return true;
    }
    if round_number > 1 {
        let Some(previous) = previous_reasons(parsed, round_number) else {
            return true;
        };
        if current == previous || (round_number >= 3 && !strict_subset(current, previous)) {
            return true;
        }
    }
    round_number >= cap
}

#[pyfunction]
fn round_account<'py>(
    py: Python<'py>,
    tier: &Bound<'py, PyAny>,
    round_number: &Bound<'py, PyAny>,
    gaps: &Bound<'py, PyAny>,
    history: &Bound<'py, PyAny>,
) -> PyResult<Py<PyDict>> {
    let tier_text = tier
        .cast::<PyString>()
        .map(|value| value.to_string_lossy().into_owned())
        .ok();
    let cap = tier_text.as_deref().and_then(round_cap);
    let round = exact_int(round_number);
    let mut current: HashSet<String> = HashSet::new();
    let gaps_iterable = gaps.is_instance_of::<PyList>()
        || gaps.is_instance_of::<PyTuple>()
        || gaps.is_instance_of::<PySet>()
        || gaps.is_instance_of::<PyFrozenSet>();
    if !gaps_iterable {
        return Err(type_err("gaps: expected a list of reason strings"));
    }
    for item in gaps.try_iter()? {
        let item = item?;
        let Ok(string) = item.cast::<PyString>() else {
            return Err(type_err("gaps: expected reason strings"));
        };
        current.insert(string.to_string_lossy().into_owned());
    }
    let parsed = parse_history(history);
    let state = match parsed {
        ParsedHistory::Absent => "absent",
        ParsedHistory::Tampered => "tampered",
        ParsedHistory::Present(_) => "present",
    };
    let previous = round.and_then(|number| previous_reasons(&parsed, number));
    let strictly_shrank = previous.map(|set| strict_subset(&current, set));
    let valid = cap.is_some() && round.is_some();
    let blocked = match (tier_text.as_deref(), cap, round) {
        (Some(name), Some(cap_value), Some(number)) => {
            Some(rounds_blocked(name, cap_value, number, &current, &parsed))
        }
        _ => None,
    };
    let doc = PyDict::new(py);
    doc.set_item("schema", SETTLE_SCHEMA)?;
    doc.set_item("valid", valid)?;
    doc.set_item("tier", tier_text)?;
    doc.set_item("cap", cap)?;
    doc.set_item("round", round)?;
    doc.set_item("blocked", blocked)?;
    doc.set_item("strictly_shrank", strictly_shrank)?;
    doc.set_item("history", state)?;
    match previous {
        Some(set) => {
            let mut sorted: Vec<&String> = set.iter().collect();
            sorted.sort();
            doc.set_item("previous_reasons", sorted)?;
        }
        None => doc.set_item("previous_reasons", py.None())?,
    }
    Ok(doc.unbind())
}

/// The hook's round counter (_owned_round): a fingerprint change advances
/// the round, clamped to the tier cap; a missing previous fingerprint (or
/// an unmeasurable tree) binds without advancing.
#[pyfunction]
fn owned_round(prev: i64, prev_fingerprint: &str, tree: &str, cap: i64) -> i64 {
    if prev < 1 {
        return 1;
    }
    let number = if !tree.is_empty() && !prev_fingerprint.is_empty() && tree != prev_fingerprint {
        prev + 1
    } else {
        prev
    };
    if number > cap {
        cap
    } else {
        number
    }
}

// ---------------------------------------------------------------------------
// Findings settlement: model._finding_gaps over raw finding dicts, in the
// union of the two dialects the repo records — the gate record's fields
// (canonical_id, resolution, deferral fields, scope_decision) and the eval
// model's (duplicate_of, counterevidence, criterion, deferral object,
// resolved). Fields of one dialect never fire on the other's records.

const CLASSIFICATIONS: [&str; 5] = [
    "confirmed",
    "refuted-with-evidence",
    "unresolved",
    "duplicate",
    "out-of-scope",
];

fn get<'py>(row: &Bound<'py, PyDict>, key: &str) -> Option<Bound<'py, PyAny>> {
    row.get_item(key).ok().flatten()
}

fn raw_str(value: &Bound<'_, PyAny>) -> Option<String> {
    value
        .cast::<PyString>()
        .map(|string| string.to_string_lossy().into_owned())
        .ok()
}

fn exact_bool(value: &Bound<'_, PyAny>) -> Option<bool> {
    value.cast::<PyBool>().ok().map(|flag| flag.is_true())
}

/// (artifact, contract, environment), each a non-blank string.
#[derive(Clone, PartialEq)]
struct Snap(Vec<String>);

fn snapshot_triple(value: &Bound<'_, PyAny>) -> Option<Snap> {
    let dict = value.cast::<PyDict>().ok()?;
    let mut parts = Vec::with_capacity(3);
    for key in ["artifact", "contract", "environment"] {
        parts.push(text(&get(&dict, key)?)?);
    }
    Some(Snap(parts))
}

/// model.applicable over a raw evidence dict.
fn evidence_applicable(
    row: &Bound<'_, PyAny>,
    target: Option<&Snap>,
    role: Option<&str>,
    require_pass: bool,
) -> bool {
    let Some(target) = target else { return false };
    let Ok(dict) = row.cast::<PyDict>() else {
        return false;
    };
    let Some(snap) = get(&dict, "snapshot").and_then(|value| snapshot_triple(&value)) else {
        return false;
    };
    let Some(passed) = get(&dict, "passed").and_then(|value| exact_bool(&value)) else {
        return false;
    };
    if require_pass && !passed {
        return false;
    }
    for key in ["id", "unit", "observation", "locator"] {
        if get(&dict, key).map_or(true, |value| text(&value).is_none()) {
            return false;
        }
    }
    let row_role = get(&dict, "role").and_then(|value| raw_str(&value));
    match row_role.as_deref() {
        Some("owner") | Some("reviewer") | Some("critic") => {}
        _ => return false,
    }
    if let Some(want) = role {
        if row_role.as_deref() != Some(want) {
            return false;
        }
    }
    let reuse = get(&dict, "reuse_target").and_then(|value| snapshot_triple(&value));
    let status = get(&dict, "status").and_then(|value| raw_str(&value));
    match status.as_deref() {
        Some("fresh") => &snap == target && reuse.is_none(),
        Some("failed") if !require_pass => &snap == target && reuse.is_none(),
        Some("reused") => {
            reuse.as_ref() == Some(target)
                && get(&dict, "applicability_checked")
                    .and_then(|value| exact_bool(&value))
                    == Some(true)
                && get(&dict, "reuse_reason").map_or(false, |value| text(&value).is_some())
                && get(&dict, "applicability_evidence")
                    .map_or(false, |value| text(&value).is_some())
        }
        _ => false,
    }
}

/// A recorded deferral: decision, reason, and follow-up, all non-blank —
/// the gate record's flat fields or the eval model's `deferral` object.
fn deferral_complete(dict: &Bound<'_, PyDict>) -> bool {
    let flat = ["deferral_decision", "deferral_reason", "follow_up"]
        .iter()
        .all(|key| get(dict, key).map_or(false, |value| text(&value).is_some()));
    if flat {
        return true;
    }
    if let Some(block) = get(dict, "deferral") {
        if let Ok(block) = block.cast::<PyDict>() {
            return ["decision", "reason", "follow_up"]
                .iter()
                .all(|key| get(&block, key).map_or(false, |value| text(&value).is_some()));
        }
    }
    false
}

fn counterevidence_cited(dict: &Bound<'_, PyDict>) -> bool {
    let Some(cited) = get(dict, "counterevidence") else {
        return false;
    };
    if let Some(text) = raw_str(&cited) {
        return !text.trim().is_empty();
    }
    let countable = cited.is_instance_of::<PyList>()
        || cited.is_instance_of::<PyTuple>()
        || cited.is_instance_of::<PySet>()
        || cited.is_instance_of::<PyFrozenSet>();
    countable && cited.len().map_or(false, |len| len > 0)
}

struct Invalid {
    id: Option<String>,
    reason: &'static str,
}

struct Entry {
    id: String,
    canonical: Option<String>,
    classification: Option<Py<PyAny>>,
    gaps: Vec<String>,
    settled: bool,
}

/// Walk duplicate links to the canonical finding, as model._finding_gaps
/// does. Returns (canonical index, problem): the problem is
/// "duplicate-without-canonical" (missing target, unknown target, or a
/// self-link) or "duplicate-cycle".
fn finding_chain(
    rows: &[Bound<'_, PyDict>],
    known: &std::collections::HashMap<String, usize>,
    start: usize,
) -> (Option<usize>, Option<&'static str>) {
    let mut current = start;
    let mut visited: HashSet<usize> = HashSet::new();
    loop {
        let dict = &rows[current];
        let classification = get(dict, "classification").and_then(|value| raw_str(&value));
        if classification.as_deref() != Some("duplicate") {
            return (Some(current), None);
        }
        if visited.contains(&current) {
            return (None, Some("duplicate-cycle"));
        }
        visited.insert(current);
        let target = get(dict, "canonical_id")
            .and_then(|value| raw_str(&value))
            .filter(|value| !value.is_empty())
            .or_else(|| {
                get(dict, "duplicate_of")
                    .and_then(|value| raw_str(&value))
                    .filter(|value| !value.is_empty())
            });
        let current_id = get(dict, "id").and_then(|value| raw_str(&value));
        match target {
            Some(target)
                if current_id.as_ref() != Some(&target) && known.contains_key(&target) =>
            {
                current = known[&target];
            }
            _ => return (None, Some("duplicate-without-canonical")),
        }
    }
}

/// One finding's settlement entry, mirroring _assess_finding in the hook:
/// the decided gaps for its canonical finding, or why the record is
/// invalid. Materiality is read from the record, never decided here.
fn assess_finding(
    rows: &[Bound<'_, PyDict>],
    known: &std::collections::HashMap<String, usize>,
    index: usize,
    target: Option<&Snap>,
    criteria: Option<&HashSet<String>>,
) -> (Option<Entry>, Option<Invalid>) {
    let dict = &rows[index];
    let Some(fid) = get(dict, "id").and_then(|value| text(&value)) else {
        return (None, Some(Invalid { id: None, reason: "invalid-finding" }));
    };
    let classification = get(dict, "classification").and_then(|value| raw_str(&value));
    if !matches!(classification.as_deref(), Some(name) if CLASSIFICATIONS.contains(&name)) {
        return (None, Some(Invalid { id: Some(fid), reason: "invalid-finding" }));
    }
    if let Some(material) = get(dict, "material") {
        if exact_bool(&material).is_none() {
            return (None, Some(Invalid { id: Some(fid), reason: "invalid-finding" }));
        }
    }
    let classification = classification.expect("checked above");
    if get(dict, "resolved").and_then(|value| exact_bool(&value)) == Some(true) {
        return (
            Some(Entry {
                id: fid.clone(),
                canonical: Some(fid),
                classification: Some(get(dict, "classification").expect("present").unbind()),
                gaps: Vec::new(),
                settled: true,
            }),
            None,
        );
    }
    let _ = classification;
    let (canonical_index, problem) = finding_chain(rows, known, index);
    if let Some(reason) = problem {
        return (None, Some(Invalid { id: Some(fid), reason }));
    }
    let canonical = &rows[canonical_index.expect("chain resolved")];
    let own = get(dict, "material").and_then(|value| exact_bool(&value));
    let inherited = get(canonical, "material").and_then(|value| exact_bool(&value));
    let material = own.unwrap_or(false) || inherited.unwrap_or(false);
    let has_resolution = get(canonical, "resolution")
        .as_ref()
        .map_or(false, |value| evidence_applicable(value, target, None, true));
    let canonical_classification = get(canonical, "classification");
    let canonical_name = canonical_classification
        .as_ref()
        .and_then(|value| raw_str(value));
    let mut gaps: Vec<String> = Vec::new();
    let mut invalid: Option<Invalid> = None;
    match canonical_name.as_deref() {
        Some("confirmed") => {
            if !has_resolution && !(!material && deferral_complete(canonical)) {
                gaps.push("unclosed-finding".to_string());
            }
        }
        Some("refuted-with-evidence") => {
            if !has_resolution && !counterevidence_cited(canonical) {
                gaps.push("unsupported-refutation".to_string());
                invalid = Some(Invalid {
                    id: Some(fid.clone()),
                    reason: "refuted-without-counterevidence",
                });
            }
        }
        Some("unresolved") => {
            if material {
                gaps.push("unresolved-finding".to_string());
            }
        }
        Some("out-of-scope") => {
            let criterion = get(canonical, "criterion");
            let criterion_name = criterion.as_ref().and_then(|value| raw_str(value));
            let criterion_present = canonical.contains("criterion").unwrap_or(false);
            let scope_decision = get(canonical, "scope_decision")
                .map_or(false, |value| text(&value).is_some());
            let names_required = match (criteria, criterion_name.as_ref()) {
                (Some(required), Some(name)) => required.contains(name),
                _ => false,
            };
            if names_required {
                invalid = Some(Invalid {
                    id: Some(fid.clone()),
                    reason: "out-of-scope-required-criterion",
                });
            } else if has_resolution && scope_decision {
                // Settled on the gate's terms: evidence plus a recorded decision.
            } else if criterion_present {
                // Settled on the eval model's terms: the criterion key is
                // present and names no required criterion (checked above).
            } else {
                gaps.push("unsupported-exclusion".to_string());
            }
        }
        _ => {}
    }
    let settled = gaps.is_empty() && invalid.is_none();
    (
        Some(Entry {
            id: fid,
            canonical: get(canonical, "id").and_then(|value| raw_str(&value)),
            classification: canonical_classification.map(|value| value.unbind()),
            gaps,
            settled,
        }),
        invalid,
    )
}

struct FindingsDoc {
    invalid: Vec<Invalid>,
    entries: Vec<Entry>,
    gaps: Vec<String>,
}

fn settle_findings_impl(
    findings: &Bound<'_, PyList>,
    snapshot: &Bound<'_, PyAny>,
    criteria: Option<&HashSet<String>>,
) -> FindingsDoc {
    let target = snapshot_triple(snapshot);
    let mut invalid: Vec<Invalid> = Vec::new();
    let mut known: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut dicts: Vec<Bound<'_, PyDict>> = Vec::new();
    for item in findings.iter() {
        let Ok(dict) = item.cast::<PyDict>() else {
            invalid.push(Invalid { id: None, reason: "invalid-finding" });
            continue;
        };
        if let Some(fid) = get(&dict, "id").and_then(|value| text(&value)) {
            if known.contains_key(&fid) {
                invalid.push(Invalid { id: Some(fid), reason: "duplicate-id" });
            } else {
                known.insert(fid, dicts.len());
            }
        }
        dicts.push(dict.clone());
    }
    let mut entries: Vec<Entry> = Vec::new();
    let mut gaps: Vec<String> = Vec::new();
    for (index, dict) in dicts.iter().enumerate() {
        if let Some(fid) = get(dict, "id").and_then(|value| text(&value)) {
            if !dicts[known[&fid]].is(dict) {
                continue; // a repeated id is reported once, as invalid
            }
        }
        let (entry, problem) = assess_finding(&dicts, &known, index, target.as_ref(), criteria);
        if let Some(problem) = problem {
            invalid.push(problem);
        }
        if let Some(entry) = entry {
            gaps.extend(entry.gaps.iter().cloned());
            entries.push(entry);
        }
    }
    FindingsDoc { invalid, entries, gaps }
}

fn invalid_list(py: Python<'_>, invalid: &[Invalid]) -> PyResult<Py<PyList>> {
    let list = PyList::empty(py);
    for item in invalid {
        let row = PyDict::new(py);
        row.set_item("id", item.id.as_deref())?;
        row.set_item("reason", item.reason)?;
        list.append(row)?;
    }
    Ok(list.unbind())
}

fn findings_document(py: Python<'_>, doc: &FindingsDoc) -> PyResult<Py<PyDict>> {
    let out = PyDict::new(py);
    out.set_item("schema", SETTLE_SCHEMA)?;
    out.set_item("valid", doc.invalid.is_empty())?;
    out.set_item("invalid", invalid_list(py, &doc.invalid)?)?;
    let entries = PyList::empty(py);
    for entry in &doc.entries {
        let row = PyDict::new(py);
        row.set_item("id", &entry.id)?;
        row.set_item("canonical", entry.canonical.as_deref())?;
        match &entry.classification {
            Some(value) => row.set_item("classification", value.bind(py))?,
            None => row.set_item("classification", py.None())?,
        }
        row.set_item("gaps", &entry.gaps)?;
        row.set_item("settled", entry.settled)?;
        entries.append(row)?;
    }
    out.set_item("entries", entries)?;
    out.set_item("gaps", &doc.gaps)?;
    Ok(out.unbind())
}

fn criteria_set(criteria: Option<&Bound<'_, PyAny>>) -> Option<HashSet<String>> {
    let criteria = criteria?;
    if criteria.is_none() {
        return None;
    }
    let mut set = HashSet::new();
    if let Ok(items) = criteria.try_iter() {
        for item in items.flatten() {
            if let Some(value) = raw_str(&item) {
                set.insert(value);
            }
        }
    }
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

#[pyfunction]
#[pyo3(signature = (findings, snapshot, criteria=None))]
fn settle_findings<'py>(
    py: Python<'py>,
    findings: &Bound<'py, PyList>,
    snapshot: &Bound<'py, PyAny>,
    criteria: Option<Bound<'py, PyAny>>,
) -> PyResult<Py<PyDict>> {
    let doc = settle_findings_impl(findings, snapshot, criteria_set(criteria.as_ref()).as_ref());
    findings_document(py, &doc)
}

fn push_invalid(
    invalid: &mut Vec<Invalid>,
    seen: &mut HashSet<(Option<String>, &'static str)>,
    item: Invalid,
) {
    if seen.insert((item.id.clone(), item.reason)) {
        invalid.push(item);
    }
}

#[pyfunction]
#[pyo3(signature = (previous, previous_snapshot, current, snapshot, criteria=None))]
fn settle_rounds<'py>(
    py: Python<'py>,
    previous: &Bound<'py, PyList>,
    previous_snapshot: &Bound<'py, PyAny>,
    current: &Bound<'py, PyList>,
    snapshot: &Bound<'py, PyAny>,
    criteria: Option<Bound<'py, PyAny>>,
) -> PyResult<Py<PyDict>> {
    let criteria = criteria_set(criteria.as_ref());
    let prev_doc = settle_findings_impl(previous, previous_snapshot, criteria.as_ref());
    let cur_doc = settle_findings_impl(current, snapshot, criteria.as_ref());
    let cur_invalid_ids: HashSet<Option<String>> =
        cur_doc.invalid.iter().map(|item| item.id.clone()).collect();
    let mut invalid: Vec<Invalid> = Vec::new();
    let mut seen: HashSet<(Option<String>, &'static str)> = HashSet::new();
    for item in prev_doc.invalid {
        push_invalid(&mut invalid, &mut seen, item);
    }
    for item in cur_doc.invalid {
        push_invalid(&mut invalid, &mut seen, item);
    }
    let prev_entries: std::collections::HashMap<&str, &Entry> =
        prev_doc.entries.iter().map(|entry| (entry.id.as_str(), entry)).collect();
    let cur_entries: std::collections::HashMap<&str, &Entry> =
        cur_doc.entries.iter().map(|entry| (entry.id.as_str(), entry)).collect();
    let prev_canonicals: HashSet<&str> = prev_doc
        .entries
        .iter()
        .filter_map(|entry| entry.canonical.as_deref())
        .collect();
    let settled = PyList::empty(py);
    for entry in &prev_doc.entries {
        let fid = &entry.id;
        if cur_invalid_ids.contains(&Some(fid.clone())) {
            continue;
        }
        let current_entry = cur_entries
            .get(fid.as_str())
            .copied()
            .or_else(|| entry.canonical.as_deref().and_then(|id| cur_entries.get(id).copied()));
        if let Some(current_entry) = current_entry {
            let row = PyDict::new(py);
            row.set_item("id", fid)?;
            row.set_item(
                "state",
                if current_entry.settled { "repaired" } else { "still-open" },
            )?;
            settled.append(row)?;
        } else if entry
            .canonical
            .as_ref()
            .map_or(false, |id| cur_invalid_ids.contains(&Some(id.clone())))
        {
            push_invalid(
                &mut invalid,
                &mut seen,
                Invalid { id: Some(fid.clone()), reason: "invalid-canonical" },
            );
        } else if !entry.settled {
            push_invalid(
                &mut invalid,
                &mut seen,
                Invalid { id: Some(fid.clone()), reason: "dropped-without-disposition" },
            );
        }
    }
    for entry in &cur_doc.entries {
        if prev_entries.contains_key(entry.id.as_str())
            || cur_invalid_ids.contains(&Some(entry.id.clone()))
        {
            continue;
        }
        if entry
            .canonical
            .as_deref()
            .map_or(false, |id| prev_canonicals.contains(id) || prev_entries.contains_key(id))
        {
            continue;
        }
        let row = PyDict::new(py);
        row.set_item("id", &entry.id)?;
        row.set_item("state", "introduced")?;
        settled.append(row)?;
    }
    let out = PyDict::new(py);
    out.set_item("schema", SETTLE_SCHEMA)?;
    out.set_item("valid", invalid.is_empty())?;
    out.set_item("invalid", invalid_list(py, &invalid)?)?;
    out.set_item("settled", settled)?;
    Ok(out.unbind())
}

// ---------------------------------------------------------------------------
// Coverage reconciliation against the frozen plan denominator.

fn unit_category(rows: &[Bound<'_, PyDict>], target: Option<&Snap>) -> &'static str {
    if rows.iter().any(|row| {
        evidence_applicable(row.as_any(), target, None, false)
            && get(row, "passed").and_then(|value| exact_bool(&value)) == Some(false)
    }) {
        return "failed";
    }
    if rows
        .iter()
        .any(|row| evidence_applicable(row.as_any(), target, None, true))
    {
        return "covered";
    }
    if rows.iter().any(|row| {
        get(row, "status").and_then(|value| raw_str(&value)).as_deref() == Some("blocked")
    }) {
        return "blocked";
    }
    if rows.iter().any(|row| {
        get(row, "status").and_then(|value| raw_str(&value)).as_deref() == Some("reused")
    }) {
        return "reused-without-reason";
    }
    if rows.is_empty() {
        "missing"
    } else {
        "stale"
    }
}

#[pyfunction]
#[pyo3(signature = (units, evidence, snapshot, role="owner", claimed_units=None))]
fn reconcile_coverage<'py>(
    py: Python<'py>,
    units: &Bound<'py, PyList>,
    evidence: &Bound<'py, PyList>,
    snapshot: &Bound<'py, PyAny>,
    role: &str,
    claimed_units: Option<Bound<'py, PyAny>>,
) -> PyResult<Py<PyDict>> {
    let target = snapshot_triple(snapshot);
    let mut denominator: Vec<String> = Vec::new();
    let mut invalid_units: Vec<usize> = Vec::new();
    for (index, item) in units.iter().enumerate() {
        match text(&item) {
            Some(unit) if !denominator.contains(&unit) => denominator.push(unit),
            Some(_) => {}
            None => invalid_units.push(index),
        }
    }
    denominator.sort();
    let plan: HashSet<&str> = denominator.iter().map(|unit| unit.as_str()).collect();
    let mut rows_by_unit: std::collections::HashMap<String, Vec<Bound<'_, PyDict>>> =
        std::collections::HashMap::new();
    let mut extra_units: HashSet<String> = HashSet::new();
    let mut invalid_rows: Vec<(usize, &'static str)> = Vec::new();
    let mut seen_ids: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut other_role_rows: usize = 0;
    for (index, item) in evidence.iter().enumerate() {
        let Ok(dict) = item.cast::<PyDict>() else {
            invalid_rows.push((index, "not-an-object"));
            continue;
        };
        let Some(eid) = get(&dict, "id").and_then(|value| text(&value)) else {
            invalid_rows.push((index, "missing-id"));
            continue;
        };
        *seen_ids.entry(eid).or_insert(0) += 1;
        let Some(unit) = get(&dict, "unit").and_then(|value| text(&value)) else {
            invalid_rows.push((index, "missing-unit"));
            continue;
        };
        if get(&dict, "role").and_then(|value| raw_str(&value)).as_deref() != Some(role) {
            other_role_rows += 1;
            continue;
        }
        if plan.contains(unit.as_str()) {
            rows_by_unit.entry(unit).or_default().push(dict.clone());
        } else {
            extra_units.insert(unit);
        }
    }
    let rows_list = PyList::empty(py);
    let mut covered: Vec<String> = Vec::new();
    let mut complete = true;
    for unit in &denominator {
        let unit_rows: Vec<Bound<'_, PyDict>> =
            rows_by_unit.get(unit).cloned().unwrap_or_default();
        let category = unit_category(&unit_rows, target.as_ref());
        if category == "covered" {
            covered.push(unit.clone());
        } else {
            complete = false;
        }
        let mut ids: Vec<String> = unit_rows
            .iter()
            .filter_map(|row| get(row, "id").and_then(|value| raw_str(&value)))
            .collect();
        ids.sort();
        let row = PyDict::new(py);
        row.set_item("unit", unit)?;
        row.set_item("category", category)?;
        row.set_item("evidence", ids)?;
        rows_list.append(row)?;
    }
    let claimed: Option<HashSet<String>> = if claimed_units.is_none() {
        None
    } else {
        let mut set = HashSet::new();
        if let Ok(items) = claimed_units.expect("checked").try_iter() {
            for item in items.flatten() {
                if let Some(value) = text(&item) {
                    set.insert(value);
                }
            }
        }
        Some(set)
    };
    let mut shrunk: Vec<String> = match &claimed {
        Some(set) => denominator
            .iter()
            .filter(|unit| !set.contains(*unit))
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    shrunk.sort();
    let mut extra_sorted: Vec<String> = extra_units.into_iter().collect();
    extra_sorted.sort();
    let invalid_rows_list = PyList::empty(py);
    for (index, reason) in &invalid_rows {
        let row = PyDict::new(py);
        row.set_item("index", index)?;
        row.set_item("reason", reason)?;
        invalid_rows_list.append(row)?;
    }
    let mut duplicate_ids: Vec<String> = seen_ids
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(eid, _)| eid.clone())
        .collect();
    duplicate_ids.sort();
    let out = PyDict::new(py);
    out.set_item("schema", SETTLE_SCHEMA)?;
    out.set_item("role", role)?;
    out.set_item("denominator", &denominator)?;
    out.set_item("denominator_shrunk", !shrunk.is_empty())?;
    out.set_item("shrunk_units", shrunk)?;
    out.set_item("rows", rows_list)?;
    out.set_item("extra_units", extra_sorted)?;
    out.set_item("invalid_rows", invalid_rows_list)?;
    out.set_item("invalid_units", invalid_units)?;
    out.set_item("duplicate_ids", duplicate_ids)?;
    out.set_item("other_role_rows", other_role_rows)?;
    out.set_item("covered", covered)?;
    out.set_item("complete", complete)?;
    Ok(out.unbind())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SETTLE_SCHEMA", SETTLE_SCHEMA)?;
    m.add_function(wrap_pyfunction!(round_account, m)?)?;
    m.add_function(wrap_pyfunction!(owned_round, m)?)?;
    m.add_function(wrap_pyfunction!(settle_findings, m)?)?;
    m.add_function(wrap_pyfunction!(settle_rounds, m)?)?;
    m.add_function(wrap_pyfunction!(reconcile_coverage, m)?)?;
    Ok(())
}
