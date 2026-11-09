//! The gate decision (spec #43, ticket #55): `sureforge_model.decide`
//! composed with the hook's `gate_from_json`, ported behind shadow mode
//! (ADR-0007 D6).
//!
//! The decision is the pure (record, history, inherited) -> verdict-and-
//! reasons function the gate runs on every Stop. This module reproduces
//! both layers of the Python composition exactly: `gate_from_json`'s
//! extraction (any failure there is the oracle's BLOCKED/invalid-record,
//! exactly as `load_decision` maps it) and `model.decide`'s own validation
//! and rule order (whose ValueError/TypeError/AttributeError surface is the
//! same BLOCKED/invalid-record). The Python runtime stays the behavioural
//! oracle (ADR-0007 D5) and the governing implementation: the hook calls
//! this function only in shadow, records divergences in the session usage
//! log, and never lets an answer here govern a Stop.
//!
//! ADR-0005 binds the port twice over. Verdicts are computed fresh from
//! the three arguments on every call — this module holds no state, reads
//! no files, and caches nothing — and the Stop blocking classes and round
//! caps below are `sureforge_model`'s own table, unchanged. Materiality is
//! an INPUT (the reviewer's recorded flag on each finding) and never an
//! output, exactly as in the model and the settlement module.
//!
//! Round accounting reuses the settlement module's caps; the history
//! parse is decide-faithful rather than settlement-faithful in one corner:
//! a key that is all digits but not a decimal integer (a superscript two,
//! say) makes `model.parse_history` raise ValueError, which `model.decide`
//! turns into invalid-record, where settlement's parse reports the history
//! as tampered. The parse here is also lazy in the same place the model's
//! is: it runs only inside round accounting, which light tier never
//! reaches and a blocked or clean gate never needs.

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyFrozenSet, PyInt, PyList, PySet, PyString, PyTuple};
use std::collections::{HashMap, HashSet};

/// The decision document schema this build speaks. The gate runtime
/// shadows only when this equals the schema it was written against.
pub const DECIDE_SCHEMA: u32 = 1;

/// Tier round caps (sureforge_model.ROUND_CAP — the configuration table).
fn round_cap(tier: &str) -> Option<i64> {
    match tier {
        "light" => Some(3),
        "standard" => Some(3),
        "full" => Some(5),
        _ => None,
    }
}

/// Tier ranks for the tier-lowering guard (sureforge_model.TIER_RANK).
fn tier_rank(tier: &str) -> Option<i64> {
    match tier {
        "light" => Some(1),
        "standard" => Some(2),
        "full" => Some(3),
        _ => None,
    }
}

/// The composed oracle answers BLOCKED/invalid-record: `gate_from_json`
/// raising (KeyError/TypeError/ValueError in extraction) or
/// `model._decide` failing validation or raising through a rule. Every
/// fallible step below returns this in place of the Python exception.
#[derive(Debug)]
struct Invalid;

type DResult<T> = Result<T, Invalid>;

// ---------------------------------------------------------------------------
// Raw values. The oracle distinguishes Python types exactly (`type(x) is
// bool`, `isinstance(x, str)`), and `gate_from_json` carries most fields
// through unexamined, so extraction keeps a scalar's kind beside its value.

#[derive(Clone, Debug)]
enum Scalar {
    None,
    Bool(bool),
    Int(i64),
    /// A Python int outside i64 range: hashable and truthy, and only ever
    /// compared against strings downstream, where it is never equal.
    HugeInt,
    Float(f64),
    Str(String),
    /// A container or other object; only its Python truthiness and
    /// hashability can matter downstream (such a value is never text and
    /// never equal to a string).
    Other { truthy: bool, unhashable: bool },
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Scalar::None, Scalar::None) => true,
            (Scalar::Bool(a), Scalar::Bool(b)) => a == b,
            (Scalar::Int(a), Scalar::Int(b)) => a == b,
            (Scalar::HugeInt, Scalar::HugeInt) => true,
            (Scalar::Float(a), Scalar::Float(b)) => a.to_bits() == b.to_bits(),
            (Scalar::Str(a), Scalar::Str(b)) => a == b,
            (
                Scalar::Other { truthy: a, unhashable: x },
                Scalar::Other { truthy: b, unhashable: y },
            ) => a == b && x == y,
            _ => false,
        }
    }
}

impl Eq for Scalar {}

impl std::hash::Hash for Scalar {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Scalar::Bool(value) => value.hash(state),
            Scalar::Int(value) => value.hash(state),
            Scalar::Float(value) => value.to_bits().hash(state),
            Scalar::Str(value) => value.hash(state),
            Scalar::Other { truthy, unhashable } => (truthy, unhashable).hash(state),
            Scalar::None | Scalar::HugeInt => {}
        }
    }
}

impl Scalar {
    /// Python truthiness of a JSON-shaped value.
    fn truthy(&self) -> bool {
        match self {
            Scalar::None => false,
            Scalar::Bool(value) => *value,
            Scalar::Int(value) => *value != 0,
            Scalar::HugeInt => true,
            Scalar::Float(value) => *value != 0.0,
            Scalar::Str(value) => !value.is_empty(),
            Scalar::Other { truthy, .. } => *truthy,
        }
    }

    /// model._text: a string with non-whitespace content.
    fn is_text(&self) -> bool {
        matches!(self, Scalar::Str(value) if !value.trim().is_empty())
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Scalar::Str(value) => Some(value),
            _ => None,
        }
    }

    /// Exactly the Python value True (`value is True` in the oracle).
    fn is_true(&self) -> bool {
        matches!(self, Scalar::Bool(true))
    }

    /// Exactly the Python value False (`value is False` in the oracle).
    fn is_false(&self) -> bool {
        matches!(self, Scalar::Bool(false))
    }
}

fn scalar(value: &Bound<'_, PyAny>) -> Scalar {
    if value.is_none() {
        return Scalar::None;
    }
    if let Ok(flag) = value.cast::<PyBool>() {
        return Scalar::Bool(flag.is_true());
    }
    if value.is_instance_of::<PyInt>() {
        return match value.extract::<i64>() {
            Ok(number) => Scalar::Int(number),
            Err(_) => Scalar::HugeInt,
        };
    }
    if let Ok(number) = value.cast::<PyFloat>() {
        return Scalar::Float(number.value());
    }
    if let Ok(string) = value.cast::<PyString>() {
        return Scalar::Str(string.to_string_lossy().into_owned());
    }
    Scalar::Other {
        truthy: value.is_truthy().unwrap_or(false),
        unhashable: value.hash().is_err(),
    }
}

/// `value or ""` in the oracle: a falsy value becomes the empty string.
fn or_empty(value: &Bound<'_, PyAny>) -> Scalar {
    if value.is_truthy().unwrap_or(false) {
        scalar(value)
    } else {
        Scalar::Str(String::new())
    }
}

fn get<'py>(dict: &Bound<'py, PyDict>, key: &str) -> Option<Bound<'py, PyAny>> {
    dict.get_item(key).ok().flatten()
}

fn item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> DResult<Bound<'py, PyAny>> {
    get(dict, key).ok_or(Invalid)
}

fn as_dict<'py>(value: &Bound<'py, PyAny>) -> DResult<Bound<'py, PyDict>> {
    value.cast::<PyDict>().map_err(|_| Invalid).cloned()
}

/// The items of an iterable value as `gate_from_json` would meet them:
/// lists and tuples by position, sets by membership, dicts by key, and a
/// string by character (an empty string is an empty sequence there, not
/// an error). Any other value is not iterable, which the oracle meets as
/// a TypeError.
fn items(value: &Bound<'_, PyAny>) -> DResult<Vec<Py<PyAny>>> {
    if let Ok(string) = value.cast::<PyString>() {
        let py = value.py();
        return string
            .to_string_lossy()
            .chars()
            .map(|c| {
                Ok(PyString::new(py, &c.to_string())
                    .to_owned()
                    .unbind()
                    .into_any())
            })
            .collect();
    }
    if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
        return value
            .try_iter()
            .map_err(|_| Invalid)?
            .map(|entry| entry.map(|entry| entry.unbind()).map_err(|_| Invalid))
            .collect();
    }
    if value.is_instance_of::<PySet>() || value.is_instance_of::<PyFrozenSet>() {
        return value
            .try_iter()
            .map_err(|_| Invalid)?
            .map(|entry| entry.map(|entry| entry.unbind()).map_err(|_| Invalid))
            .collect();
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        return Ok(dict.keys().iter().map(|key| key.unbind()).collect());
    }
    Err(Invalid)
}

/// `value or ()` for the optional sequences (`reviewer.methods`,
/// `gate.findings`, ...): a falsy value is the empty sequence.
fn or_empty_items(value: Option<&Bound<'_, PyAny>>) -> DResult<Vec<Py<PyAny>>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if !value.is_truthy().unwrap_or(false) {
        return Ok(Vec::new());
    }
    items(value)
}

// ---------------------------------------------------------------------------
// Extraction: gate_from_json, constructor by constructor.

#[derive(Clone, PartialEq)]
struct Snap {
    artifact: Scalar,
    contract: Scalar,
    environment: Scalar,
}

impl Snap {
    /// model._snapshot: every field carries text.
    fn valid(&self) -> bool {
        self.artifact.is_text() && self.contract.is_text() && self.environment.is_text()
    }
}

/// _snapshot(data): the value must be subscriptable by the three keys.
fn extract_snapshot(value: &Bound<'_, PyAny>) -> DResult<Snap> {
    let dict = as_dict(value)?;
    Ok(Snap {
        artifact: scalar(&item(&dict, "artifact")?),
        contract: scalar(&item(&dict, "contract")?),
        environment: scalar(&item(&dict, "environment")?),
    })
}

struct MethodF {
    id: Scalar,
    family: Scalar,
    failure_target: Scalar,
    procedure: Scalar,
    oracle: Scalar,
    evidence: Scalar,
    performed: Scalar,
}

fn extract_method(value: &Bound<'_, PyAny>) -> DResult<MethodF> {
    let dict = as_dict(value)?;
    Ok(MethodF {
        id: scalar(&item(&dict, "id")?),
        family: scalar(&item(&dict, "family")?),
        failure_target: scalar(&item(&dict, "failure_target")?),
        procedure: scalar(&item(&dict, "procedure")?),
        oracle: scalar(&item(&dict, "oracle")?),
        evidence: scalar(&item(&dict, "evidence")?),
        performed: scalar(&item(&dict, "performed")?),
    })
}

/// One recorded test count (`model.TestCounts`). The number checks are the
/// oracle's (`_test_run_gaps` raises ValueError on a non-int or a negative),
/// deferred to gap time through `poisoned` so extraction order matches.
enum Count {
    Small(i64),
    /// Canonical decimal text of an int outside i64 range.
    Big(String),
}

impl Count {
    fn negative(&self) -> bool {
        match self {
            Count::Small(value) => *value < 0,
            Count::Big(text) => text.starts_with('-'),
        }
    }

    fn is_zero(&self) -> bool {
        match self {
            Count::Small(value) => *value == 0,
            Count::Big(text) => text == "0",
        }
    }

    fn decimal(&self) -> String {
        match self {
            Count::Small(value) => value.to_string(),
            Count::Big(text) => text.clone(),
        }
    }
}

struct Counts {
    passed: Option<Count>,
    failed: Option<Count>,
    skipped: Option<Count>,
    total: Option<Count>,
    exit: Option<Count>,
    unparsed: bool,
    poisoned: bool,
}

fn extract_count(value: &Bound<'_, PyAny>) -> Option<Count> {
    if value.is_instance_of::<PyBool>() || !value.is_instance_of::<PyInt>() {
        return None;
    }
    match value.extract::<i64>() {
        Ok(number) => Some(Count::Small(number)),
        Err(_) => Some(Count::Big(value.str().ok()?.to_string_lossy().into_owned())),
    }
}

/// _tests(data) on an evidence row: absent or None is no counts; a non-dict
/// raises ValueError in the oracle; `unparsed` is read with `is True`.
fn extract_tests(dict: &Bound<'_, PyDict>) -> DResult<Option<Counts>> {
    let Some(raw) = get(dict, "tests") else {
        return Ok(None);
    };
    if raw.is_none() {
        return Ok(None);
    }
    let raw = as_dict(&raw)?;
    let mut poisoned = false;
    let grab = |key: &str, poisoned: &mut bool| -> DResult<Option<Count>> {
        let value = item(&raw, key)?;
        let count = extract_count(&value);
        if count.is_none() {
            *poisoned = true;
        }
        Ok(count)
    };
    let passed = grab("passed", &mut poisoned)?;
    let failed = grab("failed", &mut poisoned)?;
    let skipped = grab("skipped", &mut poisoned)?;
    let total = grab("total", &mut poisoned)?;
    let exit = grab("exit", &mut poisoned)?;
    Ok(Some(Counts {
        passed,
        failed,
        skipped,
        total,
        exit,
        unparsed: get(&raw, "unparsed").map_or(false, |value| scalar(&value).is_true()),
        poisoned,
    }))
}

struct EvidenceF {
    id: Scalar,
    unit: Scalar,
    role: Scalar,
    snapshot: Snap,
    status: Scalar,
    passed: Scalar,
    observation: Scalar,
    locator: Scalar,
    reuse_target: Option<Snap>,
    applicability_checked: bool,
    reuse_reason: Scalar,
    applicability_evidence: Scalar,
    tests: Option<Counts>,
}

fn extract_evidence(value: &Bound<'_, PyAny>) -> DResult<EvidenceF> {
    let dict = as_dict(value)?;
    let reuse = get(&dict, "reuse_target");
    let reuse_target = match reuse {
        Some(target) if target.is_instance_of::<PyDict>() => {
            Some(extract_snapshot(&target)?)
        }
        _ => None,
    };
    Ok(EvidenceF {
        id: scalar(&item(&dict, "id")?),
        unit: scalar(&item(&dict, "unit")?),
        role: scalar(&item(&dict, "role")?),
        snapshot: extract_snapshot(&item(&dict, "snapshot")?)?,
        status: get(&dict, "status").map_or(Scalar::Str(String::new()), |v| or_empty(&v)),
        passed: scalar(&item(&dict, "passed")?),
        observation: scalar(&item(&dict, "observation")?),
        locator: scalar(&item(&dict, "locator")?),
        reuse_target,
        applicability_checked: get(&dict, "applicability_checked")
            .map_or(false, |value| scalar(&value).is_true()),
        reuse_reason: get(&dict, "reuse_reason")
            .map_or(Scalar::Str(String::new()), |v| or_empty(&v)),
        applicability_evidence: get(&dict, "applicability_evidence")
            .map_or(Scalar::Str(String::new()), |v| or_empty(&v)),
        tests: extract_tests(&dict)?,
    })
}

struct FindingF {
    id: Scalar,
    classification: Scalar,
    material: Scalar,
    resolution: Option<EvidenceF>,
    canonical_id: Scalar,
    scope_decision: Scalar,
    deferral_decision: Scalar,
    deferral_reason: Scalar,
    follow_up: Scalar,
}

fn extract_finding(value: &Bound<'_, PyAny>) -> DResult<FindingF> {
    let dict = as_dict(value)?;
    let resolution = get(&dict, "resolution");
    let resolution = match resolution {
        Some(row) if row.is_instance_of::<PyDict>() => Some(extract_evidence(&row)?),
        _ => None,
    };
    let grab = |key: &str| -> Scalar {
        get(&dict, key).map_or(Scalar::None, |value| scalar(&value))
    };
    Ok(FindingF {
        id: scalar(&item(&dict, "id")?),
        classification: scalar(&item(&dict, "classification")?),
        material: scalar(&item(&dict, "material")?),
        resolution,
        canonical_id: grab("canonical_id"),
        scope_decision: grab("scope_decision"),
        deferral_decision: grab("deferral_decision"),
        deferral_reason: grab("deferral_reason"),
        follow_up: grab("follow_up"),
    })
}

struct ReviewF {
    available: Scalar,
    fresh_context: Scalar,
    author_advocacy_present: Scalar,
    within_authority: Scalar,
    methods_selected_independently: Scalar,
    methods: Vec<MethodF>,
    evidence: Vec<EvidenceF>,
}

/// _review(data): a non-dict reviewer is simply no reviewer.
fn extract_review(value: Option<&Bound<'_, PyAny>>) -> DResult<Option<ReviewF>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Ok(dict) = value.cast::<PyDict>() else {
        return Ok(None);
    };
    let dict = dict.clone();
    let mut methods = Vec::new();
    for entry in or_empty_items(get(&dict, "methods").as_ref())? {
        methods.push(extract_method(&entry.bind(value.py()))?);
    }
    let mut evidence = Vec::new();
    for entry in or_empty_items(get(&dict, "evidence").as_ref())? {
        evidence.push(extract_evidence(&entry.bind(value.py()))?);
    }
    Ok(Some(ReviewF {
        available: scalar(&item(&dict, "available")?),
        fresh_context: scalar(&item(&dict, "fresh_context")?),
        author_advocacy_present: scalar(&item(&dict, "author_advocacy_present")?),
        within_authority: scalar(&item(&dict, "within_authority")?),
        methods_selected_independently: scalar(&item(&dict, "methods_selected_independently")?),
        methods,
        evidence,
    }))
}

/// frozenset(data[key]): a string contributes its characters, a dict its
/// keys, any other iterable its elements; an unhashable element or a
/// non-iterable is the oracle's TypeError.
fn extract_str_set(value: &Bound<'_, PyAny>) -> DResult<HashSet<Scalar>> {
    if let Ok(string) = value.cast::<PyString>() {
        let text = string.to_string_lossy().into_owned();
        return Ok(text.chars().map(|c| Scalar::Str(c.to_string())).collect());
    }
    let mut set = HashSet::new();
    for entry in items(value)? {
        let bound = entry.bind(value.py());
        if bound.is_instance_of::<PyList>()
            || bound.is_instance_of::<PyDict>()
            || bound.is_instance_of::<PySet>()
            || bound.is_instance_of::<PyFrozenSet>()
        {
            return Err(Invalid); // unhashable element
        }
        set.insert(scalar(&bound));
    }
    Ok(set)
}

struct GateF {
    phase: Scalar,
    tier: Scalar,
    round_number: Scalar,
    snapshot: Snap,
    authorized: Scalar,
    decisions_resolved: Scalar,
    capabilities_available: Scalar,
    budget_remaining: Scalar,
    progress_possible: Scalar,
    review_required: Scalar,
    requirements: HashSet<Scalar>,
    satisfied: HashSet<Scalar>,
    units: HashSet<Scalar>,
    owner_methods: Vec<MethodF>,
    owner_evidence: Vec<EvidenceF>,
    reviewer: Option<ReviewF>,
    findings: Vec<FindingF>,
    self_review: Vec<Scalar>,
}

/// gate_from_json(data), field for field.
fn extract_gate(record: &Bound<'_, PyAny>) -> DResult<GateF> {
    let dict = as_dict(record)?;
    let py = record.py();
    let mut owner_methods = Vec::new();
    for entry in items(&item(&dict, "owner_methods")?)? {
        owner_methods.push(extract_method(&entry.bind(py))?);
    }
    let mut owner_evidence = Vec::new();
    for entry in items(&item(&dict, "owner_evidence")?)? {
        owner_evidence.push(extract_evidence(&entry.bind(py))?);
    }
    let mut findings = Vec::new();
    for entry in or_empty_items(get(&dict, "findings").as_ref())? {
        findings.push(extract_finding(&entry.bind(py))?);
    }
    // _self_review: a list of strings, anything else is a TypeError there.
    let self_raw = get(&dict, "self_review");
    let mut self_review = Vec::new();
    match self_raw {
        None => {}
        Some(value) => {
            let list = value.cast::<PyList>().map_err(|_| Invalid)?;
            for entry in list.iter() {
                if entry.cast::<PyString>().is_err() {
                    return Err(Invalid);
                }
                self_review.push(scalar(&entry));
            }
        }
    }
    Ok(GateF {
        phase: scalar(&item(&dict, "phase")?),
        tier: scalar(&item(&dict, "tier")?),
        round_number: scalar(&item(&dict, "round_number")?),
        snapshot: extract_snapshot(&item(&dict, "snapshot")?)?,
        authorized: scalar(&item(&dict, "authorized")?),
        decisions_resolved: scalar(&item(&dict, "decisions_resolved")?),
        capabilities_available: scalar(&item(&dict, "capabilities_available")?),
        budget_remaining: scalar(&item(&dict, "budget_remaining")?),
        progress_possible: scalar(&item(&dict, "progress_possible")?),
        review_required: scalar(&item(&dict, "review_required")?),
        requirements: extract_str_set(&item(&dict, "requirements")?)?,
        satisfied: extract_str_set(&item(&dict, "satisfied")?)?,
        units: extract_str_set(&item(&dict, "units")?)?,
        owner_methods,
        owner_evidence,
        reviewer: extract_review(get(&dict, "reviewer").as_ref())?,
        findings,
        self_review,
    })
}

// ---------------------------------------------------------------------------
// Text helpers with Python semantics.

/// Py_UNICODE_ISSPACE: the whitespace `str.split()` and the `re` module's
/// `\s` both use — Unicode White_Space plus the information separators.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || (0x1c..=0x1f).contains(&(c as u32))
}

/// Python `str.casefold()`: full case folding. Rust's `to_lowercase`
/// agrees except for the multi-character folds, spelled out here.
fn py_casefold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            'ß' | 'ẞ' => out.push_str("ss"),
            'ﬀ' => out.push_str("ff"),
            'ﬁ' => out.push_str("fi"),
            'ﬂ' => out.push_str("fl"),
            'ﬃ' => out.push_str("ffi"),
            'ﬄ' => out.push_str("ffl"),
            'ﬅ' | 'ﬆ' => out.push_str("st"),
            'İ' => out.push_str("i\u{307}"),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// `" ".join(value.split())`: whitespace runs collapse to one space.
fn collapse_ws(text: &str) -> String {
    text.split(is_py_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// model._unique_ids: every id carries text and no id repeats.
fn unique_ids<'a>(ids: impl Iterator<Item = &'a Scalar>) -> bool {
    let mut seen = HashSet::new();
    for id in ids {
        if !id.is_text() || !seen.insert(id.clone()) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// The test-run claim rule (model._TEST_CLAIM): a search over the procedure
// text, case-insensitive, with Python `re` word boundaries and `\s`. The
// pattern's alternatives are matched by hand so the engine needs no regex
// dependency; tests/test_decide_parity.py pins this corpus through the
// test-counts-missing gap.

fn is_word_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

fn boundary(chars: &[char], index: usize) -> bool {
    let left = index > 0 && is_word_char(chars[index - 1]);
    let right = index < chars.len() && is_word_char(chars[index]);
    left != right
}

/// One pattern character against the text at `index`, case-insensitively:
/// the text char's full lowercase fold must be exactly the pattern char.
fn fold_eq(chars: &[char], index: usize, pattern: char) -> bool {
    if index >= chars.len() {
        return false;
    }
    let c = chars[index];
    if c == pattern {
        return true;
    }
    let mut lowered = c.to_lowercase();
    match (lowered.next(), lowered.next()) {
        (Some(only), None) => only == pattern,
        _ => false,
    }
}

/// A literal (letters fold; spaces and punctuation are exact) matched at
/// `start`; returns the end index.
fn lit(chars: &[char], start: usize, pattern: &str) -> Option<usize> {
    let mut index = start;
    for pattern_char in pattern.chars() {
        if pattern_char == ' ' || !pattern_char.is_alphabetic() {
            if chars.get(index) != Some(&pattern_char) {
                return None;
            }
        } else if !fold_eq(chars, index, pattern_char) {
            return None;
        }
        index += 1;
    }
    Some(index)
}

/// `\b<literal>\b` matched at `start`.
fn word_lit(chars: &[char], start: usize, pattern: &str) -> Option<usize> {
    if !boundary(chars, start) {
        return None;
    }
    let end = lit(chars, start, pattern)?;
    if !boundary(chars, end) {
        return None;
    }
    Some(end)
}

/// `\s+` from `start` (greedy; what follows never starts with whitespace,
/// so no backtracking is owed). Returns the end index.
fn spaces(chars: &[char], start: usize) -> Option<usize> {
    let mut index = start;
    while index < chars.len() && is_py_space(chars[index]) {
        index += 1;
    }
    if index == start {
        None
    } else {
        Some(index)
    }
}

/// One `\S+` token from `start`.
fn token(chars: &[char], start: usize) -> Option<usize> {
    let mut index = start;
    while index < chars.len() && !is_py_space(chars[index]) {
        index += 1;
    }
    if index == start {
        None
    } else {
        Some(index)
    }
}

/// `(?:\s+\S+){0,6}\s+test\b` from `start`: up to six filler tokens, then
/// the word test. Every filler count is tried, as the regex backtracks.
fn fillers_then_test(chars: &[char], start: usize) -> bool {
    let mut positions = vec![start];
    let mut current = start;
    for _ in 0..6 {
        let Some(after_space) = spaces(chars, current) else {
            break;
        };
        let Some(after_token) = token(chars, after_space) else {
            break;
        };
        positions.push(after_token);
        current = after_token;
    }
    for position in positions {
        if let Some(after_space) = spaces(chars, position) {
            if let Some(end) = lit(chars, after_space, "test") {
                if boundary(chars, end) {
                    return true;
                }
            }
        }
    }
    false
}

/// `\b(mvn|mvnw)(.cmd)?\b...` and `\b(gradle|gradlew)(.bat)?\b...` at `start`.
fn build_tool_claim(chars: &[char], start: usize, bases: &[&str], suffix: &str) -> bool {
    if !boundary(chars, start) {
        return false;
    }
    for base in bases {
        let Some(mut index) = lit(chars, start, base) else {
            continue;
        };
        // The optional suffix counts only when what follows it still
        // reaches the filler/test tail; try both readings.
        let mut tails = vec![index];
        if let Some(after_suffix) = lit(chars, index, suffix) {
            tails.push(after_suffix);
        }
        for tail in tails.drain(..) {
            index = tail;
            if boundary(chars, index) && fillers_then_test(chars, index) {
                return true;
            }
        }
    }
    false
}

/// model.claims_test_run over the procedure text.
fn claims_test_run(procedure: &str) -> bool {
    let chars: Vec<char> = procedure.chars().collect();
    for start in 0..=chars.len() {
        for word in ["pytest", "unittest", "ctest", "vitest", "jest"] {
            if word_lit(&chars, start, word).is_some() {
                return true;
            }
        }
        for phrase in ["npm test", "cargo test", "go test", "0 failed"] {
            if word_lit(&chars, start, phrase).is_some() {
                return true;
            }
        }
        // dotnet\s+test
        if boundary(&chars, start) {
            if let Some(after_name) = lit(&chars, start, "dotnet") {
                if let Some(after_space) = spaces(&chars, after_name) {
                    if let Some(end) = lit(&chars, after_space, "test") {
                        if boundary(&chars, end) {
                            return true;
                        }
                    }
                }
            }
        }
        // tests? (passed|failed)
        if boundary(&chars, start) {
            if let Some(mut index) = lit(&chars, start, "test") {
                if let Some(after_s) = lit(&chars, index, "s") {
                    index = after_s;
                }
                if chars.get(index) == Some(&' ') {
                    for outcome in ["passed", "failed"] {
                        if let Some(end) = lit(&chars, index + 1, outcome) {
                            if boundary(&chars, end) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        if build_tool_claim(&chars, start, &["mvn", "mvnw"], ".cmd")
            || build_tool_claim(&chars, start, &["gradle", "gradlew"], ".bat")
        {
            return true;
        }
    }
    false
}

/// The claim check on a raw procedure value: `procedure or ""` first (a
/// falsy value claims nothing), and a truthy non-string is the oracle's
/// TypeError out of `re.search`.
fn claims_for(procedure: &Scalar) -> DResult<bool> {
    match procedure {
        Scalar::Str(text) => Ok(claims_test_run(text)),
        value if !value.truthy() => Ok(false),
        _ => Err(Invalid),
    }
}

// ---------------------------------------------------------------------------
// model.applicable / _methods_sufficient / _coverage_sufficient.

fn applicable(
    evidence: &EvidenceF,
    target: &Snap,
    role: Option<&str>,
    require_pass: bool,
) -> bool {
    if !evidence.snapshot.valid() {
        return false;
    }
    match evidence.passed {
        Scalar::Bool(true) => {}
        Scalar::Bool(false) if !require_pass => {}
        _ => return false,
    }
    if !evidence.id.is_text()
        || !evidence.unit.is_text()
        || !evidence.observation.is_text()
        || !evidence.locator.is_text()
    {
        return false;
    }
    match evidence.role.as_str() {
        Some("owner") | Some("reviewer") | Some("critic") => {}
        _ => return false,
    }
    if let Some(want) = role {
        if evidence.role.as_str() != Some(want) {
            return false;
        }
    }
    let status = evidence.status.as_str();
    if status == Some("fresh") || (!require_pass && status == Some("failed")) {
        return evidence.snapshot == *target && evidence.reuse_target.is_none();
    }
    if status == Some("reused") {
        return evidence.reuse_target.as_ref() == Some(target)
            && evidence.applicability_checked
            && evidence.reuse_reason.is_text()
            && evidence.applicability_evidence.is_text();
    }
    false
}

fn methods_sufficient(methods: &[MethodF], minimum: usize) -> bool {
    if methods.len() < minimum || !unique_ids(methods.iter().map(|m| &m.id)) {
        return false;
    }
    for method in methods {
        if !method.performed.is_true()
            || !method.family.is_text()
            || !method.failure_target.is_text()
            || !method.procedure.is_text()
            || !method.oracle.is_text()
            || !method.evidence.is_text()
        {
            return false;
        }
    }
    // Distinct normalized values per field, as the oracle counts them.
    for pick in 0..3 {
        let mut distinct = HashSet::new();
        for method in methods {
            let field = match pick {
                0 => &method.family,
                1 => &method.procedure,
                _ => &method.failure_target,
            };
            distinct.insert(py_casefold(&collapse_ws(field.as_str().unwrap_or_default())));
        }
        if distinct.len() < minimum {
            return false;
        }
    }
    true
}

/// `value in units` where units is a frozenset of strings: an unhashable
/// value is the oracle's TypeError, a hashable non-string simply misses.
fn in_str_set(value: &Scalar, set: &HashSet<Scalar>) -> DResult<bool> {
    match value {
        Scalar::Str(_) => Ok(set.contains(value)),
        Scalar::Other { unhashable: true, .. } => Err(Invalid),
        _ => Ok(false),
    }
}

fn coverage_sufficient(
    evidence: &[EvidenceF],
    units: &HashSet<Scalar>,
    target: &Snap,
    role: &str,
) -> DResult<bool> {
    let mut covered = HashSet::new();
    for item in evidence {
        if applicable(item, target, Some(role), true) {
            covered.insert(item.unit.clone());
        }
    }
    let mut current_failure = false;
    for item in evidence {
        if !in_str_set(&item.unit, units)? {
            continue;
        }
        if item.passed.is_false() && applicable(item, target, Some(role), false) {
            current_failure = true;
            break;
        }
    }
    Ok(units.iter().all(|unit| covered.contains(unit)) && !current_failure)
}

// ---------------------------------------------------------------------------
// model._test_run_gaps / _evidence_test_gaps.

/// Sum of non-negative decimal strings, for counts outside i64 range.
fn decimal_add(left: &str, right: &str) -> String {
    let left: Vec<u8> = left.bytes().rev().collect();
    let right: Vec<u8> = right.bytes().rev().collect();
    let mut out = Vec::new();
    let mut carry = 0u8;
    for index in 0..left.len().max(right.len()) {
        let sum = carry
            + left.get(index).map_or(0, |digit| digit - b'0')
            + right.get(index).map_or(0, |digit| digit - b'0');
        out.push(b'0' + sum % 10);
        carry = sum / 10;
    }
    if carry > 0 {
        out.push(b'0' + carry);
    }
    out.iter().rev().map(|digit| *digit as char).collect()
}

fn test_run_gaps(
    run: Option<&Counts>,
    passed: &Scalar,
    claimed: bool,
) -> DResult<Vec<&'static str>> {
    let Some(run) = run else {
        return Ok(if claimed { vec!["test-counts-missing"] } else { Vec::new() });
    };
    if run.unparsed {
        return Ok(vec!["test-counts-unparsed"]);
    }
    if run.poisoned {
        return Err(Invalid); // ValueError("invalid tests") in the oracle
    }
    let counts = [&run.passed, &run.failed, &run.skipped, &run.total, &run.exit];
    let mut decimals = Vec::with_capacity(counts.len());
    for count in counts {
        let count = count.as_ref().ok_or(Invalid)?;
        if count.negative() {
            return Err(Invalid);
        }
        decimals.push(count.decimal());
    }
    let sum = decimal_add(&decimal_add(&decimals[0], &decimals[1]), &decimals[2]);
    if sum != decimals[3] {
        return Ok(vec!["test-counts-missing"]);
    }
    if run.total.as_ref().map_or(false, |total| total.is_zero()) {
        return Ok(vec!["tests-not-run"]);
    }
    let failed_nonzero = run.failed.as_ref().map_or(false, |c| !c.is_zero());
    let exit_nonzero = run.exit.as_ref().map_or(false, |c| !c.is_zero());
    if passed.is_true() && (failed_nonzero || exit_nonzero) {
        return Ok(vec!["tests-failed"]);
    }
    Ok(Vec::new())
}

fn evidence_test_gaps(
    methods: &[MethodF],
    evidence: &[EvidenceF],
) -> DResult<Vec<&'static str>> {
    let mut by_id: HashMap<&str, &EvidenceF> = HashMap::new();
    for item in evidence {
        if let Some(id) = item.id.as_str() {
            by_id.insert(id, item);
        }
    }
    let mut gaps = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for method in methods {
        let found = match &method.evidence {
            Scalar::Str(id) => by_id.get(id.as_str()).copied(),
            Scalar::Other { unhashable: true, .. } => return Err(Invalid),
            _ => None,
        };
        let claimed = claims_for(&method.procedure)?;
        let Some(item) = found else {
            if claimed {
                gaps.push("test-counts-missing");
            }
            continue;
        };
        if let Some(id) = item.id.as_str() {
            seen.insert(id);
        }
        gaps.extend(test_run_gaps(item.tests.as_ref(), &item.passed, claimed)?);
    }
    for item in evidence {
        let id = item.id.as_str().unwrap_or_default();
        if !seen.contains(id) {
            gaps.extend(test_run_gaps(item.tests.as_ref(), &item.passed, false)?);
        }
    }
    Ok(gaps)
}

// ---------------------------------------------------------------------------
// model._finding_gaps.

const FINDING_CLASSIFICATIONS: [&str; 5] = [
    "confirmed",
    "refuted-with-evidence",
    "unresolved",
    "duplicate",
    "out-of-scope",
];

fn finding_gaps(findings: &[FindingF], snapshot: &Snap) -> DResult<Vec<&'static str>> {
    // The oracle raises on the first ill-shaped finding it reaches, and a
    // raise anywhere decides the whole gate, so every finding's shape is
    // judged before any gap is read — the outcomes are the same.
    for finding in findings {
        match finding.classification.as_str() {
            Some(name) if FINDING_CLASSIFICATIONS.contains(&name) => {}
            _ => return Err(Invalid),
        }
        if !matches!(finding.material, Scalar::Bool(_)) {
            return Err(Invalid);
        }
    }
    let mut known: HashMap<&str, usize> = HashMap::new();
    for (index, finding) in findings.iter().enumerate() {
        if let Some(id) = finding.id.as_str() {
            known.insert(id, index);
        }
    }
    let mut gaps = Vec::new();
    for finding in findings {
        // Walk the duplicate chain to the canonical finding.
        let mut canonical = finding;
        let mut visited: HashSet<&str> = HashSet::new();
        while canonical.classification.as_str() == Some("duplicate") {
            let id = canonical.id.as_str().unwrap_or_default();
            if visited.contains(id) {
                return Err(Invalid);
            }
            let next = match canonical.canonical_id.as_str() {
                Some(target) => known.get(target).copied(),
                None => None,
            };
            let Some(next) = next else {
                return Err(Invalid); // invalid duplicate chain
            };
            visited.insert(id);
            canonical = &findings[next];
        }
        let material = finding.material.truthy() || canonical.material.truthy();
        let has_resolution = canonical
            .resolution
            .as_ref()
            .map_or(false, |row| applicable(row, snapshot, None, true));
        let authorized_deferral = !material
            && canonical.deferral_decision.is_text()
            && canonical.deferral_reason.is_text()
            && canonical.follow_up.is_text();
        match canonical.classification.as_str() {
            Some("confirmed") => {
                if !has_resolution && !authorized_deferral {
                    gaps.push("unclosed-finding");
                }
            }
            Some("refuted-with-evidence") => {
                if !has_resolution {
                    gaps.push("unsupported-refutation");
                }
            }
            Some("unresolved") => {
                if material {
                    gaps.push("unresolved-finding");
                }
            }
            Some("out-of-scope") => {
                if !(has_resolution && canonical.scope_decision.is_text()) {
                    gaps.push("unsupported-exclusion");
                }
            }
            _ => {}
        }
    }
    Ok(gaps)
}

// ---------------------------------------------------------------------------
// model.parse_history, decide-faithful: the parsed form (int keys, list or
// set reasons) passes through unchanged; the raw JSON form (digit-string
// keys) is canonicalized; anything else is TAMPERED. One fidelity note:
// `int(key)` raising on an all-digits-but-not-decimal key propagates out
// of the model's parse as a ValueError, which decide turns into
// invalid-record — modelled here as the Invalid outcome, raised only when
// round accounting actually runs (the model's parse is equally lazy: it
// sits behind the blocker and clean-gate returns).

/// The value of a Unicode decimal digit (general category Nd), which is
/// exactly the set `int()` parses.
fn decimal_digit_value(c: char) -> Option<u32> {
    let cp = c as u32;
    if c.is_ascii_digit() {
        return Some(cp - 0x30);
    }
    const ND_RANGES: [(u32, u32); 36] = [
        (0x660, 0x669), (0x6F0, 0x6F9), (0x7C0, 0x7C9), (0x966, 0x96F),
        (0x9E6, 0x9EF), (0xA66, 0xA6F), (0xAE6, 0xAEF), (0xB66, 0xB6F),
        (0xBE6, 0xBEF), (0xC66, 0xC6F), (0xCE6, 0xCEF), (0xD66, 0xD6F),
        (0xDE6, 0xDEF), (0xE50, 0xE59), (0xED0, 0xED9), (0xF20, 0xF29),
        (0x1040, 0x1049), (0x1090, 0x1099), (0x17E0, 0x17E9), (0x1810, 0x1819),
        (0x1946, 0x194F), (0x19D0, 0x19D9), (0x1A80, 0x1A89), (0x1A90, 0x1A99),
        (0x1B50, 0x1B59), (0x1BB0, 0x1BB9), (0x1C40, 0x1C49), (0x1C50, 0x1C59),
        (0xA620, 0xA629), (0xA8D0, 0xA8D9), (0xA900, 0xA909), (0xA9D0, 0xA9D9),
        (0xA9F0, 0xA9F9), (0xAA50, 0xAA59), (0xABF0, 0xABF9), (0xFF10, 0xFF19),
    ];
    for (low, high) in ND_RANGES {
        if (low..=high).contains(&cp) {
            return Some(cp - low);
        }
    }
    None
}

/// Characters with the Unicode Digit property that are not decimal digits
/// (superscripts, subscripts, circled and dingbat digits): `"²".isdigit()`
/// is true in Python while `int("²")` raises.
fn is_digit_not_decimal(c: char) -> bool {
    let cp = c as u32;
    matches!(cp,
        0xB2 | 0xB3 | 0xB9
        | 0x2080..=0x2089
        | 0x2460..=0x2473 | 0x2474..=0x2488 | 0x24EA
        | 0x2776..=0x277E | 0x277F..=0x2793
        | 0x1F100..=0x1F10A)
}

fn is_py_digit(c: char) -> bool {
    decimal_digit_value(c).is_some() || is_digit_not_decimal(c)
}

enum DigitKey {
    Number(i64, String),
    OtherNumber(String),
    Tampered,
}

/// A digit-string history key: canonical decimal text or tampered, with the
/// all-digits-but-unparseable case surfacing as the model's ValueError.
fn parse_digit_key(text: &str) -> DResult<DigitKey> {
    if text.is_empty() {
        return Ok(DigitKey::Tampered);
    }
    let chars: Vec<char> = text.chars().collect();
    if !chars.iter().all(|&c| is_py_digit(c)) {
        return Ok(DigitKey::Tampered);
    }
    if chars.iter().any(|&c| decimal_digit_value(c).is_none()) {
        return Err(Invalid); // int(key) raises inside the model's parse
    }
    if chars.iter().all(|c| c.is_ascii_digit()) {
        let canonical = text.trim_start_matches('0');
        let canonical = if canonical.is_empty() { "0" } else { canonical };
        if canonical != text {
            return Ok(DigitKey::Tampered); // str(int(key)) != key
        }
        if canonical.len() <= 18 {
            let value: i64 = canonical.parse().map_err(|_| Invalid)?;
            return Ok(DigitKey::Number(value, canonical.to_string()));
        }
        return Ok(DigitKey::OtherNumber(canonical.to_string()));
    }
    // Non-ASCII decimal digits parse in Python, but str(int(key)) renders
    // ASCII, so the canonical check can never pass.
    Ok(DigitKey::Tampered)
}

enum HistoryParse {
    Absent,
    Tampered,
    Rounds { map: HashMap<i64, HashSet<String>>, any: bool },
}

/// One history entry's reasons: a list/tuple/set of text strings without
/// duplicates, or the history is tampered.
fn parse_reasons(value: &Bound<'_, PyAny>) -> Option<HashSet<String>> {
    if !(value.is_instance_of::<PyList>()
        || value.is_instance_of::<PyTuple>()
        || value.is_instance_of::<PySet>()
        || value.is_instance_of::<PyFrozenSet>())
    {
        return None;
    }
    let mut set = HashSet::new();
    for entry in items(value).ok()? {
        let bound = entry.bind(value.py());
        // The oracle checks `type(reason) is str`, not isinstance.
        if !bound.is_exact_instance_of::<PyString>() {
            return None;
        }
        let string = bound.cast::<PyString>().ok()?;
        let text = string.to_string_lossy().into_owned();
        if text.trim().is_empty() || !set.insert(text) {
            return None;
        }
    }
    Some(set)
}

fn parse_history(history: &Bound<'_, PyAny>) -> DResult<HistoryParse> {
    if history.is_none() {
        return Ok(HistoryParse::Absent);
    }
    let Ok(dict) = history.cast::<PyDict>() else {
        return Ok(HistoryParse::Tampered); // includes the "tampered" wire tag
    };
    let dict = dict.clone();
    let mut map = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut any = false;
    for (key, reasons) in dict.iter() {
        let (canonical, small): (String, Option<i64>) = if key.is_instance_of::<PyBool>() {
            return Ok(HistoryParse::Tampered);
        } else if key.is_instance_of::<PyInt>() {
            match key.extract::<i64>() {
                Ok(value) => (value.to_string(), Some(value)),
                Err(_) => (
                    key.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
                    None,
                ),
            }
        } else if let Ok(string) = key.cast::<PyString>() {
            match parse_digit_key(&string.to_string_lossy())? {
                DigitKey::Number(value, canonical) => (canonical, Some(value)),
                DigitKey::OtherNumber(canonical) => (canonical, None),
                DigitKey::Tampered => return Ok(HistoryParse::Tampered),
            }
        } else {
            return Ok(HistoryParse::Tampered);
        };
        let below_one = match small {
            Some(value) => value < 1,
            None => canonical.starts_with('-') || canonical == "0",
        };
        if below_one || !seen.insert(canonical) {
            return Ok(HistoryParse::Tampered);
        }
        any = true;
        let Some(set) = parse_reasons(&reasons) else {
            return Ok(HistoryParse::Tampered);
        };
        if let Some(value) = small {
            map.insert(value, set);
        }
    }
    Ok(HistoryParse::Rounds { map, any })
}

/// model._rounds_blocked for a gate with gaps: whether the round budget
/// for those gaps is spent.
fn rounds_blocked(
    tier: &str,
    round: i64,
    gaps: &HashSet<&str>,
    history: &Bound<'_, PyAny>,
) -> DResult<bool> {
    let cap = round_cap(tier).ok_or(Invalid)?;
    if tier == "light" {
        return Ok(round >= cap);
    }
    match parse_history(history)? {
        HistoryParse::Tampered => Ok(true),
        // No history at all past round 1: the previous round is missing,
        // which the model treats as spent; round 1 falls to the cap alone.
        HistoryParse::Absent => Ok(round > 1 || round >= cap),
        HistoryParse::Rounds { map, any } => {
            // The stall check runs only past round 1 (model._rounds_blocked):
            // at round 1 there is no previous round to compare against.
            if round > 1 {
                let previous = if any { map.get(&(round - 1)) } else { None };
                let Some(previous) = previous else {
                    return Ok(true);
                };
                let previous: HashSet<&str> = previous.iter().map(String::as_str).collect();
                if *gaps == previous || (round >= 3 && !gaps.is_subset(&previous)) {
                    return Ok(true);
                }
            }
            Ok(round >= cap)
        }
    }
}

// ---------------------------------------------------------------------------
// Validation and the decision itself (model._decide, in its own order).

fn validate(gate: &GateF) -> DResult<(&'static str, i64)> {
    match gate.phase.as_str() {
        Some("research") | Some("plan") | Some("execute") | Some("deliver") => {}
        _ => return Err(Invalid),
    }
    let tier_name = gate.tier.as_str().unwrap_or_default();
    let cap = round_cap(tier_name).ok_or(Invalid)?;
    let tier: &'static str = match tier_name {
        "light" => "light",
        "standard" => "standard",
        _ => "full",
    };
    let round = match gate.round_number {
        Scalar::Int(value) if (1..=cap).contains(&value) => value,
        _ => return Err(Invalid),
    };
    if !gate.snapshot.valid() {
        return Err(Invalid);
    }
    for flag in [
        &gate.authorized,
        &gate.decisions_resolved,
        &gate.capabilities_available,
        &gate.budget_remaining,
        &gate.progress_possible,
        &gate.review_required,
    ] {
        if !matches!(flag, Scalar::Bool(_)) {
            return Err(Invalid);
        }
    }
    if gate.requirements.is_empty() || gate.units.is_empty() {
        return Err(Invalid);
    }
    for set in [&gate.requirements, &gate.satisfied, &gate.units] {
        if set.iter().any(|value| !value.is_text()) {
            return Err(Invalid);
        }
    }
    if !unique_ids(gate.owner_evidence.iter().map(|row| &row.id))
        || !unique_ids(gate.owner_methods.iter().map(|row| &row.id))
        || !unique_ids(gate.findings.iter().map(|row| &row.id))
    {
        return Err(Invalid);
    }
    if gate.self_review.iter().any(|value| !value.is_text()) {
        return Err(Invalid);
    }
    if let Some(review) = &gate.reviewer {
        if !unique_ids(review.methods.iter().map(|row| &row.id))
            || !unique_ids(review.evidence.iter().map(|row| &row.id))
        {
            return Err(Invalid);
        }
    }
    Ok((tier, round))
}

/// model._tier_lowered: the recorded tier may not drop for the same
/// contracted work.
fn tier_lowered(tier: &str, contract: &Scalar, inherited: &Bound<'_, PyAny>) -> bool {
    let Ok(dict) = inherited.cast::<PyDict>() else {
        return false;
    };
    let dict = dict.clone();
    let Some(old_tier) = get(&dict, "tier") else {
        return false;
    };
    let Some(old_rank) = scalar(&old_tier).as_str().and_then(tier_rank) else {
        return false;
    };
    let Some(snapshot) = get(&dict, "snapshot") else {
        return false;
    };
    let Ok(snapshot) = snapshot.cast::<PyDict>() else {
        return false;
    };
    let snapshot = snapshot.clone();
    let Some(old_contract) = get(&snapshot, "contract") else {
        return false;
    };
    let old_contract = scalar(&old_contract);
    old_contract.is_text()
        && old_contract != Scalar::Str("<contract>".to_string())
        && &old_contract == contract
        && tier_rank(tier).map_or(false, |rank| rank < old_rank)
}

const SELF_REVIEW: [&str; 3] = ["completeness", "execution", "adversarial"];

fn decide_inner(
    gate: &GateF,
    history: &Bound<'_, PyAny>,
    inherited: &Bound<'_, PyAny>,
) -> DResult<(&'static str, Vec<String>)> {
    let (tier, round) = validate(gate)?;
    let phase = gate.phase.as_str().unwrap_or_default();

    let mut blockers: HashSet<&'static str> = HashSet::new();
    if !gate.authorized.is_true() {
        blockers.insert("unauthorized");
    }
    if !gate.decisions_resolved.is_true() {
        blockers.insert("unanswered-decision");
    }
    if !gate.capabilities_available.is_true() {
        blockers.insert("missing-capability");
    }
    if !gate.budget_remaining.is_true() {
        blockers.insert("budget-exhausted");
    }
    if !gate.progress_possible.is_true() {
        blockers.insert("no-progress");
    }
    if let Some(review) = &gate.reviewer {
        if review.available.is_true() && !review.within_authority.is_true() {
            blockers.insert("unauthorized-review");
        }
    }
    if tier_lowered(tier, &gate.snapshot.contract, inherited) {
        blockers.insert("tier-lowered");
    }

    let mut gaps: HashSet<&'static str> = HashSet::new();
    if !gate.requirements.is_subset(&gate.satisfied) {
        gaps.insert("acceptance-gap");
    }
    let owner_minimum = match tier {
        "light" => 1,
        "standard" => 2,
        _ => 3,
    };
    if !methods_sufficient(&gate.owner_methods, owner_minimum) {
        gaps.insert("owner-methods");
    }
    if !coverage_sufficient(&gate.owner_evidence, &gate.units, &gate.snapshot, "owner")? {
        gaps.insert("owner-coverage");
    }
    // model.review_needed: full tier needs review at the plan gate and the
    // final diff only, whatever the raw flag says; other tiers follow it.
    let review_needed = if tier == "full" {
        phase == "plan" || phase == "deliver"
    } else {
        gate.review_required.is_true()
    };
    if review_needed {
        match &gate.reviewer {
            None => {
                blockers.insert("missing-reviewer");
            }
            Some(review) => {
                if !review.available.is_true() {
                    blockers.insert("missing-reviewer");
                } else {
                    if !review.fresh_context.is_true()
                        || !review.author_advocacy_present.is_false()
                    {
                        blockers.insert("review-context-not-independent");
                    }
                    if !review.within_authority.is_true()
                        || !review.methods_selected_independently.is_true()
                    {
                        blockers.insert("review-not-authorized-or-self-selected");
                    }
                    let review_minimum = if tier == "full" { 3 } else { 1 };
                    if !methods_sufficient(&review.methods, review_minimum) {
                        gaps.insert("reviewer-methods");
                    }
                    if !coverage_sufficient(
                        &review.evidence,
                        &gate.units,
                        &gate.snapshot,
                        "reviewer",
                    )? {
                        gaps.insert("reviewer-coverage");
                    }
                }
            }
        }
    }
    if phase == "deliver" && tier != "light" {
        let members: HashSet<&str> = gate
            .self_review
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        let present = SELF_REVIEW.iter().filter(|name| members.contains(**name)).count();
        if (tier == "full" && present < SELF_REVIEW.len())
            || (tier == "standard" && present < 2)
        {
            gaps.insert("missing-self-review");
        }
    }
    for gap in evidence_test_gaps(&gate.owner_methods, &gate.owner_evidence)? {
        gaps.insert(gap);
    }
    if let Some(review) = &gate.reviewer {
        for gap in evidence_test_gaps(&review.methods, &review.evidence)? {
            gaps.insert(gap);
        }
    }
    for finding in &gate.findings {
        if let Some(resolution) = &finding.resolution {
            for gap in evidence_test_gaps(&[], std::slice::from_ref(resolution))? {
                gaps.insert(gap);
            }
        }
    }
    for gap in finding_gaps(&gate.findings, &gate.snapshot)? {
        gaps.insert(gap);
    }

    if !blockers.is_empty() {
        let mut reasons: Vec<String> = blockers
            .union(&gaps)
            .map(|reason| reason.to_string())
            .collect();
        reasons.sort();
        return Ok(("BLOCKED", reasons));
    }
    if !gaps.is_empty() {
        if rounds_blocked(tier, round, &gaps, history)? {
            let mut reasons: Vec<String> = gaps.iter().map(|reason| reason.to_string()).collect();
            reasons.push("rounds-exhausted".to_string());
            reasons.sort();
            return Ok(("BLOCKED", reasons));
        }
        let mut reasons: Vec<String> = gaps.iter().map(|reason| reason.to_string()).collect();
        reasons.sort();
        return Ok(("REPAIR", reasons));
    }
    Ok(("READY", Vec::new()))
}

fn decide_impl(
    record: &Bound<'_, PyAny>,
    history: &Bound<'_, PyAny>,
    inherited: &Bound<'_, PyAny>,
) -> DResult<(&'static str, Vec<String>)> {
    let gate = extract_gate(record)?;
    decide_inner(&gate, history, inherited)
}

/// decide(record, history, inherited) -> {"schema", "state", "reasons"}.
///
/// The extraction or rule failure the oracle surfaces as
/// BLOCKED/invalid-record is a decision here, never an exception: shadow
/// plumbing must always receive the document the composed Python gate
/// would have produced for the same inputs.
#[pyfunction]
fn decide(
    record: &Bound<'_, PyAny>,
    history: &Bound<'_, PyAny>,
    inherited: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    let py = record.py();
    let (state, reasons) = match decide_impl(record, history, inherited) {
        Ok(outcome) => outcome,
        Err(Invalid) => ("BLOCKED", vec!["invalid-record".to_string()]),
    };
    let doc = PyDict::new(py);
    doc.set_item("schema", DECIDE_SCHEMA)?;
    doc.set_item("state", state)?;
    let list = PyList::empty(py);
    for reason in &reasons {
        list.append(reason)?;
    }
    doc.set_item("reasons", list)?;
    Ok(doc.unbind().into_any())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("DECIDE_SCHEMA", DECIDE_SCHEMA)?;
    m.add_function(wrap_pyfunction!(decide, m)?)?;
    Ok(())
}
