//! Exact line-range and structural symbol/path slicing with token budgets.

use crate::outline::lexer::LineIndex;
use crate::outline::structured::{
    resolve_computed_selector, resolve_structured_selector, split_computed_selector,
    suggest_candidates, ComputedSelection, ResolvedRange,
};
use crate::outline::{flatten_items, outline_source, read_text_file, Lang, OutlineItem, OutlineOptions};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;

pub const DEFAULT_SLICE_MAX_TOKENS: usize = 4000;
const MAX_LINE_CHARS: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceTarget {
    Ranges(Vec<(usize, usize)>),
    /// The last `n` lines of the file (`<path>:-<n>`), resolved once the
    /// file's length is known. Used by the hook's `tail -n` rewrite, which
    /// cannot know the length when it rewrites the command.
    Tail(usize),
    Selector(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceSpec {
    pub path: PathBuf,
    pub target: SliceTarget,
}

#[derive(Debug, Clone)]
pub struct SliceOptions {
    pub context_lines: usize,
    pub max_tokens: usize,
    pub line_numbers: bool,
    pub truncate_long_lines: bool,
    pub signatures_only: bool,
    pub lang_override: Option<Lang>,
}

impl Default for SliceOptions {
    fn default() -> Self {
        Self {
            context_lines: 0,
            max_tokens: DEFAULT_SLICE_MAX_TOKENS,
            line_numbers: true,
            truncate_long_lines: true,
            signatures_only: false,
            lang_override: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceLine {
    pub line: usize,
    pub text: String,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceBlock {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub start_line: usize,
    pub end_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub lines: Vec<SliceLine>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceResult {
    pub slices: Vec<SliceBlock>,
    pub truncated: bool,
    pub omitted_slices: usize,
    pub omitted_lines: usize,
    pub warnings: Vec<String>,
    /// Byte length of the merged selected source spans before budget cuts; metrics-only.
    #[serde(skip)]
    pub raw_bytes: usize,
    /// A signatures-only run collapsed a multi-line interval to its signature; metrics-only.
    #[serde(skip)]
    pub signature_clipped: bool,
}

pub fn parse_spec(raw: &str) -> Result<SliceSpec, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty slice spec".to_owned());
    }
    if let Some((path_part, sel)) = trimmed.split_once("::") {
        if path_part.is_empty() || sel.trim().is_empty() {
            return Err(format!(
                "invalid slice spec `{raw}`; expected <path>::<selector>"
            ));
        }
        // A purely numeric tail after `::` is a line-range list, not a
        // selector: the harness instructions have long written ranges as
        // `<path>::<start>-<end>`, so accept that form alongside
        // `<path>:<start>-<end>` instead of failing the symbol lookup.
        let sel = sel.trim();
        if let Some(n) = parse_tail_count(sel) {
            return Ok(SliceSpec {
                path: PathBuf::from(path_part),
                target: SliceTarget::Tail(n),
            });
        }
        if looks_like_range_list(sel) {
            let ranges = parse_ranges(sel, raw)?;
            return Ok(SliceSpec {
                path: PathBuf::from(path_part),
                target: SliceTarget::Ranges(ranges),
            });
        }
        return Ok(SliceSpec {
            path: PathBuf::from(path_part),
            target: SliceTarget::Selector(sel.to_owned()),
        });
    }

    if let Some((path_part, range_part)) = trimmed.rsplit_once(':') {
        let is_drive_prefix = path_part.len() == 1 && range_part.starts_with(['\\', '/']);
        if !path_part.is_empty() && !is_drive_prefix {
            if let Some(n) = parse_tail_count(range_part) {
                return Ok(SliceSpec {
                    path: PathBuf::from(path_part),
                    target: SliceTarget::Tail(n),
                });
            }
        }
        if !path_part.is_empty() && !is_drive_prefix && looks_like_range_list(range_part) {
            let ranges = parse_ranges(range_part, raw)?;
            return Ok(SliceSpec {
                path: PathBuf::from(path_part),
                target: SliceTarget::Ranges(ranges),
            });
        }
    }

    Err(format!(
        "missing range or selector in `{raw}`; pass <path>:<start>-<end> or <path>::<selector> (or run `prometheus-kit outline <path>`)"
    ))
}

fn looks_like_range_list(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b',')
}

/// `<path>:-<n>` (n >= 1): the last `n` lines. Returns `None` for any other
/// shape, including `-0`, so malformed specs keep their existing errors.
fn parse_tail_count(part: &str) -> Option<usize> {
    let digits = part.strip_prefix('-')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: usize = digits.parse().ok()?;
    if n >= 1 {
        Some(n)
    } else {
        None
    }
}

fn parse_ranges(part: &str, full_spec: &str) -> Result<Vec<(usize, usize)>, String> {
    let mut out = Vec::new();
    for seg in part.split(',') {
        let seg = seg.trim();
        if seg.is_empty() {
            return Err(format!("empty line range in `{full_spec}`"));
        }
        if let Some((a, b)) = seg.split_once('-') {
            let start = a
                .parse::<usize>()
                .map_err(|_| format!("invalid start line `{a}` in `{full_spec}`"))?;
            // An open end (`<start>-`) runs to the end of the file; the
            // merge step clamps it to the file's actual length. This is
            // the whole-file form the hook emits for `cat`/`nl`.
            let end = if b.is_empty() {
                usize::MAX
            } else {
                b.parse::<usize>()
                    .map_err(|_| format!("invalid end line `{b}` in `{full_spec}`"))?
            };
            if start == 0 || end < start {
                return Err(format!(
                    "invalid line range `{seg}` in `{full_spec}` (start must be >= 1 and <= end)"
                ));
            }
            out.push((start, end));
        } else {
            let line = seg
                .parse::<usize>()
                .map_err(|_| format!("invalid line number `{seg}` in `{full_spec}`"))?;
            if line == 0 {
                return Err(format!(
                    "invalid line number `0` in `{full_spec}` (lines are 1-based)"
                ));
            }
            out.push((line, line));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct Interval {
    start: usize,
    end: usize,
    label: Option<String>,
    signature: Option<String>,
}

fn merge_intervals(
    raw: Vec<Interval>,
    total_lines: usize,
    context_lines: usize,
) -> Result<Vec<Interval>, String> {
    if total_lines == 0 {
        return Err("file is empty (0 lines)".to_owned());
    }
    let mut normalized = Vec::with_capacity(raw.len());
    for item in raw {
        if item.start > total_lines {
            return Err(format!(
                "requested line {} exceeds file length ({total_lines} lines)",
                item.start
            ));
        }
        let s = item.start.saturating_sub(context_lines).max(1);
        let e = item.end.saturating_add(context_lines).min(total_lines);
        if s <= e {
            normalized.push(Interval {
                start: s,
                end: e,
                label: item.label,
                signature: item.signature,
            });
        }
    }
    normalized.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));

    let mut merged: Vec<Interval> = Vec::new();
    for item in normalized {
        if let Some(last) = merged.last_mut() {
            if item.start <= last.end + 1 {
                last.end = last.end.max(item.end);
                match (&mut last.label, item.label) {
                    (Some(existing), Some(new_lbl)) if !existing.split(", ").any(|x| x == new_lbl) => {
                        existing.push_str(", ");
                        existing.push_str(&new_lbl);
                    }
                    (None, Some(new_lbl)) => last.label = Some(new_lbl),
                    _ => {}
                }
                match (&mut last.signature, item.signature) {
                    (Some(existing), Some(new_sig)) if existing != &new_sig => {
                        existing.push('\n');
                        existing.push_str(&new_sig);
                    }
                    (None, Some(new_sig)) => last.signature = Some(new_sig),
                    _ => {}
                }
                continue;
            }
        }
        merged.push(item);
    }
    Ok(merged)
}

fn norm_sep(s: &str) -> String {
    s.replace("::", ".")
}

fn resolve_code_selector(
    path: &str,
    src: &str,
    lang: Lang,
    selector: &str,
) -> Result<Vec<Interval>, String> {
    let opts = OutlineOptions {
        include_all: true,
        ..OutlineOptions::default()
    };
    let doc = outline_source(path, src, lang, &opts);
    let flat = flatten_items(&doc.items);
    let sel = selector.trim();
    let sel_norm = norm_sep(sel);
    let sel_lower = sel_norm.to_ascii_lowercase();
    let suffix_exact = format!(".{sel_norm}");
    let suffix_lower = format!(".{sel_lower}");

    let to_intervals = |matched: Vec<&OutlineItem>| -> Vec<Interval> {
        matched
            .into_iter()
            .map(|it| Interval {
                start: it.start_line,
                end: it.end_line,
                label: Some(it.qualified_name.clone()),
                signature: Some(it.signature.clone()),
            })
            .collect()
    };

    // 1. Exact qualified_name (normalizing `.` and `::`)
    let exact_q: Vec<&OutlineItem> = flat
        .iter()
        .copied()
        .filter(|it| norm_sep(&it.qualified_name) == sel_norm)
        .collect();
    if !exact_q.is_empty() {
        return Ok(to_intervals(exact_q));
    }

    // 2. Exact short name
    let exact_n: Vec<&OutlineItem> = flat.iter().copied().filter(|it| it.name == sel).collect();
    if !exact_n.is_empty() {
        return Ok(to_intervals(exact_n));
    }

    // 3. Qualified suffix match (skip leading namespace like `OrderService.ProcessAsync`)
    let suffix_q: Vec<&OutlineItem> = flat
        .iter()
        .copied()
        .filter(|it| norm_sep(&it.qualified_name).ends_with(&suffix_exact))
        .collect();
    if !suffix_q.is_empty() {
        return Ok(to_intervals(suffix_q));
    }

    // 4. Case-insensitive qualified_name, short name, then suffix
    let ci_q: Vec<&OutlineItem> = flat
        .iter()
        .copied()
        .filter(|it| norm_sep(&it.qualified_name).to_ascii_lowercase() == sel_lower)
        .collect();
    if !ci_q.is_empty() {
        return Ok(to_intervals(ci_q));
    }
    let ci_n: Vec<&OutlineItem> = flat
        .iter()
        .copied()
        .filter(|it| it.name.to_ascii_lowercase() == sel_lower)
        .collect();
    if !ci_n.is_empty() {
        return Ok(to_intervals(ci_n));
    }
    let ci_suffix: Vec<&OutlineItem> = flat
        .iter()
        .copied()
        .filter(|it| {
            norm_sep(&it.qualified_name)
                .to_ascii_lowercase()
                .ends_with(&suffix_lower)
        })
        .collect();
    if !ci_suffix.is_empty() {
        return Ok(to_intervals(ci_suffix));
    }

    let sugg = suggest_candidates(sel, flat.iter().map(|it| it.qualified_name.as_str()), true);
    Err(format!(
        "{path}: symbol `{sel}` not found; closest: {}",
        if sugg.is_empty() {
            "<none>".to_owned()
        } else {
            sugg.join(", ")
        }
    ))
}

enum SpecResolution {
    Intervals(Vec<Interval>),
    Computed(ComputedSelection),
}

fn resolve_ranges_for_spec(
    path_str: &str,
    src: &str,
    idx: &LineIndex,
    lang: Option<Lang>,
    target: &SliceTarget,
) -> Result<SpecResolution, String> {
    match target {
        SliceTarget::Ranges(ranges) => Ok(SpecResolution::Intervals(
            ranges
                .iter()
                .map(|&(start, end)| Interval {
                    start,
                    end,
                    label: None,
                    signature: None,
                })
                .collect(),
        )),
        SliceTarget::Tail(n) => {
            let total = idx.total_lines();
            if total == 0 {
                return Ok(SpecResolution::Intervals(Vec::new()));
            }
            Ok(SpecResolution::Intervals(vec![Interval {
                start: total.saturating_sub(*n - 1).max(1),
                end: total,
                label: None,
                signature: None,
            }]))
        }
        SliceTarget::Selector(sel) => {
            let lang = lang.ok_or_else(|| {
                format!("{path_str}: unsupported file type for symbol/path selector (pass --lang or line ranges)")
            })?;
            if lang.is_structured() {
                // Computed selectors (#77): `<base>@count`, `<base>@keys`,
                // `<base>@fields(a,b)` over JSON/JSONL/YAML/TOML values.
                if !matches!(lang, Lang::Markdown) {
                    if let Some((base, op)) = split_computed_selector(sel) {
                        let computed =
                            resolve_computed_selector(src, idx, lang, base, &op, sel)
                                .map_err(|e| format!("{path_str}: {e}"))?;
                        return Ok(SpecResolution::Computed(computed));
                    }
                }
                let resolved: Vec<ResolvedRange> =
                    resolve_structured_selector(src, idx, lang, sel)
                        .map_err(|e| format!("{path_str}: {e}"))?;
                Ok(SpecResolution::Intervals(
                    resolved
                        .into_iter()
                        .map(|r| Interval {
                            start: r.start_line,
                            end: r.end_line,
                            label: Some(r.label),
                            signature: None,
                        })
                        .collect(),
                ))
            } else {
                resolve_code_selector(path_str, src, lang, sel)
                    .map(SpecResolution::Intervals)
            }
        }
    }
}

fn truncate_long_line(line: &str) -> (String, bool) {
    let count = line.chars().count();
    if count <= MAX_LINE_CHARS {
        return (line.to_owned(), false);
    }
    let head: String = line.chars().take(1000).collect();
    let tail: String = line
        .chars()
        .rev()
        .take(200)
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    let omitted = count - 1200;
    (
        format!("{head}... [truncated {omitted} chars] ...{tail}"),
        true,
    )
}

fn clip_line_to_chars(line: &str, max_chars: usize) -> (String, bool) {
    let count = line.chars().count();
    if count <= max_chars {
        return (line.to_owned(), false);
    }
    let keep = max_chars.saturating_sub(28).max(16);
    let head: String = line.chars().take(keep).collect();
    let omitted = count.saturating_sub(keep);
    (format!("{head}... [truncated {omitted} chars]"), true)
}

pub fn execute_slices(specs: &[SliceSpec], opts: &SliceOptions) -> Result<SliceResult, String> {
    struct CachedFile {
        src: String,
        idx: LineIndex,
        lang: Option<Lang>,
    }
    let mut cache: HashMap<PathBuf, CachedFile> = HashMap::new();
    let mut warnings = Vec::new();

    struct FileIntervals {
        path: PathBuf,
        display: String,
        intervals: Vec<Interval>,
    }
    let mut per_file_order: Vec<PathBuf> = Vec::new();
    let mut per_file_map: HashMap<PathBuf, FileIntervals> = HashMap::new();
    let mut computed_blocks: Vec<(String, ComputedSelection)> = Vec::new();

    for spec in specs {
        let key = std::fs::canonicalize(&spec.path).unwrap_or_else(|_| spec.path.clone());
        if !cache.contains_key(&key) {
            let (src, w) = read_text_file(&spec.path)?;
            for msg in w {
                warnings.push(format!("{}: {msg}", spec.path.display()));
            }
            let idx = LineIndex::new(&src);
            let lang = opts.lang_override.or_else(|| Lang::from_path(&spec.path));
            cache.insert(key.clone(), CachedFile { src, idx, lang });
        }
        let cached = cache.get(&key).unwrap();
        let display = spec.path.to_string_lossy().to_string();
        let resolution = resolve_ranges_for_spec(
            &display,
            &cached.src,
            &cached.idx,
            cached.lang,
            &spec.target,
        )?;
        match resolution {
            SpecResolution::Computed(computed) => {
                computed_blocks.push((display, computed));
            }
            SpecResolution::Intervals(intervals) => {
                if !per_file_map.contains_key(&key) {
                    per_file_order.push(key.clone());
                    per_file_map.insert(
                        key.clone(),
                        FileIntervals {
                            path: spec.path.clone(),
                            display,
                            intervals,
                        },
                    );
                } else {
                    per_file_map.get_mut(&key).unwrap().intervals.extend(intervals);
                }
            }
        }
    }

    let unlimited = opts.max_tokens == 0;
    let budget_chars = if unlimited {
        usize::MAX
    } else {
        opts.max_tokens.saturating_mul(4)
    };
    const RESERVE: usize = 96;
    let mut used = 0usize;
    let mut kept = Vec::new();
    let mut omitted_slices = 0usize;
    let mut omitted_lines = 0usize;
    let mut truncated = false;
    let mut raw_bytes = 0usize;
    let mut signature_clipped = false;

    for key in per_file_order {
        let entry = per_file_map.remove(&key).unwrap();
        let cached = cache.get(&key).unwrap();
        let merged = merge_intervals(
            entry.intervals,
            cached.idx.total_lines(),
            if opts.signatures_only { 0 } else { opts.context_lines },
        )
        .map_err(|e| format!("{}: {e}", entry.path.display()))?;

        for iv in merged {
            // Raw input is the full merged selected span(s) before any budget
            // cut — signatures-only runs charge the whole interval even though
            // only the signature is emitted. Counted even when the interval is
            // later omitted.
            let end_excl = if iv.end < cached.idx.total_lines() {
                cached.idx.line_start(iv.end + 1)
            } else {
                cached.src.len()
            };
            raw_bytes += end_excl.saturating_sub(cached.idx.line_start(iv.start));
            signature_clipped |= opts.signatures_only && iv.end > iv.start;
            let line_total = if opts.signatures_only {
                1
            } else {
                iv.end - iv.start + 1
            };
            if truncated {
                omitted_slices += 1;
                omitted_lines += line_total;
                continue;
            }
            let header_cost = entry.display.len() + 32;
            if !unlimited && !kept.is_empty() && used + header_cost + RESERVE > budget_chars {
                truncated = true;
                omitted_slices += 1;
                omitted_lines += line_total;
                continue;
            }
            used += header_cost;

            let mut block_lines = Vec::new();
            if opts.signatures_only {
                let (mut text, mut line_trunc) = if let Some(sig) = &iv.signature {
                    (sig.clone(), false)
                } else {
                    let raw_line = cached.idx.line_slice(&cached.src, iv.start);
                    if opts.truncate_long_lines {
                        truncate_long_line(raw_line)
                    } else {
                        (raw_line.to_owned(), false)
                    }
                };
                if !unlimited && used + text.len() + 10 + RESERVE > budget_chars {
                    if kept.is_empty() {
                        let avail = budget_chars.saturating_sub(used + RESERVE + 10);
                        let (clipped, _) = clip_line_to_chars(&text, avail.max(24));
                        text = clipped;
                        line_trunc = true;
                        truncated = true;
                        block_lines.push(SliceLine {
                            line: iv.start,
                            text,
                            truncated: line_trunc,
                        });
                    } else {
                        truncated = true;
                        omitted_slices += 1;
                        omitted_lines += 1;
                        continue;
                    }
                } else {
                    used += text.len() + 10;
                    block_lines.push(SliceLine {
                        line: iv.start,
                        text,
                        truncated: line_trunc,
                    });
                }
            } else {
                for ln in iv.start..=iv.end {
                    let raw_line = cached.idx.line_slice(&cached.src, ln);
                    let (mut text, mut line_trunc) = if opts.truncate_long_lines {
                        truncate_long_line(raw_line)
                    } else {
                        (raw_line.to_owned(), false)
                    };
                    let cost = text.len() + 10;
                    if !unlimited && used + cost + RESERVE > budget_chars {
                        if block_lines.is_empty() && kept.is_empty() {
                            let avail = budget_chars.saturating_sub(used + RESERVE + 10);
                            let (clipped, _) = clip_line_to_chars(&text, avail.max(24));
                            text = clipped;
                            line_trunc = true;
                            block_lines.push(SliceLine {
                                line: ln,
                                text,
                                truncated: line_trunc,
                            });
                            truncated = true;
                            omitted_lines += iv.end - ln;
                        } else {
                            truncated = true;
                            omitted_lines += iv.end - ln + 1;
                        }
                        break;
                    }
                    used += cost;
                    block_lines.push(SliceLine {
                        line: ln,
                        text,
                        truncated: line_trunc,
                    });
                }
            }

            if !block_lines.is_empty() {
                kept.push(SliceBlock {
                    path: entry.display.clone(),
                    label: iv.label,
                    start_line: iv.start,
                    end_line: iv.end,
                    signature: iv.signature,
                    lines: block_lines,
                });
            } else {
                omitted_slices += 1;
            }
        }
    }

    // Computed selections (#77) emit synthesized lines, not source lines:
    // they share the same token budget, and clipping them sets `truncated`
    // so the renderer's omitted-lines notice applies.
    for (display, computed) in computed_blocks {
        raw_bytes += computed.lines.iter().map(|l| l.len() + 1).sum::<usize>();
        if truncated {
            omitted_slices += 1;
            omitted_lines += computed.lines.len();
            continue;
        }
        let header_cost = display.len() + 32;
        if !unlimited && !kept.is_empty() && used + header_cost + RESERVE > budget_chars {
            truncated = true;
            omitted_slices += 1;
            omitted_lines += computed.lines.len();
            continue;
        }
        used += header_cost;
        let mut block_lines = Vec::new();
        for (i, text) in computed.lines.iter().enumerate() {
            let (text, line_trunc) = if opts.truncate_long_lines {
                truncate_long_line(text)
            } else {
                (text.clone(), false)
            };
            let cost = text.len() + 10;
            if !unlimited && used + cost + RESERVE > budget_chars {
                truncated = true;
                omitted_lines += computed.lines.len() - i;
                break;
            }
            used += cost;
            block_lines.push(SliceLine {
                line: 0,
                text,
                truncated: line_trunc,
            });
        }
        if !block_lines.is_empty() {
            kept.push(SliceBlock {
                path: display,
                label: Some(computed.label),
                start_line: 0,
                end_line: 0,
                signature: None,
                lines: block_lines,
            });
        } else {
            omitted_slices += 1;
        }
    }

    Ok(SliceResult {
        slices: kept,
        truncated,
        omitted_slices,
        omitted_lines,
        warnings,
        raw_bytes,
        signature_clipped,
    })
}

pub fn render_slice_text(result: &SliceResult, opts: &SliceOptions) -> String {
    let mut out = String::new();
    for w in &result.warnings {
        out.push_str(&format!("warning: {w}\n"));
    }
    for (i, block) in result.slices.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        // Computed selections (#77) have no source range: header names the
        // selector, and the synthesized lines print without `L<n>:` prefixes.
        if block.start_line == 0 && block.end_line == 0 {
            out.push_str(&format!(
                "=== {} ({}) ===\n",
                block.path,
                block.label.as_deref().unwrap_or("computed")
            ));
            for line in &block.lines {
                out.push_str(&line.text);
                out.push('\n');
            }
            continue;
        }
        let range = if block.start_line == block.end_line {
            format!("L{}", block.start_line)
        } else {
            format!("L{}-L{}", block.start_line, block.end_line)
        };
        if opts.signatures_only {
            let text = block
                .lines
                .first()
                .map(|l| l.text.as_str())
                .unwrap_or("");
            out.push_str(&format!("{}:{range} {text}\n", block.path));
            continue;
        }
        match &block.label {
            Some(lbl) => out.push_str(&format!("=== {}:{range} ({lbl}) ===\n", block.path)),
            None => out.push_str(&format!("=== {}:{range} ===\n", block.path)),
        }
        for line in &block.lines {
            if opts.line_numbers {
                out.push_str(&format!("L{}: {}\n", line.line, line.text));
            } else {
                out.push_str(&format!("{}\n", line.text));
            }
        }
    }
    if result.truncated {
        out.push_str(&format!(
            "... (+{} omitted lines across {} additional slices; narrow range or pass --max-tokens)\n",
            result.omitted_lines, result.omitted_slices
        ));
    }
    out
}

pub fn render_slice_json(result: &SliceResult, max_tokens: usize) -> String {
    let encoded = serde_json::to_string(result).unwrap_or_else(|_| "{}".to_owned());
    if max_tokens == 0 {
        return encoded;
    }
    let budget_chars = max_tokens.saturating_mul(4);
    if encoded.len() <= budget_chars {
        return encoded;
    }
    // Trim trailing lines/slices until compact JSON fits within `budget_chars`.
    let mut trimmed = result.clone();
    loop {
        let cur = serde_json::to_string(&trimmed).unwrap_or_else(|_| "{}".to_owned());
        if cur.len() <= budget_chars || trimmed.slices.is_empty() {
            return cur;
        }
        if let Some(last) = trimmed.slices.last_mut() {
            if last.lines.len() > 1 {
                last.lines.pop();
                trimmed.truncated = true;
                trimmed.omitted_lines += 1;
                continue;
            }
        }
        if let Some(dropped) = trimmed.slices.pop() {
            trimmed.truncated = true;
            trimmed.omitted_slices += 1;
            trimmed.omitted_lines += dropped.lines.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str, content: &[u8]) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("prom_kit_slice_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    #[test]
    fn parse_spec_preserves_windows_drive_letter_and_parses_ranges_and_selectors() {
        let s1 = parse_spec(r"C:\src\OrderService.cs:10-25,40").unwrap();
        assert_eq!(s1.path, PathBuf::from(r"C:\src\OrderService.cs"));
        assert_eq!(s1.target, SliceTarget::Ranges(vec![(10, 25), (40, 40)]));

        let s2 = parse_spec("core/src/check.rs::Store::get").unwrap();
        assert_eq!(s2.path, PathBuf::from("core/src/check.rs"));
        assert_eq!(s2.target, SliceTarget::Selector("Store::get".to_owned()));

        assert!(parse_spec(r"C:\src\OrderService.cs").is_err());
        assert!(parse_spec("foo.rs:20-10").is_err());
        assert!(parse_spec("foo.rs:0").is_err());
    }

    #[test]
    fn parse_spec_accepts_double_colon_ranges_as_written_by_harness_instructions() {
        // Regression: the harness instructions wrote ranges as
        // `<path>::<start>-<end>` and every such slice failed the symbol
        // lookup (e.g. `EmployerGroupAdminService.cs::133-224`).
        let s = parse_spec("src/EmployerGroupAdminService.cs::133-224").unwrap();
        assert_eq!(s.path, PathBuf::from("src/EmployerGroupAdminService.cs"));
        assert_eq!(s.target, SliceTarget::Ranges(vec![(133, 224)]));

        let list = parse_spec("src/a.rs::10-25,40").unwrap();
        assert_eq!(
            list.target,
            SliceTarget::Ranges(vec![(10, 25), (40, 40)])
        );

        // A qualified symbol containing `::` stays a selector.
        let sym = parse_spec("src/a.rs::Foo::Bar").unwrap();
        assert_eq!(
            sym.target,
            SliceTarget::Selector("Foo::Bar".to_owned())
        );

        assert!(parse_spec("foo.rs::20-10").is_err());
        assert!(parse_spec("foo.rs::0").is_err());
    }

    #[test]
    fn parse_and_execute_open_ended_and_tail_specs() {
        // `<path>:<start>-` runs to the end of the file (the hook's
        // `cat`/`nl` form); `<path>:-<n>` is the last n lines (its
        // `tail -n` form), in both the `:` and `::` spellings.
        let open = parse_spec("src/a.rs:1-").unwrap();
        assert_eq!(open.target, SliceTarget::Ranges(vec![(1, usize::MAX)]));
        let tail = parse_spec("src/a.rs:-3").unwrap();
        assert_eq!(tail.target, SliceTarget::Tail(3));
        let tail2 = parse_spec("src/a.rs::-3").unwrap();
        assert_eq!(tail2.target, SliceTarget::Tail(3));
        assert!(parse_spec("src/a.rs:-0").is_err() || parse_spec("src/a.rs:-0").unwrap().target != SliceTarget::Tail(0));

        let p = temp_file("sample.txt", b"l1\nl2\nl3\nl4\nl5\n");
        let whole = parse_spec(&format!("{}:1-", p.display())).unwrap();
        let res = execute_slices(&[whole], &SliceOptions::default()).unwrap();
        assert_eq!(res.slices[0].start_line, 1);
        assert_eq!(res.slices[0].end_line, 5);

        let last = parse_spec(&format!("{}:-2", p.display())).unwrap();
        let res = execute_slices(&[last], &SliceOptions::default()).unwrap();
        assert_eq!(res.slices[0].start_line, 4);
        assert_eq!(res.slices[0].end_line, 5);
        assert_eq!(res.slices[0].lines[0].text, "l4");

        // A tail larger than the file clamps to the whole file.
        let big = parse_spec(&format!("{}:-99", p.display())).unwrap();
        let res = execute_slices(&[big], &SliceOptions::default()).unwrap();
        assert_eq!(res.slices[0].start_line, 1);
        assert_eq!(res.slices[0].end_line, 5);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn computed_selectors_count_keys_and_project_on_each_format() {
        // JSON
        let pj = temp_file(
            "data.json",
            b"{\n  \"users\": [\n    {\"id\": 1, \"name\": \"ana\", \"role\": \"dev\"},\n    {\"id\": 2, \"name\": \"bob\", \"role\": \"ops\"}\n  ],\n  \"meta\": {\"total\": 2, \"page\": 1}\n}\n",
        );
        let run = |path: &PathBuf, sel: &str| {
            let spec = parse_spec(&format!("{}::{sel}", path.display())).unwrap();
            execute_slices(&[spec], &SliceOptions::default()).unwrap()
        };
        let res = run(&pj, "/users@count");
        assert_eq!(res.slices[0].lines[0].text, "2");
        let res = run(&pj, "@count");
        assert_eq!(res.slices[0].lines[0].text, "2");
        let res = run(&pj, "/meta@keys");
        let mut keys: Vec<&str> = res.slices[0].lines.iter().map(|l| l.text.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["page", "total"]);
        let res = run(&pj, "/users@fields(id,name)");
        let rows: Vec<&str> = res.slices[0].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(rows, vec!["{\"id\":1,\"name\":\"ana\"}", "{\"id\":2,\"name\":\"bob\"}"]);
        let rendered = render_slice_text(&res, &SliceOptions::default());
        assert!(rendered.contains("/users@fields(id,name)"));
        let _ = std::fs::remove_dir_all(pj.parent().unwrap());

        // JSONL
        let pl = temp_file(
            "rows.jsonl",
            b"{\"type\":\"msg\",\"id\":1,\"v\":10}\n{\"type\":\"err\",\"id\":2,\"v\":20}\n{\"type\":\"msg\",\"id\":3,\"v\":30}\n",
        );
        let res = run(&pl, "type=msg@count");
        assert_eq!(res.slices[0].lines[0].text, "2");
        let res = run(&pl, "@count");
        assert_eq!(res.slices[0].lines[0].text, "3");
        let res = run(&pl, "type=msg@fields(id,v)");
        let rows: Vec<&str> = res.slices[0].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(rows, vec!["{\"id\":1,\"v\":10}", "{\"id\":3,\"v\":30}"]);
        let res = run(&pl, "@keys");
        let mut keys: Vec<&str> = res.slices[0].lines.iter().map(|l| l.text.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["id", "type", "v"]);
        let _ = std::fs::remove_dir_all(pl.parent().unwrap());

        // YAML
        let py = temp_file(
            "data.yaml",
            b"users:\n  - id: 1\n    name: ana\n  - id: 2\n    name: bob\nmeta:\n  total: 2\n  page: 1\n",
        );
        let res = run(&py, "users@count");
        assert_eq!(res.slices[0].lines[0].text, "2");
        let res = run(&py, "meta@keys");
        let keys: Vec<&str> = res.slices[0].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(keys, vec!["total", "page"]);
        let res = run(&py, "users@fields(id,name)");
        let rows: Vec<&str> = res.slices[0].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(rows, vec!["{id: 1, name: ana}", "{id: 2, name: bob}"]);
        let _ = std::fs::remove_dir_all(py.parent().unwrap());

        // TOML
        let pt = temp_file(
            "data.toml",
            b"[meta]\ntotal = 2\npage = 1\n\n[[bin]]\nname = \"a\"\nsize = 3\n\n[[bin]]\nname = \"b\"\nsize = 4\n",
        );
        let res = run(&pt, "bin@count");
        assert_eq!(res.slices[0].lines[0].text, "2");
        let res = run(&pt, "meta@keys");
        let keys: Vec<&str> = res.slices[0].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(keys, vec!["total", "page"]);
        let res = run(&pt, "bin@fields(name,size)");
        let rows: Vec<&str> = res.slices[0].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(rows, vec!["{name: \"a\", size: 3}", "{name: \"b\", size: 4}"]);
        let _ = std::fs::remove_dir_all(pt.parent().unwrap());
    }

    #[test]
    fn computed_selector_output_clips_under_the_token_budget() {
        let mut src = String::from("{\"rows\": [");
        for i in 0..200 {
            if i > 0 {
                src.push(',');
            }
            src.push_str(&format!("{{\"id\": {i}, \"name\": \"row-{i}\"}}"));
        }
        src.push_str("]}");
        let p = temp_file("big.json", src.as_bytes());
        let spec = parse_spec(&format!("{}::/rows@fields(id,name)", p.display())).unwrap();
        let opts = SliceOptions {
            max_tokens: 100,
            ..SliceOptions::default()
        };
        let res = execute_slices(&[spec], &opts).unwrap();
        assert!(res.truncated);
        assert!(res.omitted_lines > 0);
        let rendered = render_slice_text(&res, &opts);
        assert!(rendered.contains("omitted lines"), "{rendered}");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn merges_overlapping_ranges_with_context_and_truncates_long_lines() {
        let long = "x".repeat(2500);
        let src = format!("line1\nline2\nline3\nline4\n{long}\nline6\n");
        let p = temp_file("sample.txt", src.as_bytes());
        let specs = vec![
            parse_spec(&format!("{}:1-2", p.display())).unwrap(),
            parse_spec(&format!("{}:3-5", p.display())).unwrap(),
        ];
        let opts = SliceOptions {
            context_lines: 1,
            ..SliceOptions::default()
        };
        let res = execute_slices(&specs, &opts).unwrap();
        assert_eq!(res.slices.len(), 1);
        assert_eq!(res.slices[0].start_line, 1);
        assert_eq!(res.slices[0].end_line, 6);
        assert!(res.slices[0].lines[4].truncated);
        assert!(res.slices[0].lines[4].text.contains("[truncated 1300 chars]"));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn resolves_csharp_suffix_and_gives_suggestions_on_missing_symbol() {
        let src = "namespace A.B;\npublic class Svc {\n    public void Run() {}\n    public void Stop() {}\n}\n";
        let p = temp_file("Svc.cs", src.as_bytes());
        let spec = parse_spec(&format!("{}::Svc.Run", p.display())).unwrap();
        let res = execute_slices(&[spec], &SliceOptions::default()).unwrap();
        assert_eq!(res.slices[0].start_line, 3);
        assert_eq!(res.slices[0].end_line, 3);

        let missing = parse_spec(&format!("{}::Rn", p.display())).unwrap();
        let err = execute_slices(&[missing], &SliceOptions::default()).unwrap_err();
        assert!(err.contains("A.B.Svc.Run"));

        let unrelated = parse_spec(&format!("{}::ZzzCompletelyUnrelated", p.display())).unwrap();
        let err2 = execute_slices(&[unrelated], &SliceOptions::default()).unwrap_err();
        assert!(err2.contains("closest: <none>"));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn no_truncate_lines_still_respects_nonzero_max_tokens() {
        let huge = "a".repeat(8000);
        let p = temp_file("huge.txt", format!("{huge}\n").as_bytes());
        let spec = parse_spec(&format!("{}:1", p.display())).unwrap();
        let opts = SliceOptions {
            max_tokens: 40,
            truncate_long_lines: false,
            ..SliceOptions::default()
        };
        let res = execute_slices(&[spec], &opts).unwrap();
        assert!(res.truncated);
        let txt = render_slice_text(&res, &opts);
        assert!(txt.len() <= 300, "unexpected len {}", txt.len());
        let json = render_slice_json(&res, opts.max_tokens);
        assert!(json.len() <= 200, "unexpected json len {}", json.len());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn rejects_binary_files_cleanly() {
        let p = temp_file("blob.bin", b"\x00\x01\x02\x03");
        let spec = parse_spec(&format!("{}:1-5", p.display())).unwrap();
        let err = execute_slices(&[spec], &SliceOptions::default()).unwrap_err();
        assert!(err.contains("binary file skipped"));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
