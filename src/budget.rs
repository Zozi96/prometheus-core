//! One token budget module for every Kit command (ADR-0017 D5/D6).
//!
//! A Kit command hands this module its result, its **Keep policy**, its
//! truncation notice, and the budget. The module owns the tokens-to-bytes
//! conversion, the trim loop, and the notice guarantee, and it measures
//! each trim against the format being emitted (text or `--json`), never
//! against another format's rendering.
//!
//! Guarantees:
//! - Text: output never exceeds the budget, the cut falls on a line end,
//!   and the command's notice survives whenever anything was trimmed. A
//!   budget smaller than the notice gives the notice alone.
//! - `--json`: the document is always valid; the smallest valid document
//!   may exceed the budget.
//! - A budget of zero means no limit.

use serde::Serialize;

/// Bytes charged per token in every Kit command's `--max-tokens` budget.
/// This is the only tokens-to-bytes conversion in the codebase.
pub const BYTES_PER_TOKEN: usize = 4;

/// The part of a Kit command's result that survives a budget trim
/// (GLOSSARY.md: **Keep policy**).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepPolicy {
    /// Keep the beginning (`search`, `diff`, `slice`, `outline`).
    Head,
    /// Keep the end (`compact`: a log fails at its end).
    Tail,
    /// Keep the upper levels (`map`: deepest directories collapse first).
    UpperLevels,
}

/// Convert a token budget to its byte budget. `None` means no limit
/// (a budget of zero).
pub fn tokens_to_bytes(max_tokens: usize) -> Option<usize> {
    if max_tokens == 0 {
        None
    } else {
        Some(max_tokens.saturating_mul(BYTES_PER_TOKEN))
    }
}

/// Byte budget for `max_tokens`, or `usize::MAX` when unlimited.
pub fn byte_budget_or_max(max_tokens: usize) -> usize {
    tokens_to_bytes(max_tokens).unwrap_or(usize::MAX)
}

/// Whole tokens needed to cover `byte_len` bytes, rounding up. Used at
/// the binary's edge to reserve budget for a fixed line (the `compact
/// --keep-log` pointer) without re-implementing the conversion.
pub fn tokens_for_bytes(byte_len: usize) -> usize {
    byte_len.div_ceil(BYTES_PER_TOKEN)
}

/// Trim `state` until `render(state)` fits the byte budget for
/// `max_tokens`, calling `step` for one give-up at a time. `step` is the
/// command's Keep policy made concrete: it drops the next piece of the
/// result (and records the trim on the result) and returns `false` when
/// nothing more can be given up. The loop stops at the smallest result
/// the policy can produce, even if that still exceeds the budget — for
/// text the caller then applies [`finish_text`]; for `--json` that
/// smallest valid document is the answer.
pub fn trim_structured<S>(
    state: &mut S,
    max_tokens: usize,
    render: impl Fn(&S) -> String,
    mut step: impl FnMut(&mut S) -> bool,
) {
    let Some(budget) = tokens_to_bytes(max_tokens) else {
        return;
    };
    while render(state).len() > budget {
        if !step(state) {
            break;
        }
    }
}

/// Like [`trim_structured`], but finds the step count by exponential
/// probing plus binary search instead of rendering after every single
/// step — O(log n) renders instead of O(n), which removes the
/// quadratic rendering of large results (each probe still renders in
/// full, so the count of renders is what changes, never the output).
///
/// Extra contract over [`trim_structured`], which the caller must
/// guarantee (outline's JSON policy does: past the first step, which
/// adds the truncation notice, every further step removes a whole
/// rendered item — a text line or a JSON object — larger than any
/// growth of the omitted-count digits; batch TEXT outlines do not
/// meet it — their notice changes composition and empty files gain
/// a placeholder line — so they use an exact segmented search in
/// the outline module instead):
/// - rendered length is monotone non-increasing in the step count, so
///   "fits the budget" is a suffix property of the step count and the
///   first fitting count the search finds is the same one the
///   sequential loop stops at;
/// - `step` is a pure function of the state (applying the same number
///   of steps to a clone of the initial state gives the same state),
///   because probes re-apply steps from the initial state.
///
/// The search's bounds are factual, not assumed: `lo` is always a
/// probed count whose render exceeded the budget and `hi` a probed
/// count whose render fits (or the exhausted smallest result).
pub fn trim_structured_bisect<S: Clone>(
    state: &mut S,
    max_tokens: usize,
    render: impl Fn(&S) -> String,
    mut step: impl FnMut(&mut S) -> bool,
) {
    let Some(budget) = tokens_to_bytes(max_tokens) else {
        return;
    };
    if render(state).len() <= budget {
        return;
    }
    let initial = state.clone();
    // Apply `count` steps to a fresh clone of the initial state and
    // render it: (state, steps actually applied, rendered length).
    let mut probe = |count: usize| -> (S, usize, usize) {
        let mut candidate = initial.clone();
        let mut applied = 0;
        while applied < count && step(&mut candidate) {
            applied += 1;
        }
        let len = render(&candidate).len();
        (candidate, applied, len)
    };
    // Exponential probing for a fitting (or exhausted) upper bound.
    let mut lo = 0usize; // probed: render exceeds the budget (count 0, above)
    let mut hi = 1usize;
    let hi_state = loop {
        let (candidate, applied, len) = probe(hi);
        if applied < hi {
            // Steps exhausted at `applied`: the smallest result. If
            // it does not fit, the sequential loop ends there too;
            // if it fits, the first fitting count lies in (lo,
            // applied] and the binary search below finds it.
            if len > budget {
                *state = candidate;
                return;
            }
            hi = applied;
            break candidate;
        }
        if len <= budget {
            break candidate;
        }
        lo = hi;
        hi *= 2;
    };
    // Binary search for the first fitting count in (lo, hi].
    let mut hi_state = hi_state;
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        let (candidate, _applied, len) = probe(mid);
        if len <= budget {
            hi = mid;
            hi_state = candidate;
        } else {
            lo = mid;
        }
    }
    *state = hi_state;
}

/// Enforce the text guarantee (ADR-0017 D6) on a fully rendered string:
/// the result never exceeds the budget, every cut falls on a line end,
/// and `notice` (a single line, without its trailing newline) survives
/// whenever anything was trimmed. A budget smaller than the notice
/// gives the notice alone. Lines are kept from the end named by
/// `policy` (`UpperLevels` keeps from the top, like `Head`).
pub fn finish_text(
    rendered: String,
    max_tokens: usize,
    policy: KeepPolicy,
    notice: &str,
) -> String {
    let Some(budget) = tokens_to_bytes(max_tokens) else {
        return rendered;
    };
    if rendered.len() <= budget {
        return rendered;
    }
    if !notice.is_empty() && budget < notice.len() + 1 {
        return format!("{notice}\n");
    }
    let notice_cost = if notice.is_empty() {
        0
    } else {
        notice.len() + 1
    };
    let lines: Vec<&str> = rendered.lines().collect();
    let mut kept: Vec<&str> = Vec::new();
    let mut used = notice_cost;
    match policy {
        KeepPolicy::Tail => {
            for line in lines.iter().rev() {
                if *line == notice {
                    continue;
                }
                let cost = line.len() + 1;
                if used + cost > budget {
                    break;
                }
                used += cost;
                kept.push(line);
            }
            kept.reverse();
        }
        KeepPolicy::Head | KeepPolicy::UpperLevels => {
            for line in &lines {
                if *line == notice {
                    continue;
                }
                let cost = line.len() + 1;
                if used + cost > budget {
                    break;
                }
                used += cost;
                kept.push(line);
            }
        }
    }
    let mut out = String::new();
    if policy == KeepPolicy::Tail && !notice.is_empty() {
        out.push_str(notice);
        out.push('\n');
    }
    for line in kept {
        out.push_str(line);
        out.push('\n');
    }
    if policy != KeepPolicy::Tail && !notice.is_empty() {
        out.push_str(notice);
        out.push('\n');
    }
    out
}

/// Cap a JSON error list at `max_bytes` of serialized JSON, keeping the
/// head of the list and replacing the dropped tail with one summary
/// entry built by `summary(omitted_count)`. This is the one error-list
/// cap shared by `slice` and `outline` (each used to carry a copy).
/// Returns the capped list and whether anything was dropped.
pub fn cap_error_list<E: Clone + Serialize>(
    errors: &[E],
    max_bytes: usize,
    summary: impl Fn(usize) -> E,
) -> (Vec<E>, bool) {
    if errors.is_empty() {
        return (Vec::new(), false);
    }
    let full = serde_json::to_string(errors).unwrap_or_default();
    if full.len() <= max_bytes {
        return (errors.to_vec(), false);
    }
    let mut kept: Vec<E> = Vec::new();
    for (idx, err) in errors.iter().enumerate() {
        let omitted = errors.len() - idx - 1;
        let mut candidate = kept.clone();
        candidate.push(err.clone());
        if omitted > 0 {
            candidate.push(summary(omitted));
        }
        if serde_json::to_string(&candidate).unwrap_or_default().len() <= max_bytes {
            kept.push(err.clone());
        } else {
            break;
        }
    }
    let omitted = errors.len() - kept.len();
    if omitted > 0 {
        kept.push(summary(omitted));
    }
    while serde_json::to_string(&kept).unwrap_or_default().len() > max_bytes && kept.len() > 1 {
        kept.pop();
        let omitted_now = errors.len().saturating_sub(kept.len().saturating_sub(1));
        if let Some(last) = kept.last_mut() {
            *last = summary(omitted_now);
        }
    }
    (kept, true)
}

/// Append `error: <message>` lines to a text rendering under the token
/// budget, shared by `slice` and `outline`: the first error is clipped
/// with `clip` when it alone would overflow, and any remaining errors
/// collapse into one `... (+N omitted errors)` line.
pub fn append_error_lines(
    out: &mut String,
    messages: &[String],
    max_tokens: usize,
    clip: impl Fn(&str, usize) -> String,
) {
    if messages.is_empty() {
        return;
    }
    let budget_chars = byte_budget_or_max(max_tokens);
    if !out.is_empty() && (budget_chars == usize::MAX || out.len() + 1 < budget_chars) {
        out.push('\n');
    }
    const ERR_TAIL_RESERVE: usize = 36;
    let mut emitted = 0usize;
    for (idx, message) in messages.iter().enumerate() {
        let line = format!("error: {message}\n");
        let remaining_after = messages.len() - idx - 1;
        let reserve = if remaining_after > 0 {
            ERR_TAIL_RESERVE
        } else {
            0
        };
        if budget_chars != usize::MAX && out.len() + line.len() + reserve > budget_chars {
            if emitted == 0 && out.len() + 16 < budget_chars {
                let avail = budget_chars.saturating_sub(out.len() + 8 + reserve);
                let clipped = clip(message, avail.max(16));
                out.push_str(&format!("error: {clipped}\n"));
                emitted += 1;
            }
            let omitted = messages.len().saturating_sub(emitted);
            if omitted > 0 {
                out.push_str(&format!("... (+{omitted} omitted errors)\n"));
            }
            break;
        }
        out.push_str(&line);
        emitted += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[test]
    fn tokens_to_bytes_is_the_one_conversion_and_zero_is_unlimited() {
        assert_eq!(tokens_to_bytes(0), None);
        assert_eq!(tokens_to_bytes(1), Some(4));
        assert_eq!(tokens_to_bytes(250), Some(1000));
        assert_eq!(byte_budget_or_max(0), usize::MAX);
        assert_eq!(tokens_for_bytes(0), 0);
        assert_eq!(tokens_for_bytes(5), 2);
    }

    #[test]
    fn finish_text_head_keeps_lines_and_notice_within_budget() {
        let rendered = "aaaa\nbbbb\ncccc\ndddd\n".to_owned();
        // Budget 4 tokens = 16 bytes: notice "note!" (6 with newline)
        // leaves 10 bytes -> two 5-byte lines.
        let out = finish_text(rendered, 4, KeepPolicy::Head, "note!");
        assert_eq!(out, "aaaa\nbbbb\nnote!\n");
        assert!(out.len() <= 16);
    }

    #[test]
    fn finish_text_tail_keeps_last_lines_with_notice_first() {
        let rendered = "aaaa\nbbbb\ncccc\ndddd\n".to_owned();
        let out = finish_text(rendered, 4, KeepPolicy::Tail, "note!");
        assert_eq!(out, "note!\ncccc\ndddd\n");
        assert!(out.len() <= 16);
    }

    #[test]
    fn finish_text_budget_smaller_than_notice_gives_notice_alone() {
        let rendered = "aaaa\nbbbb\n".to_owned();
        let out = finish_text(rendered, 1, KeepPolicy::Head, "a much longer notice");
        assert_eq!(out, "a much longer notice\n");
    }

    #[test]
    fn finish_text_cut_falls_on_line_end_for_multibyte_text() {
        // Replaces kit_util's old clip_to_byte_budget multibyte test:
        // the generic byte clip is gone; cuts land on line ends.
        let line = "あ".repeat(50);
        let rendered = format!("{line}\n{line}\n{line}\n");
        let out = finish_text(rendered, 40, KeepPolicy::Head, "note");
        assert!(out.len() <= 160);
        assert!(out.ends_with("note\n"));
        for l in out.lines() {
            assert!(l == "note" || l.chars().all(|c| c == 'あ'));
        }
    }

    #[derive(Debug, Clone, Serialize, PartialEq, Eq)]
    struct FakeError {
        spec: String,
        message: String,
    }

    #[test]
    fn cap_error_list_keeps_head_and_summarizes_the_tail_once() {
        let errors: Vec<FakeError> = (0..10)
            .map(|i| FakeError {
                spec: format!("spec-{i}"),
                message: format!("message number {i}"),
            })
            .collect();
        let (capped, dropped) = cap_error_list(&errors, 120, |omitted| FakeError {
            spec: "...".to_owned(),
            message: format!("... (+{omitted} omitted errors)"),
        });
        assert!(dropped);
        assert!(serde_json::to_string(&capped).unwrap().len() <= 120);
        assert_eq!(capped[0], errors[0]);
        assert!(capped.last().unwrap().message.contains("omitted errors"));
        let (whole, dropped) = cap_error_list(&errors, 10_000, |_| unreachable!());
        assert!(!dropped);
        assert_eq!(whole, errors);
    }

    #[test]
    fn trim_structured_stops_at_the_smallest_result() {
        // "[1]\n" is 4 bytes = the 1-token budget: trimming stops there.
        let mut state = vec![1, 2, 3];
        trim_structured(
            &mut state,
            1,
            |s: &Vec<i32>| format!("{:?}\n", s),
            |s: &mut Vec<i32>| s.pop().is_some(),
        );
        assert_eq!(state, vec![1]);
        // When the render can never fit, the step runs to exhaustion.
        let mut state = vec![1, 2, 3];
        trim_structured(
            &mut state,
            1,
            |_: &Vec<i32>| "always too long\n".to_owned(),
            |s: &mut Vec<i32>| s.pop().is_some(),
        );
        assert!(state.is_empty());
        // Unlimited budget never steps.
        let mut state = vec![1, 2, 3];
        trim_structured(
            &mut state,
            0,
            |s: &Vec<i32>| format!("{:?}\n", s),
            |s: &mut Vec<i32>| s.pop().is_some(),
        );
        assert_eq!(state, vec![1, 2, 3]);
    }

    #[test]
    fn trim_structured_bisect_matches_the_sequential_loop() {
        // A monotone model: each step drops the last line and counts
        // the omission in a trailing notice (notice appears at the
        // first step, then only its digits can grow -- the same shape
        // as outline's head policy). For every size and budget, the
        // bisect must land on exactly the sequential loop's state.
        type Lines = (Vec<String>, usize);
        let render = |(lines, omitted): &Lines| {
            let mut out = lines.join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            if *omitted > 0 {
                out.push_str(&format!("... (+{omitted} omitted)\n"));
            }
            out
        };
        let step = |(lines, omitted): &mut Lines| {
            if lines.pop().is_some() {
                *omitted += 1;
                true
            } else {
                false
            }
        };
        for size in [0usize, 1, 5, 40, 137] {
            for max_tokens in [0usize, 1, 3, 7, 16, 64, 10_000] {
                let initial: Lines = ((0..size).map(|i| format!("item-{i:03}")).collect(), 0);
                let mut sequential = initial.clone();
                trim_structured(&mut sequential, max_tokens, render, step);
                let mut bisected = initial.clone();
                trim_structured_bisect(&mut bisected, max_tokens, render, step);
                assert_eq!(sequential, bisected, "size {size}, max_tokens {max_tokens}");
            }
        }
        // Exhaustion: a render that can never fit still ends at the
        // smallest result, like the sequential loop.
        let mut state = vec![1, 2, 3];
        trim_structured_bisect(
            &mut state,
            1,
            |_: &Vec<i32>| "always too long\n".to_owned(),
            |s: &mut Vec<i32>| s.pop().is_some(),
        );
        assert!(state.is_empty());
    }
}
