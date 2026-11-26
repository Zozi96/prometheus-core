//! Shared typed failure-summary renderer for red Check runs and
//! `compact --mode test`.

use crate::logs::{FailureDetail, ParsedLog};

/// Deterministic failure-block bounds. The byte bound covers the rendered
/// block for ordinary log paths; the omission pointer itself is never
/// dropped, since without it the cap would hide where the rest went.
pub const FAILURE_SUMMARY_MAX_LINES: usize = 24;
pub const FAILURE_SUMMARY_MAX_BYTES: usize = 2048;
const FAILURE_LINE_BYTES: usize = 180;
const SELECTOR_LINE_BYTES: usize = 220;

fn fallback_details(parsed: &ParsedLog) -> Vec<FailureDetail> {
    if !parsed.failure_details.is_empty() {
        return parsed.failure_details.clone();
    }
    parsed
        .failed_tests
        .iter()
        .map(|selector| FailureDetail {
            test: selector.clone(),
            selector: selector.clone(),
            message: String::new(),
        })
        .collect()
}

/// Clip from the end by bytes, never splitting UTF-8. The suffix says how
/// many bytes were dropped; the loop accounts for its own digit growth, so
/// ordinary budgets (well above the suffix size) always fit exactly.
fn clip_bytes_end(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut keep = max_bytes.saturating_sub(24).max(8).min(text.len());
    while keep > 0 && !text.is_char_boundary(keep) {
        keep -= 1;
    }
    loop {
        let omitted = text.len() - keep;
        let out = format!("{}... (+{omitted} bytes)", &text[..keep]);
        if out.len() <= max_bytes || keep == 0 {
            return out;
        }
        keep -= 1;
        while keep > 0 && !text.is_char_boundary(keep) {
            keep -= 1;
        }
    }
}

pub(crate) fn failure_omission_notice(omitted: usize, log_path: Option<&str>) -> String {
    match log_path {
        Some(path) => format!("... ({omitted} failures omitted; see full log: {path})"),
        None => format!("... ({omitted} failures omitted; full log unavailable)"),
    }
}

/// Render the bounded failure block as lines. Every failure carries its
/// test identity and re-runnable selector; the concise runner error is
/// included when the typed parser found one. When count, line, or byte
/// capacity is exceeded, the final line says how many failures were
/// omitted and points at the saved log.
pub fn render_failure_summary(parsed: &ParsedLog, log_path: Option<&str>) -> Vec<String> {
    let details = fallback_details(parsed);
    if details.is_empty() {
        return Vec::new();
    }

    let counted = parsed
        .counts
        .and_then(|counts| usize::try_from(counts.failed).ok())
        .unwrap_or(0);
    let total = details.len().max(counted);
    let mut lines = vec![format!("failures ({total}):")];
    let mut bytes = lines[0].len() + 1;
    let reserved_notice = failure_omission_notice(total, log_path).len() + 1;
    let mut shown = 0usize;

    for detail in &details {
        let message = if detail.message.is_empty() {
            "failure"
        } else {
            detail.message.as_str()
        };
        let failure_line =
            clip_bytes_end(&format!("- {}: {message}", detail.test), FAILURE_LINE_BYTES);
        let selector_line = clip_bytes_end(
            &format!("  rerun: {}", detail.selector),
            SELECTOR_LINE_BYTES,
        );
        let needed = failure_line.len() + 1 + selector_line.len() + 1;
        let would_lines = lines.len() + 2 + 1; // keep one line for a possible omission notice
        let would_bytes = bytes + needed + reserved_notice;
        if shown > 0
            && (would_lines > FAILURE_SUMMARY_MAX_LINES || would_bytes > FAILURE_SUMMARY_MAX_BYTES)
        {
            break;
        }
        if shown == 0
            && (lines.len() + 2 > FAILURE_SUMMARY_MAX_LINES
                || bytes + needed > FAILURE_SUMMARY_MAX_BYTES)
        {
            break;
        }
        lines.push(failure_line);
        lines.push(selector_line);
        bytes += needed;
        shown += 1;
    }

    if shown < total {
        lines.push(failure_omission_notice(total - shown, log_path));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(count: usize) -> ParsedLog {
        let failure_details = (0..count)
            .map(|index| FailureDetail {
                test: format!("tests::case_{index}"),
                selector: format!("cargo test -- --exact tests::case_{index}"),
                message: format!("assertion failed {index}"),
            })
            .collect::<Vec<_>>();
        ParsedLog {
            counts: None,
            error: None,
            failing_lines: Vec::new(),
            failed_tests: failure_details
                .iter()
                .map(|detail| detail.selector.clone())
                .collect(),
            failure_details,
        }
    }

    #[test]
    fn renderer_is_bounded_deterministic_and_points_to_the_log() {
        let parsed = parsed(30);
        let first = render_failure_summary(&parsed, Some("/tmp/check.log"));
        let second = render_failure_summary(&parsed, Some("/tmp/check.log"));
        assert_eq!(first, second);
        assert!(first.len() <= FAILURE_SUMMARY_MAX_LINES);
        assert!(first.join("\n").len() + 1 <= FAILURE_SUMMARY_MAX_BYTES);
        assert_eq!("failures (30):", first[0]);
        assert!(first[1].contains("tests::case_0: assertion failed 0"));
        assert!(first[2].contains("rerun: cargo test -- --exact tests::case_0"));
        assert_eq!(
            first.last().unwrap(),
            &format!(
                "... ({} failures omitted; see full log: /tmp/check.log)",
                30 - (first.len() - 2) / 2
            )
        );
    }

    #[test]
    fn long_failure_text_is_byte_capped() {
        let mut long = parsed(10);
        for detail in &mut long.failure_details {
            detail.message.push_str(&" very-long-detail".repeat(80));
            detail.selector.push_str(&"::very_long_selector".repeat(30));
        }
        let lines = render_failure_summary(&long, Some("/tmp/check.log"));
        assert!(lines.len() <= FAILURE_SUMMARY_MAX_LINES);
        assert!(lines.join("\n").len() + 1 <= FAILURE_SUMMARY_MAX_BYTES);
        assert!(lines
            .last()
            .unwrap()
            .contains("failures omitted; see full log: /tmp/check.log"));

        let mut unicode = parsed(8);
        for detail in &mut unicode.failure_details {
            detail.message = "é".repeat(500);
        }
        let lines = render_failure_summary(&unicode, Some("/tmp/check.log"));
        assert!(lines.join("\n").len() + 1 <= FAILURE_SUMMARY_MAX_BYTES);
    }

    #[test]
    fn small_renderer_keeps_error_and_selector_without_notice() {
        let lines = render_failure_summary(&parsed(1), Some("/tmp/check.log"));
        assert_eq!(
            lines,
            vec![
                "failures (1):",
                "- tests::case_0: assertion failed 0",
                "  rerun: cargo test -- --exact tests::case_0",
            ]
        );
    }
}
