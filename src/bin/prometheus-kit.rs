//! prometheus-kit: deterministic token-reduction CLI toolkit over Prometheus core.
//!
//! Subcommands:
//!   outline   Compact structural skeleton of code, JSON/JSONL, YAML, TOML, and Markdown.
//!   slice     Targeted line-range or symbol/path slice with strict token budgets.
//!   compact   Deduplicated CLI/build/test/log compactor with lossless log spillover.
//!   search      Budgeted, grouped, line-clipped, symbol-annotated search.
//!   diff        Compact structural git status, diff, and commit summary.
//!   map         One-call repository tree with line counts and optional top-level symbols.
//!   hook        PreToolUse secret-path, large-read/reread, and shell-rewrite guards.
//!   droid-mode  Switch installed Factory Droid model pins between on/off modes.
//!   metrics     Print local hook-rule totals by host and rule (maintainer aid).

use prometheus_core::compact::{
    capture_command_log, compact_command, compact_text, render_compact_json, render_compact_text,
    CompactMode, CompactOptions,
};
use prometheus_core::diff::{
    execute_diff, render_diff_json, render_diff_text, DiffMode, DiffOptions, DiffOutput,
};
use prometheus_core::droid_mode::{apply_mode, default_home, resolve_config_path};
use prometheus_core::hook::{is_supported_host, panic_fallback, run_hook};
use prometheus_core::kit_util::write_private_spillover;
use prometheus_core::map::{execute_map, render_map_json, render_map_text, MapOptions};
use prometheus_core::metrics::{self, Rule};
use prometheus_core::outline::{
    outline_file, read_text_file_sized, render_outline_json, render_outline_text, Lang,
    OutlineOptions, DEFAULT_OUTLINE_MAX_TOKENS,
};
use prometheus_core::search::{execute_search, render_search_json, render_search_text, SearchOptions};
use prometheus_core::slice::{
    execute_slices, parse_spec, render_slice_json, render_slice_text, SliceOptions,
    DEFAULT_SLICE_MAX_TOKENS,
};
use std::io::{Read, Write};
use std::path::PathBuf;

const MAIN_USAGE: &str = "\
usage: prometheus-kit <command> [options] <args...>

commands:
  outline     Extract compact structural skeleton with line ranges (code, JSON/JSONL, YAML, TOML, Markdown)
  slice       Extract exact line ranges or symbol/path slices with token budgets
  compact     Compact verbose CLI/build/test output or log files (preserves exit code)
  search      Budgeted, grouped, line-clipped search with optional symbol labels
  diff        Compact structural git status/diff/commit viewer excluding lockfile noise
  map         Repository directory map with line counts and optional top-level symbols
  hook        Evaluate PreToolUse secret, read-budget, and rewrite guards for a host
  droid-mode  Switch installed Droid model pins between on and off modes
  metrics     Print local totals by host and rule (maintainer aid)

options:
  -h, --help      Show help
  --version       Show version";

const OUTLINE_USAGE: &str = "\
usage: prometheus-kit outline [options] <path...>

options:
  --depth <n>         Max nesting depth (0 = top-level; default: 2 code/md, 3 json/yaml/toml)
  --max-tokens <n>    Output token budget (0 = unlimited; default: 2000)
  --kind <k>          Filter by item kind (repeatable or comma-separated)
  --filter <s>        Case-insensitive substring filter on name/signature
  --lang <l>          Override language detection
  --imports           Include top-level imports/usings
  --all               Include private fields/consts where supported (C#/TS/Rust/Go)
  --json              Emit compact JSON
  -h, --help          Show help";

const SLICE_USAGE: &str = "\
usage: prometheus-kit slice [options] <spec...>

spec forms:
  <path>:<line>[,<start>-<end>...]   Exact 1-based line ranges
                                     (<path>::<start>-<end> is also accepted)
  <path>::<selector>                 Code symbol (Foo.Bar), JSON Pointer (/a/b/0),
                                     dot path (a.b[0]), JSONL filter (type=msg),
                                     or Markdown heading/slug

note:
  Overlapping ranges on the same file are merged; output is grouped per file
  in first-seen order.

options:
  -C, --context <n>     Lines of surrounding context (default: 0)
  --max-tokens <n>      Output token budget (0 = unlimited; default: 4000)
  --no-line-numbers     Omit `L<n>: ` line prefixes
  --no-truncate-lines   Disable 2,000-char single-line safeguard
  --signatures-only     Print matched signatures and line ranges only
  --lang <l>            Override language detection
  --json                Emit compact JSON
  -h, --help            Show help";

const COMPACT_USAGE: &str = "\
usage: prometheus-kit compact [options] (-- <command...> | [path])

Without `-- <command...>` or `[path]`, reads from stdin.

options:
  --mode <m>          auto|build|test|log|generic (default: auto)
  --max-tokens <n>    Output token budget (0 = unlimited; default: 1500)
  --tail <n>          Tail lines when showing generic/failure context (default: 25)
  --save-log <path>   Always save raw output to <path>
  --no-spillover      Do not write automatic temp spillover logs
  --keep-log          With `-- <command...>`: keep full raw output in a private
                      temp log and print a `log:` pointer (conflicts with
                      --save-log, --no-spillover, --json); a tiny --max-tokens
                      budget prints the pointer only
  --json              Emit compact JSON
  -h, --help          Show help";

const SEARCH_USAGE: &str = "\
usage: prometheus-kit search [options] <pattern> [path...]

options:
  -i, --ignore-case       Case-insensitive match
  -F, --fixed-strings     Treat pattern as literal string
  -w, --word-regexp       Match whole words only
  --glob <g>              Include/exclude glob (repeatable)
  --type <l>              Filter by file type/language
  --max-per-file <n>      Max matched lines per file (0 = unlimited; default: 5)
  --max-files <n>         Max matching files shown (0 = unlimited; default: 30)
  --max-tokens <n>        Output token budget (0 = unlimited; default: 2000)
  --max-line-chars <n>    Clip matched line width (0 = unlimited; default: 180)
  --symbols               Annotate each match with its enclosing symbol
  --files-only            List matching paths and counts only
  --include-noise         Include lockfiles, minified assets, and vendor/build dirs
  --hidden                Include hidden dotfiles
  --no-ignore             Do not respect .gitignore/.ignore files
  --json                  Emit compact JSON
  -h, --help              Show help";

const DIFF_USAGE: &str = "\
usage: prometheus-kit diff [options] [path...]

options:
  --root <dir>            Repository path (default: .)
  --status                Compact branch/staged/unstaged/untracked summary
  --staged, --cached      Diff index vs HEAD
  --base <ref>            Diff working tree vs <ref>
  --commit <rev>          Show compact commit diff for <rev>
  --stat                  Summary + touched symbols only (no hunks)
  --symbol <s>            Keep only hunks touching symbols matching <s>
  -C, --context <n>       Unified diff context lines (default: 2)
  --max-hunk-lines <n>    Max lines per hunk (0 = unlimited; default: 40)
  --max-tokens <n>        Output token budget (0 = unlimited; default: 2500)
  --include-noise         Include lockfile/minified/generated diffs
  --json                  Emit compact JSON
  -h, --help              Show help";

const MAP_USAGE: &str = "\
usage: prometheus-kit map [options] [path]

options:
  --depth <n>             Max directory depth (0 = unlimited; default: 3)
  --symbols               Annotate supported files with top-level symbols
  --max-symbols <n>       Max symbols per file (default: 6)
  --glob <g>              Include/exclude glob (repeatable)
  --type <l>              Filter by file type/language
  --max-tokens <n>        Output token budget (0 = unlimited; default: 2000)
  --include-noise         Include lockfiles, minified assets, and vendor/build dirs
  --hidden                Include hidden dotfiles
  --no-ignore             Do not respect .gitignore/.ignore files
  --json                  Emit compact JSON
  -h, --help              Show help";

fn emit_output(rendered: &str) {
    print!("{rendered}");
    if !rendered.ends_with('\n') {
        println!();
    }
    let _ = std::io::stdout().flush();
}

/// Wire bytes a rendered string occupies on stdout: content plus the newline
/// `emit_output` appends when missing.
fn wire_len(s: &str) -> usize {
    s.len() + usize::from(!s.ends_with('\n'))
}

/// Emit exactly `rendered`, then record a metrics row when the run reduced or
/// clipped its input (`clipped`) or the raw input exceeded the wire output.
/// Metrics failures are silent and never alter the reply.
fn emit_measured(rule: Rule, raw: usize, clipped: bool, rendered: &str) {
    emit_output(rendered);
    if clipped || raw > wire_len(rendered) {
        metrics::record(metrics::command_host(), rule, raw, wire_len(rendered));
    }
}

/// Detect a render-stage budget cut by comparing `rendered` with an
/// unbudgeted in-memory re-render. The closure runs only when metrics are
/// enabled, a nonzero budget applied, and the raw input was not already
/// larger than the emission (that case records via `raw > wire_len`), so
/// disabled or already-reduced runs pay nothing.
fn render_was_clipped(
    rendered: &str,
    max_tokens: usize,
    raw_bytes: usize,
    full: impl FnOnce() -> String,
) -> bool {
    metrics::enabled()
        && max_tokens != 0
        && raw_bytes <= wire_len(rendered)
        && full() != rendered
}

fn next_val(raw: &[String], index: &mut usize, flag: &str, usage: &str) -> Result<String, i32> {
    *index += 1;
    match raw.get(*index) {
        Some(v) => Ok(v.clone()),
        None => {
            eprintln!("prometheus-kit: missing value for {flag}\n{usage}");
            Err(2)
        }
    }
}

fn next_usize(raw: &[String], index: &mut usize, flag: &str, usage: &str) -> Result<usize, i32> {
    let v = next_val(raw, index, flag, usage)?;
    v.parse::<usize>().map_err(|_| {
        eprintln!("prometheus-kit: {flag} must be a non-negative integer, got `{v}`");
        2
    })
}

fn next_lang(raw: &[String], index: &mut usize, usage: &str) -> Result<Lang, i32> {
    let v = next_val(raw, index, "--lang", usage)?;
    Lang::from_name(&v).ok_or_else(|| {
        eprintln!("prometheus-kit: unsupported --lang `{v}`");
        2
    })
}

fn run_outline(raw: &[String]) -> i32 {
    let mut opts = OutlineOptions {
        max_tokens: DEFAULT_OUTLINE_MAX_TOKENS,
        ..OutlineOptions::default()
    };
    let mut lang_override = None;
    let mut json_mode = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut positional_only = false;
    let mut i = 0usize;

    while i < raw.len() {
        let arg = raw[i].as_str();
        if !positional_only {
            match arg {
                "-h" | "--help" => {
                    println!("{OUTLINE_USAGE}");
                    return 0;
                }
                "--" => positional_only = true,
                "--depth" => match next_usize(raw, &mut i, "--depth", OUTLINE_USAGE) {
                    Ok(n) => opts.max_depth = Some(n),
                    Err(code) => return code,
                },
                "--max-tokens" => match next_usize(raw, &mut i, "--max-tokens", OUTLINE_USAGE) {
                    Ok(n) => opts.max_tokens = n,
                    Err(code) => return code,
                },
                "--kind" => match next_val(raw, &mut i, "--kind", OUTLINE_USAGE) {
                    Ok(v) => opts.kinds.extend(
                        v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned),
                    ),
                    Err(code) => return code,
                },
                "--filter" => match next_val(raw, &mut i, "--filter", OUTLINE_USAGE) {
                    Ok(v) => opts.filter = Some(v),
                    Err(code) => return code,
                },
                "--lang" => match next_lang(raw, &mut i, OUTLINE_USAGE) {
                    Ok(l) => lang_override = Some(l),
                    Err(code) => return code,
                },
                "--imports" => opts.include_imports = true,
                "--all" => opts.include_all = true,
                "--json" => json_mode = true,
                _ if arg.starts_with('-') && arg != "-" => {
                    eprintln!("prometheus-kit outline: unknown option `{arg}`\n{OUTLINE_USAGE}");
                    return 2;
                }
                _ => paths.push(PathBuf::from(arg)),
            }
        } else {
            paths.push(PathBuf::from(arg));
        }
        i += 1;
    }

    if paths.is_empty() {
        eprintln!("prometheus-kit outline: expected at least one <path>\n{OUTLINE_USAGE}");
        return 2;
    }

    let mut docs = Vec::with_capacity(paths.len());
    for p in &paths {
        match outline_file(p, lang_override, &opts) {
            Ok(doc) => docs.push(doc),
            Err(err) => {
                eprintln!("prometheus-kit outline: {err}");
                return 1;
            }
        }
    }

    let rendered = if json_mode {
        render_outline_json(&docs, &opts)
    } else {
        render_outline_text(&docs, &opts)
    };
    let raw_bytes: usize = docs.iter().map(|d| d.raw_bytes).sum();
    let clipped = render_was_clipped(&rendered, opts.max_tokens, raw_bytes, || {
        let mut unbudgeted = opts.clone();
        unbudgeted.max_tokens = 0;
        if json_mode {
            render_outline_json(&docs, &unbudgeted)
        } else {
            render_outline_text(&docs, &unbudgeted)
        }
    });
    emit_measured(Rule::Outline, raw_bytes, clipped, &rendered);
    0
}

fn run_slice(raw: &[String]) -> i32 {
    let mut opts = SliceOptions {
        max_tokens: DEFAULT_SLICE_MAX_TOKENS,
        ..SliceOptions::default()
    };
    let mut json_mode = false;
    let mut raw_specs: Vec<String> = Vec::new();
    let mut positional_only = false;
    let mut i = 0usize;

    while i < raw.len() {
        let arg = raw[i].as_str();
        if !positional_only {
            match arg {
                "-h" | "--help" => {
                    println!("{SLICE_USAGE}");
                    return 0;
                }
                "--" => positional_only = true,
                "-C" | "--context" => match next_usize(raw, &mut i, arg, SLICE_USAGE) {
                    Ok(n) => opts.context_lines = n,
                    Err(code) => return code,
                },
                "--max-tokens" => match next_usize(raw, &mut i, "--max-tokens", SLICE_USAGE) {
                    Ok(n) => opts.max_tokens = n,
                    Err(code) => return code,
                },
                "--no-line-numbers" => opts.line_numbers = false,
                "--no-truncate-lines" => opts.truncate_long_lines = false,
                "--signatures-only" => opts.signatures_only = true,
                "--lang" => match next_lang(raw, &mut i, SLICE_USAGE) {
                    Ok(l) => opts.lang_override = Some(l),
                    Err(code) => return code,
                },
                "--json" => json_mode = true,
                _ if arg.starts_with('-') && arg != "-" => {
                    eprintln!("prometheus-kit slice: unknown option `{arg}`\n{SLICE_USAGE}");
                    return 2;
                }
                _ => raw_specs.push(arg.to_owned()),
            }
        } else {
            raw_specs.push(arg.to_owned());
        }
        i += 1;
    }

    if raw_specs.is_empty() {
        eprintln!("prometheus-kit slice: expected at least one <spec>\n{SLICE_USAGE}");
        return 2;
    }

    let mut specs = Vec::with_capacity(raw_specs.len());
    for raw_spec in &raw_specs {
        match parse_spec(raw_spec) {
            Ok(spec) => specs.push(spec),
            Err(err) => {
                eprintln!("prometheus-kit slice: {err}");
                return 2;
            }
        }
    }

    match execute_slices(&specs, &opts) {
        Ok(result) => {
            let rendered = if json_mode {
                render_slice_json(&result, opts.max_tokens)
            } else {
                render_slice_text(&result, &opts)
            };
            let mut clipped = result.truncated
                || result.signature_clipped
                || result
                    .slices
                    .iter()
                    .any(|b| b.lines.iter().any(|l| l.truncated));
            if !clipped && json_mode {
                clipped = render_was_clipped(&rendered, opts.max_tokens, result.raw_bytes, || {
                    render_slice_json(&result, 0)
                });
            }
            emit_measured(Rule::Slice, result.raw_bytes, clipped, &rendered);
            0
        }
        Err(err) => {
            eprintln!("prometheus-kit slice: {err}");
            1
        }
    }
}

fn run_compact(raw: &[String]) -> i32 {
    let mut opts = CompactOptions::default();
    let mut json_mode = false;
    let mut keep_log = false;
    let mut command: Vec<String> = Vec::new();
    let mut file_path: Option<PathBuf> = None;
    let mut i = 0usize;

    while i < raw.len() {
        let arg = raw[i].as_str();
        match arg {
            "-h" | "--help" => {
                println!("{COMPACT_USAGE}");
                return 0;
            }
            "--" => {
                command = raw[i + 1..].to_vec();
                if command.is_empty() {
                    eprintln!("prometheus-kit compact: expected command after `--`\n{COMPACT_USAGE}");
                    return 2;
                }
                break;
            }
            "--mode" => match next_val(raw, &mut i, "--mode", COMPACT_USAGE) {
                Ok(v) => match CompactMode::parse(&v) {
                    Some(m) => opts.mode = m,
                    None => {
                        eprintln!("prometheus-kit compact: invalid --mode `{v}`\n{COMPACT_USAGE}");
                        return 2;
                    }
                },
                Err(code) => return code,
            },
            "--max-tokens" => match next_usize(raw, &mut i, "--max-tokens", COMPACT_USAGE) {
                Ok(n) => opts.max_tokens = n,
                Err(code) => return code,
            },
            "--tail" => match next_usize(raw, &mut i, "--tail", COMPACT_USAGE) {
                Ok(n) => opts.tail_lines = n,
                Err(code) => return code,
            },
            "--save-log" => match next_val(raw, &mut i, "--save-log", COMPACT_USAGE) {
                Ok(v) => opts.save_log = Some(PathBuf::from(v)),
                Err(code) => return code,
            },
            "--no-spillover" => opts.allow_spillover = false,
            "--keep-log" => keep_log = true,
            "--json" => json_mode = true,
            _ if arg.starts_with('-') && arg != "-" => {
                eprintln!("prometheus-kit compact: unknown option `{arg}`\n{COMPACT_USAGE}");
                return 2;
            }
            _ => {
                if file_path.is_some() {
                    eprintln!(
                        "prometheus-kit compact: unexpected argument `{arg}` (use `--` before commands)\n{COMPACT_USAGE}"
                    );
                    return 2;
                }
                file_path = Some(PathBuf::from(arg));
            }
        }
        i += 1;
    }

    if !command.is_empty() && file_path.is_some() {
        eprintln!("prometheus-kit compact: pass either `[path]` or `-- <command...>`, not both");
        return 2;
    }

    if keep_log {
        if command.is_empty() || opts.save_log.is_some() || !opts.allow_spillover || json_mode {
            eprintln!(
                "prometheus-kit compact: --keep-log requires `-- <command...>` and conflicts with --save-log, --no-spillover, --json\n{COMPACT_USAGE}"
            );
            return 2;
        }
        return run_kept_command(&command, opts);
    }

    let (result, exit_code) = if !command.is_empty() {
        match compact_command(&command, &opts) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("prometheus-kit compact: {err}");
                return 1;
            }
        }
    } else if let Some(path) = file_path {
        match read_text_file_sized(&path) {
            Ok((text, _, raw_bytes)) => {
                let mut res = compact_text(&text, None, &opts);
                res.raw_bytes = raw_bytes;
                (res, 0)
            }
            Err(err) => {
                eprintln!("prometheus-kit compact: {err}");
                return 1;
            }
        }
    } else {
        let mut buf = Vec::new();
        if let Err(err) = std::io::stdin().read_to_end(&mut buf) {
            eprintln!("prometheus-kit compact: stdin: {err}");
            return 1;
        }
        let raw_bytes = buf.len();
        let text = String::from_utf8_lossy(&buf);
        let mut res = compact_text(&text, None, &opts);
        res.raw_bytes = raw_bytes;
        (res, 0)
    };

    let rendered = if json_mode {
        render_compact_json(&result, opts.max_tokens)
    } else {
        render_compact_text(&result, opts.max_tokens)
    };
    // Every compaction counts as a reduction, including render overhead.
    emit_measured(Rule::Compact, result.raw_bytes, true, &rendered);
    exit_code
}

/// `compact --keep-log -- <cmd>`: capture the command's merged output once,
/// persist the raw bytes in an owner-private temp log, and print the compact
/// summary led by an always-recoverable `log:` pointer. When the private log
/// cannot be written — or the capture broke mid-stream — the raw bytes go to
/// stdout byte-for-byte with a diagnostic where needed: no added newline, no
/// JSON, no normalization, no compaction row, and the command's own status.
fn run_kept_command(command: &[String], mut opts: CompactOptions) -> i32 {
    let (raw, code, read_error) = match capture_command_log(command) {
        Ok(captured) => captured,
        Err(err) => {
            let cmd0 = command.first().map(String::as_str).unwrap_or("command");
            eprintln!("prometheus-kit compact: {cmd0}: {err}");
            return spawn_exit_code(&err);
        }
    };
    if let Some(err) = read_error {
        // The pipe broke mid-capture: the bytes and status are real but the
        // log would be incomplete, so nothing is persisted or compacted.
        eprintln!("prometheus-kit compact: incomplete capture: {err}");
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(&raw);
        let _ = out.flush();
        return code;
    }
    let Some(log_path) = write_private_spillover(&raw) else {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(&raw);
        let _ = out.flush();
        return code;
    };
    // The raw log already exists; compact_text must not spill a second copy.
    opts.allow_spillover = false;
    // Lead with the pointer so budget clipping can never remove it, and
    // reserve its share of the token budget for the summary that follows. A
    // tiny positive budget keeps the pointer and drops the summary entirely;
    // zero stays unlimited.
    let log_line = format!("log: {}\n", log_path.display());
    let reserved = log_line.len().div_ceil(4);
    if opts.max_tokens != 0 && opts.max_tokens <= reserved {
        emit_measured(Rule::Compact, raw.len(), true, &log_line);
        return code;
    }
    opts.max_tokens = opts.max_tokens.saturating_sub(reserved);
    let text = String::from_utf8_lossy(&raw);
    let mut result = compact_text(&text, Some(code), &opts);
    result.raw_bytes = raw.len();
    let summary = render_compact_text(&result, opts.max_tokens);
    let rendered = format!("{log_line}{summary}");
    emit_measured(Rule::Compact, raw.len(), true, &rendered);
    code
}

/// Shell-style status for a command that never started: 127 when the
/// executable is missing, 126 when it cannot be executed — Unix only; other
/// platforms report a plain failure.
fn spawn_exit_code(err: &std::io::Error) -> i32 {
    #[cfg(unix)]
    let code = match err.kind() {
        std::io::ErrorKind::NotFound => 127,
        std::io::ErrorKind::PermissionDenied => 126,
        _ => 1,
    };
    #[cfg(not(unix))]
    let code = {
        let _ = err;
        1
    };
    code
}

fn run_search(raw: &[String]) -> i32 {
    let mut opts = SearchOptions {
        paths: Vec::new(),
        ..SearchOptions::default()
    };
    let mut json_mode = false;
    let mut positional_only = false;
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0usize;

    while i < raw.len() {
        let arg = raw[i].as_str();
        if !positional_only {
            match arg {
                "-h" | "--help" => {
                    println!("{SEARCH_USAGE}");
                    return 0;
                }
                "--" => positional_only = true,
                "-i" | "--ignore-case" => opts.ignore_case = true,
                "-F" | "--fixed-strings" => opts.fixed_strings = true,
                "-w" | "--word-regexp" => opts.word_regexp = true,
                "--glob" => match next_val(raw, &mut i, "--glob", SEARCH_USAGE) {
                    Ok(v) => opts.globs.push(v),
                    Err(code) => return code,
                },
                "--type" => match next_val(raw, &mut i, "--type", SEARCH_USAGE) {
                    Ok(v) => match Lang::from_name(&v) {
                        Some(l) => opts.lang_type = Some(l),
                        None => {
                            eprintln!("prometheus-kit search: unsupported --type `{v}`");
                            return 2;
                        }
                    },
                    Err(code) => return code,
                },
                "--max-per-file" => match next_usize(raw, &mut i, "--max-per-file", SEARCH_USAGE) {
                    Ok(n) => opts.max_per_file = n,
                    Err(code) => return code,
                },
                "--max-files" => match next_usize(raw, &mut i, "--max-files", SEARCH_USAGE) {
                    Ok(n) => opts.max_files = n,
                    Err(code) => return code,
                },
                "--max-tokens" => match next_usize(raw, &mut i, "--max-tokens", SEARCH_USAGE) {
                    Ok(n) => opts.max_tokens = n,
                    Err(code) => return code,
                },
                "--max-line-chars" => {
                    match next_usize(raw, &mut i, "--max-line-chars", SEARCH_USAGE) {
                        Ok(n) => opts.max_line_chars = n,
                        Err(code) => return code,
                    }
                }
                "--symbols" => opts.annotate_symbols = true,
                "--files-only" => opts.files_only = true,
                "--include-noise" => opts.include_noise = true,
                "--hidden" => opts.hidden = true,
                "--no-ignore" => opts.no_ignore = true,
                "--json" => json_mode = true,
                _ if arg.starts_with('-') && arg != "-" => {
                    eprintln!("prometheus-kit search: unknown option `{arg}`\n{SEARCH_USAGE}");
                    return 2;
                }
                _ => positionals.push(arg.to_owned()),
            }
        } else {
            positionals.push(arg.to_owned());
        }
        i += 1;
    }

    if positionals.is_empty() {
        eprintln!("prometheus-kit search: expected <pattern>\n{SEARCH_USAGE}");
        return 2;
    }
    opts.pattern = positionals.remove(0);
    opts.paths = if positionals.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        positionals.into_iter().map(PathBuf::from).collect()
    };

    match execute_search(&opts) {
        Ok(res) => {
            let rendered = if json_mode {
                render_search_json(&res, &opts)
            } else {
                render_search_text(&res, &opts)
            };
            let mut clipped = res.truncated
                || res
                    .files
                    .iter()
                    .any(|f| f.matches.iter().any(|m| m.clipped));
            if !clipped {
                clipped = render_was_clipped(&rendered, opts.max_tokens, res.raw_bytes, || {
                    let mut unbudgeted = opts.clone();
                    unbudgeted.max_tokens = 0;
                    if json_mode {
                        render_search_json(&res, &unbudgeted)
                    } else {
                        render_search_text(&res, &unbudgeted)
                    }
                });
            }
            emit_measured(Rule::Search, res.raw_bytes, clipped, &rendered);
            0
        }
        Err(err) => {
            eprintln!("prometheus-kit search: {}", err.message());
            err.exit_code()
        }
    }
}

fn run_diff(raw: &[String]) -> i32 {
    let mut opts = DiffOptions::default();
    let mut json_mode = false;
    let mut positional_only = false;
    let mut mode_count = 0usize;
    let mut i = 0usize;

    while i < raw.len() {
        let arg = raw[i].as_str();
        if !positional_only {
            match arg {
                "-h" | "--help" => {
                    println!("{DIFF_USAGE}");
                    return 0;
                }
                "--" => positional_only = true,
                "--root" => match next_val(raw, &mut i, "--root", DIFF_USAGE) {
                    Ok(v) => opts.root = PathBuf::from(v),
                    Err(code) => return code,
                },
                "--status" => {
                    opts.mode = DiffMode::Status;
                    mode_count += 1;
                }
                "--staged" | "--cached" => {
                    opts.mode = DiffMode::Staged;
                    mode_count += 1;
                }
                "--base" => match next_val(raw, &mut i, "--base", DIFF_USAGE) {
                    Ok(v) => {
                        opts.mode = DiffMode::Base(v);
                        mode_count += 1;
                    }
                    Err(code) => return code,
                },
                "--commit" => match next_val(raw, &mut i, "--commit", DIFF_USAGE) {
                    Ok(v) => {
                        opts.mode = DiffMode::Commit(v);
                        mode_count += 1;
                    }
                    Err(code) => return code,
                },
                "--stat" => opts.stat_only = true,
                "--symbol" => match next_val(raw, &mut i, "--symbol", DIFF_USAGE) {
                    Ok(v) => opts.symbol_filter = Some(v),
                    Err(code) => return code,
                },
                "-C" | "--context" => match next_usize(raw, &mut i, arg, DIFF_USAGE) {
                    Ok(n) => opts.context_lines = n,
                    Err(code) => return code,
                },
                "--max-hunk-lines" => {
                    match next_usize(raw, &mut i, "--max-hunk-lines", DIFF_USAGE) {
                        Ok(n) => opts.max_hunk_lines = n,
                        Err(code) => return code,
                    }
                }
                "--max-tokens" => match next_usize(raw, &mut i, "--max-tokens", DIFF_USAGE) {
                    Ok(n) => opts.max_tokens = n,
                    Err(code) => return code,
                },
                "--include-noise" => opts.include_noise = true,
                "--json" => json_mode = true,
                _ if arg.starts_with('-') && arg != "-" => {
                    eprintln!("prometheus-kit diff: unknown option `{arg}`\n{DIFF_USAGE}");
                    return 2;
                }
                _ => opts.paths.push(PathBuf::from(arg)),
            }
        } else {
            opts.paths.push(PathBuf::from(arg));
        }
        i += 1;
    }

    if mode_count > 1 {
        eprintln!(
            "prometheus-kit diff: --status, --staged, --base, and --commit are mutually exclusive"
        );
        return 2;
    }

    match execute_diff(&opts) {
        Ok(out) => {
            let rendered = if json_mode {
                render_diff_json(&out, opts.max_tokens)
            } else {
                render_diff_text(&out, opts.max_tokens)
            };
            let raw_bytes = match &out {
                DiffOutput::Status(s) => s.raw_bytes,
                DiffOutput::Diff { raw_bytes, .. } => *raw_bytes,
            };
            let mut clipped = match &out {
                DiffOutput::Status(s) => {
                    s.truncated || s.omitted_entries > 0 || !s.excluded_noise.is_empty()
                }
                DiffOutput::Diff {
                    files,
                    excluded_noise,
                    truncated,
                    omitted_files,
                    filtered_output,
                    ..
                } => {
                    *truncated
                        || *omitted_files > 0
                        || !excluded_noise.is_empty()
                        || *filtered_output
                        || files.iter().any(|f| {
                            f.summary_note.is_some()
                                || f.hunks.iter().any(|h| h.omitted_lines > 0)
                        })
                }
            };
            if !clipped {
                clipped = render_was_clipped(&rendered, opts.max_tokens, raw_bytes, || {
                    if json_mode {
                        render_diff_json(&out, 0)
                    } else {
                        render_diff_text(&out, 0)
                    }
                });
            }
            emit_measured(Rule::Diff, raw_bytes, clipped, &rendered);
            0
        }
        Err(err) => {
            eprintln!("prometheus-kit diff: {err}");
            1
        }
    }
}

fn run_map(raw: &[String]) -> i32 {
    let mut opts = MapOptions::default();
    let mut json_mode = false;
    let mut positional_only = false;
    let mut root_set = false;
    let mut i = 0usize;

    while i < raw.len() {
        let arg = raw[i].as_str();
        if !positional_only {
            match arg {
                "-h" | "--help" => {
                    println!("{MAP_USAGE}");
                    return 0;
                }
                "--" => positional_only = true,
                "--depth" => match next_usize(raw, &mut i, "--depth", MAP_USAGE) {
                    Ok(n) => opts.max_depth = n,
                    Err(code) => return code,
                },
                "--symbols" => opts.include_symbols = true,
                "--max-symbols" => match next_usize(raw, &mut i, "--max-symbols", MAP_USAGE) {
                    Ok(n) => opts.max_symbols_per_file = n,
                    Err(code) => return code,
                },
                "--glob" => match next_val(raw, &mut i, "--glob", MAP_USAGE) {
                    Ok(v) => opts.globs.push(v),
                    Err(code) => return code,
                },
                "--type" => match next_val(raw, &mut i, "--type", MAP_USAGE) {
                    Ok(v) => match Lang::from_name(&v) {
                        Some(l) => opts.lang_type = Some(l),
                        None => {
                            eprintln!("prometheus-kit map: unsupported --type `{v}`");
                            return 2;
                        }
                    },
                    Err(code) => return code,
                },
                "--max-tokens" => match next_usize(raw, &mut i, "--max-tokens", MAP_USAGE) {
                    Ok(n) => opts.max_tokens = n,
                    Err(code) => return code,
                },
                "--include-noise" => opts.include_noise = true,
                "--hidden" => opts.hidden = true,
                "--no-ignore" => opts.no_ignore = true,
                "--json" => json_mode = true,
                _ if arg.starts_with('-') && arg != "-" => {
                    eprintln!("prometheus-kit map: unknown option `{arg}`\n{MAP_USAGE}");
                    return 2;
                }
                _ => {
                    if root_set {
                        eprintln!("prometheus-kit map: expected at most one [path]\n{MAP_USAGE}");
                        return 2;
                    }
                    opts.root = PathBuf::from(arg);
                    root_set = true;
                }
            }
        } else {
            if root_set {
                eprintln!("prometheus-kit map: expected at most one [path]\n{MAP_USAGE}");
                return 2;
            }
            opts.root = PathBuf::from(arg);
            root_set = true;
        }
        i += 1;
    }

    match execute_map(&opts) {
        Ok(res) => {
            let rendered = if json_mode {
                render_map_json(&res, opts.max_tokens)
            } else {
                render_map_text(&res, opts.max_tokens)
            };
            // Raw is the same map's unbudgeted render; with no budget the
            // rendered output already is that render, so raw == emitted.
            let mut raw = 0usize;
            let mut clipped = false;
            if metrics::enabled() {
                if opts.max_tokens == 0 {
                    raw = wire_len(&rendered);
                } else {
                    let full = if json_mode {
                        render_map_json(&res, 0)
                    } else {
                        render_map_text(&res, 0)
                    };
                    clipped = full != rendered;
                    raw = wire_len(&full);
                }
            }
            emit_measured(Rule::Map, raw, clipped, &rendered);
            0
        }
        Err(err) => {
            eprintln!("prometheus-kit map: {}", err.message());
            err.exit_code()
        }
    }
}

const HOOK_USAGE: &str = "\
usage: prometheus-kit hook <claude|cursor|devin|droid|muse>

Reads one hook event JSON object from stdin and prints the host reply JSON
(secret guard, large-read/reread advisory, and shell auto-rewrite).";

const DROID_MODE_USAGE: &str = "\
usage: prometheus-kit droid-mode <on|off> [--config <path>] [--home <dir>]

options:
  --config <path>   Path to droid-modes.json
  --home <dir>      Home directory holding .factory/
  -h, --help        Show help";

const METRICS_USAGE: &str = "\
usage: prometheus-kit metrics
Print local totals by host and rule. Set PROMETHEUS_KIT_NO_METRICS to disable writes.";

fn run_hook_cmd(raw: &[String]) -> i32 {
    let mut host: Option<String> = None;
    for arg in raw {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{HOOK_USAGE}");
                return 0;
            }
            _ if arg.starts_with('-') => {
                eprintln!("prometheus-kit hook: unknown option `{arg}`\n{HOOK_USAGE}");
                return 2;
            }
            _ => {
                if host.is_some() {
                    eprintln!("prometheus-kit hook: expected exactly one <host>\n{HOOK_USAGE}");
                    return 2;
                }
                host = Some(arg.clone());
            }
        }
    }
    let Some(host) = host else {
        eprintln!("prometheus-kit hook: missing <host>\n{HOOK_USAGE}");
        return 2;
    };
    if !is_supported_host(&host) {
        eprintln!("prometheus-kit hook: unsupported host `{host}`\n{HOOK_USAGE}");
        return 2;
    }
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
    let reply = match std::panic::catch_unwind(|| run_hook(&host, &buf)) {
        Ok(value) => value,
        Err(_) => panic_fallback(&host),
    };
    let rendered = serde_json::to_string(&reply).unwrap_or_else(|_| "{}".to_string());
    println!("{rendered}");
    let _ = std::io::stdout().flush();
    0
}

fn run_droid_mode_cmd(raw: &[String]) -> i32 {
    let mut mode: Option<String> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut home_dir: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < raw.len() {
        let arg = raw[i].as_str();
        match arg {
            "-h" | "--help" => {
                println!("{DROID_MODE_USAGE}");
                return 0;
            }
            "--config" => match next_val(raw, &mut i, "--config", DROID_MODE_USAGE) {
                Ok(v) => config_path = Some(PathBuf::from(v)),
                Err(code) => return code,
            },
            "--home" => match next_val(raw, &mut i, "--home", DROID_MODE_USAGE) {
                Ok(v) => home_dir = Some(PathBuf::from(v)),
                Err(code) => return code,
            },
            _ if arg.starts_with('-') => {
                eprintln!("prometheus-kit droid-mode: unknown option `{arg}`\n{DROID_MODE_USAGE}");
                return 2;
            }
            _ => {
                if mode.is_some() {
                    eprintln!("prometheus-kit droid-mode: expected a single mode <on|off>\n{DROID_MODE_USAGE}");
                    return 2;
                }
                mode = Some(arg.to_string());
            }
        }
        i += 1;
    }
    let Some(mode) = mode else {
        eprintln!("{DROID_MODE_USAGE}");
        return 2;
    };
    if !matches!(mode.as_str(), "on" | "off") {
        eprintln!("{DROID_MODE_USAGE}");
        return 2;
    }
    let home = match home_dir {
        Some(h) => h,
        None => match default_home() {
            Ok(h) => h,
            Err(err) => {
                eprintln!("droid core mode unchanged: {err}");
                return 1;
            }
        },
    };
    let config = match resolve_config_path(config_path.as_deref(), &home) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("droid core mode unchanged: {err}");
            return 1;
        }
    };
    match apply_mode(&mode, &home, &config) {
        Ok(msg) => {
            println!("{msg}");
            0
        }
        Err(err) => {
            eprintln!("droid core mode unchanged: {err}");
            1
        }
    }
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some(first) = raw.first().map(String::as_str) else {
        eprintln!("{MAIN_USAGE}");
        std::process::exit(2);
    };
    let code = match first {
        "-h" | "--help" => {
            println!("{MAIN_USAGE}");
            0
        }
        "--version" => {
            println!("prometheus-kit {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "outline" => run_outline(&raw[1..]),
        "slice" => run_slice(&raw[1..]),
        "compact" => run_compact(&raw[1..]),
        "search" => run_search(&raw[1..]),
        "diff" => run_diff(&raw[1..]),
        "map" => run_map(&raw[1..]),
        "hook" => run_hook_cmd(&raw[1..]),
        "droid-mode" => run_droid_mode_cmd(&raw[1..]),
        "metrics" if raw.len() == 1 => {
            println!("{}", prometheus_core::metrics::totals());
            0
        }
        "metrics" if matches!(raw.as_slice(), [_, flag] if flag == "-h" || flag == "--help") => {
            println!("{METRICS_USAGE}");
            0
        }
        "metrics" => {
            eprintln!("{METRICS_USAGE}");
            2
        }
        other => {
            eprintln!("prometheus-kit: unknown command `{other}`\n{MAIN_USAGE}");
            2
        }
    };
    std::process::exit(code);
}
