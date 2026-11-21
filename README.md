# prometheus-core

The native deterministic engine for `prometheus-check` and `prometheus-kit`.

## Modules

- `check` — runner, targeted selection, receipts, and host-wide Check slot.
- `classify` — documentation and test path classification.
- `compact` — deduplicated CLI/build/test/log compactor with lossless spillover logs.
- `diff` — compact structural git status, diff, and commit summary excluding lockfile noise.
- `droid_mode` — data-driven switcher for Factory Droid model pins (`prometheus-kit droid-mode`).
- `fingerprint` — in-process worktree fingerprinting.
- `hook` — native `PreToolUse` secret-path, large-read/reread, and shell-rewrite guards (`prometheus-kit hook`).
- `impact` — impact graph and targeted selection.
- `kit_util` — ANSI/CR normalization, noise-path classification, UTF-8 clipping, and spillover helpers.
- `logs` — normalized test-log parsing.
- `map` — one-call repository directory map with line counts and optional top-level symbols.
- `metrics` — bounded local savings counter read by `prometheus-kit metrics`.
- `outline` — structural outline extraction for code (C#, Razor, Rust, Python, TS/JS, Go, PowerShell), JSON/JSONL, YAML, TOML, and Markdown with token budgets.
- `search` — budgeted, grouped, line-clipped, optionally symbol-annotated search.
- `slice` — exact line-range and symbol/path slicing with interval merging and token budgets.
- `store` — hashing and Check slot primitives.

## Build, test, and benchmark

```sh
cargo build --release --locked --bin prometheus-check --bin prometheus-kit
cargo test --locked
cargo run --release --locked --example bench_kit
```

Rust differential parity tests in `fingerprint::tests` compare the worktree
fingerprint with `git add -A` and `git write-tree` across randomized trees.

## Maintainer metrics

`prometheus-kit metrics` prints lifetime totals aggregated from
`~/.agents/prometheus/metrics/savings.jsonl` as `{"by_host": ..., "by_rule": ...}`
(`--help` for usage). Each row stores only an epoch timestamp, a fixed host
(`claude`, `cursor`, `devin`, `droid`, `muse`, `standalone`), a fixed rule id,
and two byte counts — never session ids, paths, commands, or content. Hook
hosts come from the hook name; CLI commands classify only from the presence
of known nonempty host markers (`CURSOR_PROJECT_DIR`, `DEVIN_PROJECT_DIR`,
`CLAUDECODE`, `FACTORY_DROID_SESSION_ID`, `MUSE_SESSION_ID`), and zero or
multiple distinct markers report `standalone`.

What counts: shell command rewrites (original command bytes → replacement
bytes), large-read advisories and reread warnings (zero raw bytes → warning
length), reread denials (estimated read bytes → denial message length),
allowed retries (zero raw bytes → the same estimate, cancelling the denial's
credit), and at most one row per `compact`, `outline`, `slice`, `search`,
`diff`, or `map` invocation whose output was actually reduced or clipped —
`compact` counts every compaction including render overhead. For command
rows `raw_bytes` minus `emitted_bytes` is the measured saving; warning rows
add bytes, so only compare deltas within a single `rule_id`. For `slice` and
`search` on files that are not valid UTF-8, `raw_bytes` counts the selected
*decoded* text bytes, which can differ from the on-disk byte count.

The file is capped at 1 MiB and is opened only through owner-checked,
no-follow paths: on Unix every component must be a real directory owned by
the effective uid, with the metrics directory and file carrying no
group/other permission bits; on Windows ancestors are pinned by handles
that refuse delete-sharing and reparse points, missing directories are
created only for writes (the metrics directory atomically with an
owner-only protected DACL), and the private directory and file must pass an
owner/DACL check against the process token user; objects we create carry an
explicit owner and a protected owner-only DACL, so metrics stay private even
under a parent directory with no inheritable ACEs. Pre-existing metrics
directories or files whose DACL grants anyone else — including standard
user-profile ACLs that name SYSTEM or Administrators, or objects owned by
SYSTEM/admin rather than the current user — are refused rather than
repaired, so elevated or shared-account setups simply record nothing.
Refused opens, lock contention, malformed lines, and a full file all drop
rows silently — totals are a lower bound, never an error. Set `PROMETHEUS_KIT_NO_METRICS=1`
to disable all writes (an empty value still disables); reads never create
the file.

## Releases

A `core-v*` tag publishes twelve `prometheus-check-<platform>[.exe]` and `prometheus-kit-<platform>[.exe]` assets.
Linux builds target GLIBC 2.17 or older using manylinux2014 containers.
