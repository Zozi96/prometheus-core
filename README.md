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

## Releases

A `core-v*` tag publishes twelve `prometheus-check-<platform>[.exe]` and `prometheus-kit-<platform>[.exe]` assets.
Linux builds target GLIBC 2.17 or older using manylinux2014 containers.
