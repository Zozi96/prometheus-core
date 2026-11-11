# prometheus-core

The native deterministic engine for the standalone `prometheus-check` runner.

## Modules

- `check` — runner, targeted selection, receipts, and host-wide Check slot.
- `classify` — documentation and test path classification.
- `fingerprint` — in-process worktree fingerprinting.
- `impact` — impact graph and targeted selection.
- `logs` — normalized test-log parsing.
- `store` — hashing and Check slot primitives.

## Build and test

```sh
cargo build --release --locked --bin prometheus-check
cargo test --locked
```

Rust differential parity tests in `fingerprint::tests` compare the worktree
fingerprint with `git add -A` and `git write-tree` across randomized trees.

## Releases

A `core-v*` tag publishes six `prometheus-check-<platform>[.exe]` assets.
Linux builds target GLIBC 2.17 or older using manylinux2014 containers.
