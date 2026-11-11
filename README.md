# prometheus-core

The in-process deterministic engine for the Prometheus gate (SureForge procedure).

One Rust crate, exposed to Python as the `prometheus_core` module (PyO3, abi3).
The gate runtime negotiates `ENGINE_API` (currently 4): when the module loads
and the API matches, it answers in process; on any failure the runtime reruns
the whole call on its own git CLI route.

## Modules

- `fingerprint` — the tree fingerprint: in-process git primitives (status,
  tracked files, excludes, staging into a private object store).
- `scan` — unified tree scan.
- `classify` — change-class support for the scan.
- `impact` — impact graph and targeted selection.
- `logs` — test-log parsing into normalized receipts.
- `store` — receipt store and check slot.
- `brief` — review/write brief construction.
- `settle` — findings and evidence settlement.
- `decide` — gate decision evaluation.
- `hooks` / `prometheus-hook` — fast-path host hook binary.
- `check` / `prometheus-check` — the standalone check runner (ADR-0010):
  targeted selection over the impact graph, the host-wide check slot with
  bounded footprint, iteration-profile handling, and green receipts, with
  no Python gate runtime involved.

## Building

The default `python` feature builds the `prometheus_core` module. The native
binaries need no Python: build and test them with
`cargo build --release --no-default-features --bins` and
`cargo test --no-default-features`.

## Releases

Pushing a `core-v*` tag runs the `core-release` workflow, which builds the
module for six platforms and publishes them as release assets. The parent
repo's `runtime/prometheus_core.lock` records the tag and each asset's sha256;
its installer verifies the checksum and the `ENGINE_API` before keeping a
download.

The Linux `prometheus-check` binaries are built in the same manylinux2014
container as the module, and the build fails if they reference a glibc newer
than 2.17.

## Parity

`parity_fuzz.py` differentially tests the fingerprint primitives against
`git add -A` + `git write-tree` over randomized trees. It expects this repo
checked out as the `core/` submodule of the Prometheus parent.
