# prometheus-core

The in-process deterministic engine for the Prometheus gate (SureForge procedure).

One Rust crate, exposed to Python as the `prometheus_core` module (PyO3, abi3).
The gate runtime negotiates `ENGINE_API` (currently 3): when the module loads
and the API matches, it answers in process; on any failure the runtime reruns
the whole call on its own git CLI route.

## Modules

- `fingerprint` — the tree fingerprint: in-process git primitives (status,
  tracked files, excludes, staging into a private object store).
- `scan` — unified tree scan (scaffold; lands with the scan tickets of spec #43).
- `classify` — change-class support for the scan (scaffold).
- `logs` — test-log parsing into normalized receipts (scaffold).
- `brief` — review/write brief construction (scaffold).
- `settle` — findings and evidence settlement (scaffold).

## Releases

Pushing a `core-v*` tag runs the `core-release` workflow, which builds the
module for six platforms and publishes them as release assets. The parent
repo's `runtime/prometheus_core.lock` records the tag and each asset's sha256;
its installer verifies the checksum and the `ENGINE_API` before keeping a
download.

## Parity

`parity_fuzz.py` differentially tests the fingerprint primitives against
`git add -A` + `git write-tree` over randomized trees. It expects this repo
checked out as the `core/` submodule of the Prometheus parent.
