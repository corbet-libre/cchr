# Agent instructions

Write code, comments and documentation in English.

## Product boundary

- Charter: verify coherent community publications; never decide admission.
- Read docs/CONTRACT.md before changing the public boundary.
- Survey maintained libraries first; record candidates and reasons in README.md.
- Reuse csgn verification and cshm schema semantics. No cryptographic primitives.
- No member queries, activity logs, identifiers in diagnostics, private keys or SQL storage.
- Inject time and I/O; invalid trust never becomes authority.
- Licence: LGPL-3.0-only WITH LGPL-3.0-linking-exception.

## Quality boundary

- Run formatting, strict Clippy, tests and wasm32 checks in GitHub Actions.
- Execute shared vectors on wasm; compile-only is insufficient.
- Do not run Cargo on the workstation. Never deploy or publish registries.
- Pin first-party Git dependencies by full revision, one revision per crate.
- Commit explicit paths, plain English imperative messages, no AI attribution.
- Pull with rebase before every push; never force-push.
