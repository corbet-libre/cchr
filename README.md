# cchr — Charter

## Scope

### Purpose

Verifies and retains one coherent current set of a community's signed material from cvld.

### Owns

- Installs the manifest and the five snapshot kinds (settings, current schema, schema versions with classifications, community directory, revocations) as one all-or-nothing replacement, with monotonic revision and epoch floors.
- Provides the immutable verified view (original signed bytes, revisions, effective policy epoch, schema and history, revocation membership) that cgrd and Gather read.
- Is reusable by reference on member devices.

### Never

- Does not decide admission.
- Does not trust a signing ring because it signs itself, mix epochs, ignore separate revocations, translate rich policies into conjunctive settings, sign replacement snapshots, or store member data.
- Does not fetch (fetching belongs to cnvy) and does not read a wall clock.
- Does not carry schema editing methods.

### States

Unbootstrapped to Verifying to Current; expired, missing, or regressed-time reads lead to Unavailable; an invalid candidate leaves the current state and floors unchanged.

### Test obligations

- A real cvld feed installs only with authenticated bootstrap; wrong purpose or community, rollback, equal revision with different bytes, mixed epochs, expired snapshots, and missing kinds fail.
- Rotation accepts authorized retained keys, while a candidate ring never authenticates itself.
- Vectors cover real all, any, and k-of-n rules with revoked devices, and unsupported material refuses attendance.
- Ordinary member activity leaves feed bytes unchanged.
- Identical vectors run natively and on wasm, with install and update load coverage.

## Reuse and alternatives

- Extracted the verification sequence from cvld's `toy/src/offline.rs`, adding
  atomic commit, exact-byte conflict detection, bounded decoding and clock fences.
- Reuse **csgn** for canonical COSE, signature, purpose, issuer, lifetime and
  retained-key checks; **cshm** for schema validation/change classification.
  Calling coset or ed25519-dalek directly here would duplicate their owner.
- [serde_json](https://docs.rs/serde_json/latest/serde_json/) supplies parsing;
  a small recursive visitor rejects duplicate object keys before typed decoding.
  [url](https://docs.rs/url/latest/url/) handles origin parsing. No custom parser
  or cryptographic primitive is implemented.
- Importing the cplc/cvld server facade would couple this LGPL device consumer to
  FSL issuers and native storage. Their existing wire fields are decoded locally
  and checked against actual HTTP output in an isolated current-main producer process.

## Validation

GitHub Actions runs fmt, strict Clippy, coherent dependency checks, native tests,
wasm32 compilation and the same vectors under wasm-bindgen-test. The separate
`door` job starts the real cvld HTTP global/community services with disposable
libSQL databases and software authenticators. It changes policy/schema/revocation
through ordinary actions, verifies ordinary activity leaves feed bytes unchanged,
and feeds those bytes to both native and wasm consumers. Artifacts contain the
exact dependency locks and synthetic public publications. No external accounts.

## Dependency maintenance and coverage

First-party dependencies follow `main`; Cargo.lock records one exact revision
per crate. CI checks the entire resolved graph, including optional declarations.
Dependabot covers Cargo and GitHub Actions (there is no npm manifest here).
The merge workflow uses GitHub metadata only and requires every substantive CI
job and all published checks to succeed on the exact Dependabot head. It never
executes PR code with write permissions or bypasses branch protection.

[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) supplies LLVM line and
branch measurements; the strict gate and exclusions are in [COVERAGE.md](docs/COVERAGE.md).
