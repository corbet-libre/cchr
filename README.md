# cchr — Charter

## Scope

Verify one coherent set of community trust material from the cvld door. Charter
retains the original signed manifest and all five snapshots, current schema,
checked schema history, revocations and monotonic revisions. It runs on native
Rust and wasm with injected Unix-second time and deployment-configured publishing keys.

```rust
# fn example(bytes: &[u8], configuration: cchr::Configuration, now: u64) -> cchr::Result<()> {
let mut charter = cchr::Charter::new(configuration)?;
charter.install(bytes, now)?;
let current = charter.current(now)?;
assert_eq!(current.community(), "alpha");
# Ok(()) }
```

`Configuration` comes from the embedding deployment: exact HTTPS origin,
community, initial public key ring and independent feed/ring revision floors.
Responses never authorize their own keys. Every later ring requires original
csgn transition bytes signed by the currently installed ring. Charter owns
verification and commits the new ring/floors only with a fully valid feed.
No storage, network, wall-clock access, signing keys or background tasks exist.

Charter supplies `admission_policy(action, now, maximum_snapshot_age)` to Guard's
`check_published`. The adapter retains original signed settings and separate
revocations. Guard returns admission only after the actual credential, device,
profile, pins and complete Rulebook policy pass. Charter alone grants no
admission. No replacement snapshot is signed or synthesized.

See [the implemented contract](docs/CONTRACT.md). LGPL-3.0-only WITH
LGPL-3.0-linking-exception; not published to package registries.

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

## Balance snapshot

The signed manifest may require a canonical Balance document through
`balance_revision`. Its separate `balance` feed field must then be present with
the exact revision, same community/epoch and strict
`cblc.public-verifier.v1` purpose under the configured publication ring. It is
installed atomically with all other snapshots and key transitions; its deadline
shortens the whole view. Missing, regressed or conflicting bytes refuse and
retain the old floors, including after expiry. A configured kind cannot later
disappear. Duplicate payload fields are rejected at every depth.

`VerifiedCharter::balance()` borrows original authenticated bytes and routing
metadata via Beacon's shared `balance::Balance` type. Decode economic policy and
artifact bindings with the accounting owner; this LGPL library introduces no
second accounting schema, account-state verifier or FSL dependency. An absent
Balance document grants no accounting capability. Public-record currentness and
punishment remain separate feature decisions.

`VerifiedCharter::settings(now)` borrows the original `crbk::Snapshot` after
checking protected issuance time and the complete installed-feed expiry. Its
community, revision, epoch, time and content come from the actual signed settings
publication. Rulebook-owned projections define product keys and values; Charter
provides no defaults, forum parser or admission result.

Public passkey binding uses original csgn COSE verification plus Keyhole's portable
`PublicCredential` type. Charter does not implement WebAuthn parsing or crypto;
the owning G3 composition calls the maintained original Keyhole verifier after
checking current Policy material and exact Keys challenge.

## Common root-board publication

`VerifiedCharter::root_board()` returns Policy's authenticated public descriptor
publication when the signed manifest requires `root_board_revision`. Its original
COSE bytes install atomically, shorten the complete deadline and retain independent
revision/equivocation and presence floors even after expiry. Routing uses the
exact `cplc.root-board.v1` purpose, configured community and manifest epoch.

This is the same byte-ownership boundary as Balance. Charter adds no CPSD
crypto dependency: a consumer obtains a current view, decodes `Payload.descriptor`
with original CPSD, and checks descriptor scope, epoch and lifetime before use.
Authenticated malformed descriptor bytes provide no decoded capability, role or
credential. No holder, source-community or member activity data enters this field.
