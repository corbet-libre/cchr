# cchr — Charter

Verify one coherent set of community trust material from the cvld door. Charter
retains the original signed manifest and all five snapshots, current schema,
checked schema history, revocations and monotonic revisions. It runs on native
Rust and wasm with caller-supplied time and authenticated origin evidence.

```rust
# fn example(bytes: &[u8], authority: &cchr::AuthenticatedOrigin, now: u64) -> cchr::Result<()> {
let mut charter = cchr::Charter::new("https://alpha.example.test", "alpha")?;
charter.install(bytes, authority, now)?;
let current = charter.current(now)?;
assert_eq!(current.community(), "alpha");
# Ok(()) }
```

`AuthenticatedOrigin` is a privileged transport/configuration boundary, analogous
to cpsd's authenticated community. Never construct it from an unauthenticated
feed. Bootstrap requires a fresh authenticated origin and revision floor;
a self-signed ring is insufficient. Rotated rings require new origin evidence.
No storage, network, wall-clock access, signing keys or background tasks exist.

Charter is **not an admission checker**. The current cgrd policy format cannot
consume cplc's full all/any/threshold policy and separate revocations. Until that
owner boundary is implemented, `admission_policy()` returns `UnsupportedPolicy`.
Do not convert settings, drop constraints or sign replacement snapshots.

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
  and checked against actual HTTP output in an isolated, pinned producer process.

## Validation

GitHub Actions runs fmt, strict Clippy, pinned-dependency checks, native tests,
wasm32 compilation and the same vectors under wasm-bindgen-test. The separate
`door` job starts the real cvld HTTP global/community services with disposable
libSQL databases and software authenticators. It changes policy/schema/revocation
through ordinary actions, verifies ordinary activity leaves feed bytes unchanged,
and feeds those bytes to both native and wasm consumers. Artifacts contain the
exact dependency locks and synthetic public publications. No external accounts.
