# cchr agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cchr` — native suite, green
  (vectors `32`, birth_genesis `7` + `1` ignored, root_board `5`,
  genesis_stamp `4`, lib `4`, snapshot_age `1`, revision_stamp `1`;
  `door` needs the `door-vectors` feature), exit 0
- `~/agents/scratch/cbuild <lane> fmt -p cchr -- --check` — must be clean
- Full gate (strict clippy `--locked`, wasm32 check, wasm vectors,
  real-door fixtures, nightly 100% coverage) runs in CI only:
  `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test in `tests/vectors.rs` unless noted):
- Verify-only: charter never admits; admission is the Guard's job
  -> `coherent_material_is_immutable_and_expiry_cannot_reverse` (empty `Bundle` not admitted)
- Atomic commit: failed installs keep the old set
  -> `invalid_candidates_never_partially_replace_the_installed_set`
- Equal revision with different bytes is equivocation and refused
  -> `same_revision_requires_exact_original_signed_bytes`
- Injected clock only moves forward; regression is refused
  -> `coherent_material_is_immutable_and_expiry_cannot_reverse` (`ClockRegression`)
- `MAXIMUM_SNAPSHOT_AGE` is a code constant: two issuer days
  -> `tests/snapshot_age.rs::the_product_snapshot_age_limit_is_two_issuer_days`
- Pure leaf: no storage, network, wall clock or signing keys
  -> `src/lib.rs:2` (`forbid(unsafe_code)`); installs take only `&[u8]` + `now`
- Duplicate object keys refused at every depth
  -> `duplicate_fields_unknown_fields_trailing_bytes_and_limits_fail`
- Roots come from deployment config; rings rotate only by signed transition
  -> `configured_root_and_signed_rotation_are_explicit`

Pointers: `src/lib.rs`, `src/wire.rs`, `docs/CONTRACT.md`,
`docs/COVERAGE.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking exception; never publish to a registry.
