# Coverage gate

CI uses cargo-llvm-cov on nightly for upstream Rust branch instrumentation.
Stable Rust remains the compiler for formatting, Clippy, native and wasm checks.
The gate requires exactly 100% covered production lines and branches, from the
LLVM JSON counts, and refuses absent or empty measurements. There are no
production-code exclusions. Test harness and fixture files are excluded because
they are validation inputs rather than shipped behavior. A failed gate is an
open test gap, never evidence of complete coverage.

Dependencies are resolved once per CI run and the resulting Cargo.lock artifact
is reused by every job. CI refreshes within the declared ranges;
Dependabot proposes lockfile updates for review and merging after full CI.
The checked-in lock and per-run artifacts retain exact reproducible resolutions.

HTTPS origin parsing relies on `url`'s special-scheme host validation: an HTTPS
URL without a host fails parsing before Charter receives a `Url`. The redundant
post-parse host absence condition was removed, while malformed HTTPS origins
remain covered by the real parser and origin tests. No production coverage
exclusion is used for this invariant.
