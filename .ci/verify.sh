#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
CCHR_LAST_GATE="init"
trap 'rc=$?; echo "CCHR-DIAG last_gate=$CCHR_LAST_GATE exit=$rc" >&2; exit $rc' EXIT
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
# door-fixtures.sh requires exactly CI=true (GitHub semantics); the Crow
# repository-jobs worker provides it here.
export CI=true

CCHR_LAST_GATE="metadata"
bash .ci/update-our-crates.sh
cargo metadata --locked --format-version 1 > dependency-metadata.json
CCHR_LAST_GATE="first-party"
python3 .github/check-first-party.py
CCHR_LAST_GATE="coverage-selftest"
python3 .github/test-check-source-coverage.py
CCHR_LAST_GATE="toolchain"
rustc --version
CCHR_LAST_GATE="fmt"
cargo fmt --all --check
CCHR_LAST_GATE="clippy"
cargo clippy --locked --all-targets -- -D warnings
CCHR_LAST_GATE="native-tests"
cargo test --locked
CCHR_LAST_GATE="wasm-check"
cargo check --locked --target wasm32-unknown-unknown
# scripts/wasm-runner.sh (set -u) needs RUNNER_TEMP + GITHUB_PATH and only
# appends the runner dir; reload PATH from the file so the test runner resolves.
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"
CCHR_LAST_GATE="wasm-runner"
bash scripts/wasm-runner.sh
export PATH="$(tail -n 1 "$GITHUB_PATH"):$PATH"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
CCHR_LAST_GATE="wasm-vectors"
cargo test --locked --target wasm32-unknown-unknown --lib --test it

CCHR_LAST_GATE="door-fixtures"
bash scripts/door-fixtures.sh
CCHR_LAST_GATE="door-metadata"
cargo metadata --locked --format-version 1 > dependency-metadata.json
CCHR_LAST_GATE="door-native"
cargo test --locked --features door-vectors --test door
CCHR_LAST_GATE="door-wasm-runner"
bash scripts/wasm-runner.sh
export PATH="$(tail -n 1 "$GITHUB_PATH"):$PATH"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
CCHR_LAST_GATE="door-wasm"
cargo test --locked --target wasm32-unknown-unknown --features door-vectors --test door

CCHR_LAST_GATE="nightly-select"
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
CCHR_LAST_GATE="coverage"
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --text --show-instantiations > coverage.txt
)
CCHR_LAST_GATE="coverage-check"
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
CCHR_LAST_GATE="first-party-final"
python3 .github/check-first-party.py
