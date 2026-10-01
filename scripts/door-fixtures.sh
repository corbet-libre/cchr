#!/usr/bin/env bash
set -euo pipefail
test "${CI:-}" = true
source_root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
door_dir="$source_root/.build/cvld"
mkdir -p "$door_dir"
# The cache may already have restored target/ here; preserve it.
git -C "$door_dir" init --quiet
git -C "$door_dir" remote add origin https://github.com/corbet-libs/cvld
git -C "$door_dir" fetch --quiet --depth 1 origin 83c163e4239923fa45e38e3712561c42c90f16d8
git -C "$door_dir" switch --detach FETCH_HEAD
mkdir -p "$door_dir/examples"
cp "$source_root/scripts/produce_door.rs" "$door_dir/examples/charter_feed.rs"
export CHARTER_FIXTURES="$source_root/.build/fixtures"
cargo run --locked --manifest-path "$door_dir/Cargo.toml" --features development-gate --example charter_feed
