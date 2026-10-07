#!/usr/bin/env bash
set -euo pipefail
test "${CI:-}" = true
source_root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
door_dir="$source_root/.build/cvld"
mkdir -p "$door_dir"
# The cache may already have restored target/ here; preserve it.
git -C "$door_dir" init --quiet
git -C "$door_dir" remote add origin https://git.corbet.ch/corbet-libs/cvld
git -C "$door_dir" fetch --quiet --depth 1 origin main
git -C "$door_dir" switch --detach FETCH_HEAD
git -C "$door_dir" rev-parse HEAD > "$source_root/.build/door-revision.txt"
mkdir -p "$door_dir/examples"
cp "$source_root/scripts/produce_door.rs" "$door_dir/examples/charter_feed.rs"
python3 - "$door_dir/Cargo.toml" <<'PY'
import sys
from pathlib import Path
manifest = Path(sys.argv[1])
text = manifest.read_text()
assert text.count('[dependencies]\n') == 1
text = text.replace('[dependencies]\n', '[dependencies]\ncgrd = { git = "https://git.corbet.ch/corbet-foss/cgrd", branch = "main", default-features = false }\n', 1)
manifest.write_text(text)
PY
export CHARTER_FIXTURES="$source_root/.build/fixtures"
cd "$door_dir"
cargo update
cargo metadata --locked --format-version 1 > dependency-metadata.json
python3 "$source_root/.github/check-first-party.py"
python3 "$source_root/scripts/check-door-dependencies.py" Cargo.lock
cargo run --locked --features development-gate --example charter_feed
