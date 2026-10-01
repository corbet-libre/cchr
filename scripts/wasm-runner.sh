#!/usr/bin/env bash
set -euo pipefail
version=$(jq -r '.packages[] | select(.name == "wasm-bindgen") | .version' dependency-metadata.json)
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}"
mkdir -p "$RUNNER_TEMP/charter-wasm-runner"
cd "$RUNNER_TEMP/charter-wasm-runner"
curl -A 'ci-dependency-fetch/1.0' --fail --location --retry 3 --remote-name "$base/$archive"
curl -A 'ci-dependency-fetch/1.0' --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xzf "$archive" --strip-components=1
echo "$PWD" >> "$GITHUB_PATH"
