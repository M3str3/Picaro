#!/usr/bin/env bash
# Regenerates tests/fixtures/minimal_x64.exe from minimal_main.rs.
#
# The fixture is committed so that the PE parser tests do not depend on a
# working MinGW-w64 toolchain being available on every machine: the fixture is
# tiny (~4 KB) and never executed, only statically parsed by the tests.
# Regenerate it only when `minimal_main.rs` changes, on a machine that has the
# `x86_64-pc-windows-gnu` target and the MinGW linker installed.
#
# Usage: bash scripts/build_test_fixture.sh

set -euo pipefail

# Resolve the repo root (the parent of this script's directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGET="x86_64-pc-windows-gnu"
SRC="$ROOT/tests/fixtures/minimal_main.rs"
OUT_DIR="$ROOT/tests/fixtures"
OUT="$OUT_DIR/minimal_x64.exe"

mkdir -p "$OUT_DIR"

rustc --target "$TARGET" \
    -O \
    -C panic=abort \
    -C strip=symbols \
    "$SRC" \
    -o "$OUT"

echo "OK: $OUT"
