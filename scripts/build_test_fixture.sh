#!/usr/bin/env bash
# Regenerates the committed PE fixtures in tests/fixtures/ from minimal_main.rs.
#
# The fixtures are committed so the PE parser tests do not depend on a working
# Windows toolchain being available on every machine: they are tiny (~4 KB) and
# never executed, only statically parsed by the tests. Regenerate them only when
# `minimal_main.rs` changes, on a machine that has the target installed.
#
# Usage:
#   bash scripts/build_test_fixture.sh              # both, with the default triples
#   bash scripts/build_test_fixture.sh x86          # only minimal_x86.exe
#   TARGET=i686-pc-windows-msvc bash scripts/build_test_fixture.sh x86
#
# The defaults are the GNU cross targets (what the Docker image has). On Windows
# without MinGW, `TARGET=i686-pc-windows-msvc` (or `x86_64-pc-windows-msvc`) works
# just as well: the fixture is parsed, never run.

set -euo pipefail

# Resolve the repo root (the parent of this script's directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC="$ROOT/tests/fixtures/minimal_main.rs"

# build <arch> <default triple>
build() {
    local arch="$1"
    local target="${TARGET:-$2}"
    local out="$ROOT/tests/fixtures/minimal_${arch}.exe"

    rustc --target "$target" \
        -O \
        -C panic=abort \
        -C debuginfo=0 \
        -C strip=symbols \
        "$SRC" \
        -o "$out"

    # MSVC still writes a `.pdb` next to the binary; the fixture is only parsed,
    # so keep the tree clean.
    rm -f "${out%.exe}.pdb"

    echo "OK: $out ($target)"
}

case "${1:-all}" in
    x64) build x64 x86_64-pc-windows-gnu ;;
    x86) build x86 i686-pc-windows-gnu ;;
    all)
        build x64 x86_64-pc-windows-gnu
        build x86 i686-pc-windows-gnu
        ;;
    *)
        echo "usage: $0 [all|x64|x86]" >&2
        exit 2
        ;;
esac
