#!/usr/bin/env bash
# Convenience wrapper: build the batesian image on first use, then run it
# against the current directory with every argument passed through unchanged.
#
# Usage:
#   bash scripts/docker-batesian.sh build examples/configs/test-reflective.yaml
#   bash scripts/docker-batesian.sh audit dist/test_packed_reflective.exe
#   bash scripts/docker-batesian.sh techniques list
#
# Pass --build first to force a rebuild of the image.
set -euo pipefail

IMAGE="${BATESIAN_IMAGE:-batesian:latest}"

# Resolve the repo root (this script lives in scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "${1:-}" == "--build" ]]; then
    shift
    docker build -t "$IMAGE" "$ROOT"
elif ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "batesian: building image $IMAGE (first run)..." >&2
    docker build -t "$IMAGE" "$ROOT"
fi

# Mount the current directory as /work: configs and payloads are read from it
# and outputs (dist/…) are written back through the same mount. Allocate a TTY
# only when stdout is one, so the CLI's color auto-detection keeps working and
# piping still succeeds.
if [ -t 1 ]; then
    exec docker run --rm -it -v "$PWD:/work" -w /work "$IMAGE" "$@"
else
    exec docker run --rm -v "$PWD:/work" -w /work "$IMAGE" "$@"
fi
