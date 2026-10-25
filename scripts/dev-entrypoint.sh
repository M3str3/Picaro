#!/usr/bin/env bash
# Entrypoint for the compose dev container.
#
# The repo is bind-mounted at /work, so source edits never rebuild the image and
# Cargo's output lives in the `picaro-target` volume. The only one-time cost is
# the cross-compiled dependency set the packer links into the stub: seed it here
# (debug profile, the one `cargo run` uses), then exec the requested command.
#
#   docker compose run --rm dev-run build examples/plans/reflective-loading.yaml
#   docker compose run --rm dev cargo test
#
# The checks make every later run a no-op.
set -euo pipefail

cd /work

ensure_target() {
    local triple="$1"
    if [ ! -d "target/${triple}/debug/deps" ]; then
        echo "picaro-dev: building ${triple} dependencies (first run)..." >&2
        cargo build --target "${triple}"
    fi
}

ensure_target x86_64-pc-windows-gnu
ensure_target i686-pc-windows-gnu

if [ "$#" -eq 0 ]; then
    exec bash
fi
exec "$@"
