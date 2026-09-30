# syntax=docker/dockerfile:1

# picaro — build and run the packer inside a container.
#
# This image bundles the full toolchain the packer needs to turn its generated
# Rust stub into a Windows PE, so a machine without Rust + MinGW-w64 can still
# use the project:
#
#   * rustc + cargo        (base image)
#   * x86_64-pc-windows-gnu standard library (rustup target)
#   * MinGW-w64 linker     (gcc-mingw-w64-x86-64)
#   * prebuilt workspace .rlib files for the stub's Windows target
#
# Signing needs no Windows SDK either: `osslsigncode` signs the artifact and
# `openssl` generates the `mode: lab` certificate chain, so every signing mode
# except `store` (which reads the Windows certificate store) works in here.
#
# Usage (see README.md, "Docker"):
#   docker build -t picaro .
#   docker run --rm -it --user "$(id -u):$(id -g)" -e PICARO_BUILD_DIR=/tmp/picaro-build \
#     -v "$PWD:/work" -w /work picaro build plan.yaml
#
# `--user` keeps the artifacts you write through the mount yours instead of
# root-owned; `PICARO_BUILD_DIR` moves the packer's scratch files off the
# read-only source tree. scripts/picaro.py sets both for you.

# Pinned by digest, not by the floating `1-bookworm` tag. That tag is re-pushed
# with every Rust release (roughly every six weeks) and every Debian bookworm
# rebuild, and a new base image invalidates every layer below `FROM` — the
# dependency layer (`COPY Cargo.toml Cargo.lock` plus the placeholder build)
# included, so a rebuild would recompile the whole tree instead of reusing the
# cache.
#
# The digest is the multi-arch *index* (linux/amd64, arm64, ...), so all
# architectures keep working; pinning a per-arch digest would break the others.
# At the time of writing `1-bookworm` == `1.98.1-bookworm` (2026-09-30).
#
# To bump: `docker pull rust:1-bookworm`, then
# `docker image inspect rust:1-bookworm --format '{{index .RepoDigests 0}}'`,
# and update the digest and the date below.
FROM rust:1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e

# MinGW-w64 provides `x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc`, the
# linkers `rustc --target <arch>-pc-windows-gnu` uses to link the stub into a PE.
# `osslsigncode` is the portable Authenticode signer and `openssl` builds the lab
# certificate chain.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 \
        gcc-mingw-w64-i686 \
        openssl \
        osslsigncode \
    && rm -rf /var/lib/apt/lists/*

# Standard library for the Windows GNU cross-compilation targets (both
# architectures: `build.output.arch` selects which one the stub is built for).
RUN rustup target add x86_64-pc-windows-gnu i686-pc-windows-gnu

# The packer reads its stub template and Cargo.lock from CARGO_MANIFEST_DIR at
# runtime, so the source stays in the image next to the built binary.
WORKDIR /usr/src/picaro

# Layer the build so a source edit recompiles only the packer, not its
# dependencies. Manifests plus a placeholder `main.rs` come first: this
# downloads and compiles the whole dependency tree (windows-rs included) into a
# layer keyed on `Cargo.toml`/`Cargo.lock` alone. The Cargo registry and the
# `.rlib`s stay in the image regardless: the packer reads both at runtime to
# link the stub.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && cargo build --target x86_64-pc-windows-gnu --release \
    && cargo build --target i686-pc-windows-gnu --release

# Then the real source on top of the dependency layer, so only the packer crate
# is recompiled. The host build also produces the host-side proc-macro rlibs
# (windows-implement, windows-interface) in `target/release/deps`; the cross
# builds produce the stub's `.rlib`s and the windows_<arch>_gnu import libs
# (`build.output.arch: x86` needs the i686 one). `touch` puts the sources
# strictly after the placeholder build's fingerprints, so Cargo cannot treat the
# crate as fresh and keep the placeholder binary when a copied file carries an
# older mtime.
COPY src ./src
RUN touch src/main.rs && cargo build --release
RUN cargo build --target x86_64-pc-windows-gnu --release
RUN cargo build --target i686-pc-windows-gnu --release

# Copied after the compile: read at runtime, so editing a template or an example
# must not invalidate the build layers above. `examples/` feeds the smoke tests
# below; `yara/` is read by `audit`.
COPY templates ./templates
COPY yara ./yara
COPY examples ./examples

# The user mounts a directory with plans/payloads here; outputs land back on
# the host through the same mount.
WORKDIR /work
VOLUME ["/work"]

ENTRYPOINT ["/usr/src/picaro/target/release/picaro"]
CMD ["--help"]
