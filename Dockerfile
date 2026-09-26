# syntax=docker/dockerfile:1

# batesian — build and run the packer inside a container.
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
# Usage (see README.md, "Docker"):
#   docker build -t batesian .
#   docker run --rm -it -v "$PWD:/work" -w /work batesian build config.yaml

FROM rust:1-bookworm

# MinGW-w64 provides `x86_64-w64-mingw32-gcc`, the linker `rustc --target
# x86_64-pc-windows-gnu` uses to link the stub into a PE.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*

# Standard library for the Windows GNU cross-compilation target.
RUN rustup target add x86_64-pc-windows-gnu

# The packer reads its stub template and Cargo.lock from CARGO_MANIFEST_DIR at
# runtime, so the source stays in the image next to the built binary.
WORKDIR /usr/src/batesian

# Layer the build: manifests first so dependency resolution is cached, then the
# source. `examples/` is needed only for the end-to-end smoke test below.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY banner.txt ./
COPY yara ./yara
COPY examples ./examples

# Build the packer for the host (Linux). This also produces the host-side
# proc-macro rlibs (windows-implement, windows-interface) in target/release/deps.
RUN cargo build --release

# Cross-compile the workspace for the stub's Windows target. This produces the
# .rlib files the packer links with bare rustc (chacha20poly1305, hex, windows,
# thiserror) plus the windows_x86_64_gnu import lib in the cargo registry cache.
RUN cargo build --target x86_64-pc-windows-gnu --release

# Smoke test: pack a payload end-to-end to prove the cross toolchain is wired
# correctly. Fails the image build if anything is misconfigured.
RUN ./target/release/batesian --quiet build examples/configs/test-reflective.yaml \
    && test -s dist/test_packed_reflective.exe

# The user mounts a directory with configs/payloads here; outputs land back on
# the host through the same mount.
WORKDIR /work
VOLUME ["/work"]

ENTRYPOINT ["/usr/src/batesian/target/release/batesian"]
CMD ["--help"]
