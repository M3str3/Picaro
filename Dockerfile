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
#   docker run --rm -it -v "$PWD:/work" -w /work picaro build plan.yaml

FROM rust:1-bookworm

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

# Layer the build: manifests first so dependency resolution is cached, then the
# source. `examples/` is needed only for the end-to-end smoke test below.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY yara ./yara
COPY examples ./examples

# Build the packer for the host (Linux). This also produces the host-side
# proc-macro rlibs (windows-implement, windows-interface) in target/release/deps.
RUN cargo build --release

# Cross-compile the workspace for the stub's Windows targets. This produces the
# .rlib files the packer links with bare rustc (chacha20poly1305, hex, windows,
# thiserror) plus the windows_<arch>_gnu import libs in the cargo registry cache.
# The i686 build is what makes `build.output.arch: x86` work in here.
RUN cargo build --target x86_64-pc-windows-gnu --release
RUN cargo build --target i686-pc-windows-gnu --release

# Smoke test: pack a payload end-to-end to prove the cross toolchain is wired
# correctly. Fails the image build if anything is misconfigured.
RUN ./target/release/picaro --quiet build examples/plans/reflective-loading.yaml \
    && test -s dist/test_packed_reflective.exe

# Second smoke test: the portable signer. Builds a lab-signed artifact (the
# certificate chain is generated with `openssl`) and proves the artifact carries
# a signature, so a missing/broken signer fails the image build.
RUN ./target/release/picaro --quiet build examples/plans/lab-signed.yaml \
    && test -s dist/lab_signed.exe \
    && osslsigncode extract-signature -pem -in dist/lab_signed.exe -out /tmp/lab_signed.pem \
    && test -s /tmp/lab_signed.pem

# The user mounts a directory with plans/payloads here; outputs land back on
# the host through the same mount.
WORKDIR /work
VOLUME ["/work"]

ENTRYPOINT ["/usr/src/picaro/target/release/picaro"]
CMD ["--help"]
