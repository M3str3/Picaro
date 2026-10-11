# syntax=docker/dockerfile:1

# Picaro — build and run the packer inside a container.
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
#
# The file has three stages:
#   * `toolchain` — the cross-compilation environment and the compiled packer
#     (shared by both images below).
#   * `dev`        — `toolchain` + Metasploit's `msfvenom` + a shell, selected
#     by `docker-compose.yml` (`target: dev`).
#   * `picaro`     — the production image above; declared *last* because Docker's
#     default build target is the last stage in the file.
FROM rust:1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS toolchain

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

# `powershell_hosting` compiles a small C# launcher at build time against the
# Windows PowerShell 5.1 engine, which needs two inputs a Linux toolchain does
# not have:
#
#   * a C# compiler able to emit a .NET Framework 4.x assembly — Mono's `mcs`
#     (`mono-devel` carries the net40 reference assemblies under
#     `/usr/lib/mono/4.0-api` too).
#   * PowerShell 5.1's `System.Management.Automation.dll` — the SDK *reference*
#     assembly from the official NuGet package (targets net40). A reference
#     assembly is all the compiler needs; at run time the CLR host resolves the
#     real assembly from the target's GAC.
#
# Both are build-time only and never reach the artifact, exactly like rustc and
# MinGW above. The two overrides (`PICARO_CSC` / `PICARO_PSASSEMBLY`) are the
# same knobs a host install uses. This block sits *after* the cargo layers on
# purpose: it only runs once and never invalidates the (expensive) dependency
# compile above.
ARG PICARO_PSREF_VERSION=1.1.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        mono-devel \
        mono-mcs \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && test -x /usr/bin/mcs \
    && curl -fsSL -o /tmp/psref.nupkg \
        "https://www.nuget.org/api/v2/package/Microsoft.PowerShell.5.ReferenceAssemblies/${PICARO_PSREF_VERSION}" \
    && mkdir -p /usr/local/lib/powershell-ref \
    && unzip -o -j /tmp/psref.nupkg 'lib/*' -d /usr/local/lib/powershell-ref \
    && test -f /usr/local/lib/powershell-ref/System.Management.Automation.dll \
    && rm -f /tmp/psref.nupkg

# Point the packer at the container's C# compiler and PowerShell reference
# assembly. `mcs` is Mono's compiler; it emits the .NET Framework assembly the
# stub's CLR host loads at run time.
ENV PICARO_CSC=/usr/bin/mcs \
    PICARO_PSASSEMBLY=/usr/local/lib/powershell-ref/System.Management.Automation.dll

# Copied after the compile: read at runtime, so editing an example must not
# invalidate the build layers above. `examples/` feeds the smoke tests below;
# the stub template and the YARA rules live under `src/` now, so they are copied
# above with the source.
COPY examples ./examples

# ---------------------------------------------------------------------------
# Development image: `toolchain` plus Metasploit's `msfvenom` and a non-root
# shell, so payloads can be generated and packed/audited in one container with
# the host's `exchange/` folder mounted in. Selected by `docker-compose.yml`
# (`target: dev`) or `docker build --target dev`.
#
# Declared *before* the production stage on purpose: Docker's default build
# target is the *last* stage, so `picaro` stays last and `docker build -t
# picaro .` (what scripts/picaro.py and the README use) is unchanged.
FROM toolchain AS dev

# Convenience tooling for poking at payloads and artifacts. `nasm` lets
# msfvenom use its assembly-based encoders.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        file \
        gnupg \
        less \
        nasm \
        xxd \
        nano \
    && rm -rf /var/lib/apt/lists/*

# Optional: trust a TLS-inspecting proxy's CA so the Metasploit download below
# works behind a corporate proxy (Netskope, Zscaler, ...), which re-signs
# `downloads.metasploit.com` with a root the base image does not trust. Two
# opt-in knobs, both empty by default:
#
#   PICARO_EXTRA_CA=<path>     a PEM/CRT file inside the build context, added
#                              to the system trust store as-is (explicit).
#   PICARO_TRUST_PROXY_CA=1    extract the proxy's self-signed root from the
#                              live chain (in the build's own network path) and
#                              trust it. Convenience for a locked-down dev box:
#                              it trusts whatever root the network presents, so
#                              use it knowingly and not in CI.
#
# See README.md, "Development container".
ARG PICARO_EXTRA_CA=
ARG PICARO_TRUST_PROXY_CA=
RUN set -eu; \
    if [ -n "${PICARO_EXTRA_CA}" ]; then \
        install -Dm0644 "${PICARO_EXTRA_CA}" \
            /usr/local/share/ca-certificates/picaro-extra-ca.crt; \
    fi; \
    if [ -n "${PICARO_TRUST_PROXY_CA}" ]; then \
        hosts="${PICARO_TRUST_PROXY_CA}"; \
        if [ "${hosts}" = "1" ] || [ "${hosts}" = "true" ]; then \
            hosts="downloads.metasploit.com raw.githubusercontent.com"; \
        fi; \
        work="$(mktemp -d)"; \
        for host in ${hosts}; do \
            openssl s_client -connect "${host}:443" -servername "${host}" -showcerts \
                </dev/null >"${work}/chain.pem" 2>/dev/null || true; \
            rm -f "${work}"/c*.pem; \
            csplit -sz -f "${work}/c" -b '%d.pem' "${work}/chain.pem" \
                '/-----BEGIN CERTIFICATE-----/' '{*}' >/dev/null 2>&1 || true; \
            for pem in "${work}"/c*.pem; do \
                [ -f "${pem}" ] || continue; \
                subj="$(openssl x509 -in "${pem}" -noout -subject 2>/dev/null || true)"; \
                iss="$(openssl x509 -in "${pem}" -noout -issuer 2>/dev/null || true)"; \
                [ -n "${subj}" ] || continue; \
                if [ "${subj#subject=}" = "${iss#issuer=}" ]; then \
                    cp "${pem}" "/usr/local/share/ca-certificates/picaro-proxy-${host}.crt"; \
                fi; \
            done; \
        done; \
        rm -rf "${work}"; \
    fi; \
    if [ -n "${PICARO_EXTRA_CA}" ] || [ -n "${PICARO_TRUST_PROXY_CA}" ]; then \
        update-ca-certificates; \
    fi

# Metasploit Framework (the package that provides `msfvenom`). Rapid7 publishes
# an apt repository and an installer that adds it plus its signing key; the
# installer is pinned to the commit that last touched it, so the build is
# reproducible and the embedded PGP key verifies every package. The CA above is
# trusted first, because a TLS-inspecting proxy re-signs this download.
# RUN set -eux; \
#     curl -fsSL -o /tmp/msfinstall \
#         "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/45946ec8c2620d7f9c97d4d5ef3f30a201c48677/config/templates/metasploit-framework-wrappers/msfupdate.erb"; \
#     chmod +x /tmp/msfinstall; \
#     /tmp/msfinstall; \
#     rm -f /tmp/msfinstall

# Run as a non-root user so anything written through the bind mounts is owned
# by the invoking host user instead of root. The uid/gid default to the common
# 1000; override with `--build-arg PICARO_UID=... --build-arg PICARO_GID=...`
# (docker-compose.yml forwards `PICARO_UID`/`PICARO_GID` from the environment).
ARG PICARO_UID=1000
ARG PICARO_GID=1000
RUN groupadd --gid "${PICARO_GID}" dev \
    && useradd --uid "${PICARO_UID}" --gid "${PICARO_GID}" \
        --create-home --shell /bin/bash dev

# `picaro` on PATH, so the workflow matches a host install.
RUN ln -s /usr/src/picaro/target/release/picaro /usr/local/bin/picaro

# A login shell (`bash -lc`, what `docker compose run --rm dev bash -lc 'cargo …'`
# uses) re-reads `/etc/profile`, which *resets* `PATH` and drops
# `/usr/local/cargo/bin`; restore it so the toolchain stays reachable.
RUN printf '%s\n' 'export PATH="/usr/local/cargo/bin:${PATH}"' \
    > /etc/profile.d/rust.sh

# `HOME` must be writable for msfvenom's cache; the packer's scratch directory
# is redirected off the baked-in (read-only) source tree, exactly as the
# one-shot `docker run` in the README does.
ENV HOME=/home/dev \
    PICARO_BUILD_DIR=/tmp/picaro-build

# Seed `/work/target` for the `picaro-target` named volume docker-compose.yml
# mounts there: Docker initialises a fresh volume from this image path, and
# Cargo (uid 1000) cannot write a root-owned one.
RUN mkdir -p /work/target && chown -R dev:dev /work

USER dev
WORKDIR /work
CMD ["/bin/bash"]

# ---------------------------------------------------------------------------
# Production image (the default `docker build` target).
FROM toolchain AS picaro

# The user mounts a directory with plans/payloads here; outputs land back on
# the host through the same mount.
WORKDIR /work
VOLUME ["/work"]

ENTRYPOINT ["/usr/src/picaro/target/release/picaro"]
CMD ["--help"]
