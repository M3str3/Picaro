# Architecture

## What this project is

A malware loader packer for authorized red team engagements and security
research. It takes a PE and a YAML config, produces a packed PE with selected
evasion techniques applied.

Intended use: lab environments, authorized audits, security research. Any other
use is out of scope.

## Phases

| Phase | State | Scope |
|---|---|---|
| 1 | done | CLI + YAML parsing + validation |
| 2 | done | XChaCha20-Poly1305 payload encryption |
| 3 | done | Rust stub generation + `rustc` compilation |
| 4 | done | Process hollowing (in-memory execution) |
| 5 | done | Static measurement infrastructure (`audit`) |
| 6 | planned | Indirect syscalls |
| 7 | in progress | AMSI patching (`patch_amsi`), technique categories |

## Pipeline (build)

```
packerman build config.yaml
    │
    ├─ 1. Parse YAML, substitute build args, validate   (src/config)
    ├─ 2. Read (file or URL) + validate payload PE      (src/engine/pe, src/engine/fetch)
    ├─ 3. Encrypt payload              (src/engine/crypto, XChaCha20-Poly1305)
    ├─ 4. Render Rust stub             (src/engine/stub, templates/stub/main.rs.tpl)
    ├─ 5. Compile stub with rustc      (src/engine/compiler, --extern from target/)
    └─ 6. Copy to output path
```

The stub (generated) decrypts the payload in memory and runs it via process
hollowing. No cleartext payload touches disk.

## Technique pipeline model

Each technique is categorized as Preparation or Execution
(`src/techniques/mod.rs`):

- **Preparation** — modifies the current process state (e.g. `patch_amsi`) but
  never runs the payload.
- **Execution** — runs the decrypted payload (`process_hollowing`,
  `reflective_loading`).

The pipeline must contain `0..N` Preparation techniques followed by exactly one
Execution technique. Validation (`src/config/validate.rs`) rejects a pipeline
with zero or multiple Execution techniques, or any Preparation technique placed
after the Execution technique.

The stub renders the pipeline into two placeholders:

- `$PREPARATION_BLOCKS$` — the Preparation fragments, each wrapped in its own
  module (so their `use` statements cannot collide), plus a generated
  `run_preparations()` dispatcher that calls each one in order.
- `$EXECUTION_BLOCK$` — the single Execution fragment, injected at the top
  level (it provides `execute_payload`).

`run()` calls `run_preparations()?` before `execute_payload(&mut image)`.

## Pipeline (audit)

```
packerman audit binary [--focus sections]
    │
    ├─ PE header + sections + entropy  (src/audit/pe_info)
    ├─ imports / exports              (src/audit/pe_info)
    ├─ strings scan                   (src/audit/strings)
    ├─ YARA (stub)                    (src/audit/yara)
    ├─ Defender offline scan          (src/audit/defender)
    └─ report                         (src/audit/report)
```

## Repo layout

```text
src/
  config/     YAML parsing and validation
  engine/     crypto, pe parsing, stub generation, compilation
  audit/      static measurement (pe_info, strings, yara, defender, report)
  techniques/ one directory per technique + the registry (mod.rs)
  error.rs    top-level error types
templates/
  stub/       Rust stub template with $placeholders$
examples/
  configs/    example YAMLs
  payloads/   test payloads
yara/         YARA rules (empty for now)
docs/         measurements + this file
code_examples/  third-party reference material
build/        (gitignored) intermediate artifacts
dist/         (gitignored) final packed binaries
```

## Key decisions

- **Everything in Rust** (packer and stub).
- **Crypto**: XChaCha20-Poly1305 (24-byte nonce), crate `chacha20poly1305`.
- **Stub compilation**: bare `rustc` with `--extern` pointing at the `.rlib`
  files under `target/`. `-C lto=fat` was dropped because cargo-built `.rlib`
  files lack bitcode.
- **Windows FFI**: `windows-rs` (`windows` crate). `NtUnmapViewOfSection` is
  resolved dynamically from `ntdll.dll` (windows-rs does not export it).
- **Errors**: `thiserror`, no `panic!`/`unwrap` in the packer.
- **Input sources**: a local `path` or a remote `url` (fetched in memory via
  `ureq`, never written to disk). `$build.N$` placeholders in the YAML are
  resolved from positional CLI arguments before validation.
- **Static evasion** (phase 5) is measured with `packerman audit` so each later
  technique's impact can be quantified against a known baseline.

## Cross-compilation from Linux

When `packerman` runs on Linux/WSL, the stub is cross-compiled to
`x86_64-pc-windows-gnu` instead of natively. Two extra `-L` flags are required
and are easy to forget:

- `-L native=<...>/windows_x86_64_gnu-<ver>/lib` — `windows-rs` links via
  `raw-dylib` against `libwindows.0.52.0.a`, an import library provided by the
  `windows_x86_64_gnu` crate. On Windows this is `windows_x86_64_msvc` instead.
- `-L dependency=<target/{debug,release}/deps>` (the *host* deps) — the
  `windows-rs` proc-macros (`windows-implement`, `windows-interface`) are
  compiled for the host, not for the cross target.

Without the first, linking fails with `cannot find -lwindows.0.52.0`; without
the second, compilation fails with `can't find crate for windows_implement`.
