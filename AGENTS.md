# packerman — Agent Instructions

## What this project is

A malware loader packer for authorized red team engagements and security
research. Takes a PE file and a YAML config, produces a packed PE with
selected evasion techniques applied.

Intended use: lab environments, authorized audits, security research.
Any other use is out of scope and not supported.

## Architecture principles (non-negotiable)

- **Everything in Rust.** No C, no C++, no Nim. The stub is also Rust.
- **Compilers live in PATH.** Never embed toolchains in the repo.
  If `rustc` is missing, error out with clear instructions.
- **FFI via `windows-rs`.** No raw `extern "system"` unless absolutely
  necessary, and if so, encapsulated behind a safe wrapper.
- **Crypto: XChaCha20-Poly1305.** Both packer and stub. Nonce = 24 bytes.
  Crate: `chacha20poly1305`.
- **No unsafe in the packer.** Minimal, encapsulated unsafe is allowed
  only in the generated stub, for FFI.
- **Errors via `thiserror`.** Never `panic!` in user-facing code paths.
  Never `.unwrap()` outside tests.
- **`cargo clippy --all-targets` must be clean** before any commit.

## Coding conventions

- **Code, comments, doc comments, READMEs, commit messages: English.**
- **Personal notes, chat with the assistant, session memory: Spanish is fine.**
- Every new module ships with tests.
- Public functions get doc comments explaining *why*, not *what*.
- Test names describe behavior, not implementation.
- Prefer explicit over clever.

## Repo layout

```text
src/
  config/       YAML parsing and validation
  engine/       crypto, stub generation, compilation
  audit/        static measurement (pe_info, strings, yara, defender, report)
  techniques/   one directory per technique + the registry (mod.rs)
  error.rs      top-level error types
templates/
  stub/         Rust stub template with {{placeholders}}
examples/
  configs/      example YAMLs
  payloads/     test payloads for end-to-end verification
code_examples/  reference material (see below)
build/          (gitignored) intermediate artifacts
dist/           (gitignored) final packed binaries
```

Each technique lives under `src/techniques/<name>/` (README + stub fragment +
tests). The registry (`src/techniques/mod.rs`) is metadata-only; inspect it with
`packerman techniques {list,show,validate}`. Adding a technique is documented in
`src/techniques/README.md`.

## Current state

**Phase 5 complete.** Static measurement infrastructure:
- `packerman audit <binary>` reports header, sections + entropy, imports/exports,
  strings, YARA (stub) and an optional offline Defender scan.
- The process-hollowing binary's static baseline is documented in
  `docs/measurements/` and `.memory.md`.

**String obfuscation (done).** `payload.strings` (`strategy: xor|stack`,
`key: random|literal:<hex>`) obfuscates every stub string literal through
`src/engine/obfuscation.rs`. Replaces the old hardcoded XOR `0x5A`. Docs in
`docs/techniques/string_obfuscation.md`, measurements in
`docs/measurements/phase6_strings_{xor,stack}.md`.

**Technique categories + `patch_amsi` (done).** Techniques are now Preparation
vs Execution (`TechniqueDef.category`); a pipeline is `0..N` Preparation followed
by exactly one Execution. `patch_amsi` (T1562.001) is the first Preparation
technique. Validation in `src/config/validate.rs`; the stub renders into
`{{PREPARATION_BLOCKS}}` / `{{EXECUTION_BLOCK}}` (Preparation fragments are
wrapped in per-technique modules to avoid `use` collisions).

**Phase 6 planned.** Indirect syscalls.
See `.memory.md` for the rolling state.

## code_examples/ — how to use it

This directory contains reference implementations from public projects
(vx-underground, PEzor, RustPacker, etc.). Use it as REFERENCE, not as
code to paste.

Rules:
1. **Read it, understand it, then reimplement in our style.**
   Do not copy code verbatim unless it's clearly marked as reusable
   (MIT/CC0/public domain).
2. **Check licenses before copying anything.** If in doubt, don't copy,
   reimplement.
3. **Document provenance.** When a pattern clearly comes from a specific
   project, note it in a comment: `// Adapted from: <project> <URL>`.
4. **Never copy code we don't understand.** If it's not clear what a
   line does, ask before using it.

## Session workflow

At the **start** of a session:
- Read this file.
- Read `.memory.md` for the last session's state.

At the **end** of a session:
- Update `.memory.md` with what was done, open questions, and next steps.
- Keep it short (one screen max). It's a rolling log, not a journal.
