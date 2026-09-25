# batesian — Agent Instructions

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
- **No string literals in stub fragments.** Every string that ends up in the
  generated stub must go through `StringsConfig::obfuscate`. The packer's
  `render_fragment` receives `&StringsConfig` for exactly this reason. Literals
  that never reach the generated stub (compile-time constants, format strings
  in build-time code) are exempt.
- **`cargo clippy --all-targets` must be clean** before any commit.

## Coding conventions

- **Code, comments, doc comments, READMEs, commit messages: English.**
- **Personal notes, chat with the assistant, session memory: Spanish is fine.**
- Every new module ships with tests.
- Public functions get doc comments explaining *why*, not *what*.
- Test names describe behavior, not implementation.
- Prefer explicit over clever.
- **User-facing output goes through `src/ui.rs`.** Use `Palette` (`banner`,
  headings, `field`/`step`/`done`) instead of hand-written ANSI escapes or
  ad-hoc formatting; color degrades to plain text when redirected.
- When adding a technique, grep the fragment for `"` before committing. If the
  string is used at runtime by the stub, it must come from `StringsConfig`.

## Repo layout

```text
src/
  config/       YAML parsing and validation
  engine/       crypto, stub generation, compilation
  audit/        static measurement (pe_info, strings, yara, defender, report)
  techniques/   one directory per technique + the registry (mod.rs)
  error.rs      top-level error types
  ui.rs         terminal output: banner, palette, formatting helpers
templates/
  stub/         Rust stub template with $placeholders$
examples/
  configs/      example YAMLs
  payloads/     test payloads for end-to-end verification
code_examples/  reference material (see below)
build/          (gitignored) intermediate artifacts
dist/           (gitignored) final packed binaries
banner.txt      ASCII banner, compiled in by src/ui.rs
```

Each technique lives under `src/techniques/<name>/` (README + stub fragment +
tests). The registry (`src/techniques/mod.rs`) is metadata-only; inspect it with
`batesian techniques {list,show,validate}`. Adding a technique is documented in
`src/techniques/README.md`.

## Current state

**Phase 5 complete.** Static measurement infrastructure:
- `batesian audit <binary>` reports header, sections + entropy, imports/exports,
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
`$PREPARATION_BLOCKS$` / `$EXECUTION_BLOCK$` (Preparation fragments are
wrapped in per-technique modules to avoid `use` collisions).

**String-leak consolidation (done).** Every runtime literal in every stub
fragment goes through `StringsConfig` (`patch_amsi`, `process_hollowing`
included). `audit` reports a `Sensitive:` line (`SENSITIVE_LITERALS`) and blanks
the import table's own DLL/function-name strings (`import_text_ranges`) so those
are not false positives. The `#[ignore]` test
`no_sensitive_literals_in_generated_stubs` is the CI safety net: it flags a
literal only when it is in the compiled stub **and** in the generated stub
source (comments stripped) — a binary hit alone can come from the toolchain
(e.g. `windows-result` ships `ntdll.dll`).

**CLI UX, app renamed to `batesian` (done).** The crate, binary and CLI are
`batesian` (previously `husk`, originally `packerman`). UX lives in `src/ui.rs`:
a truecolor `Palette` with a soft violet brand accent, clear green/yellow/red
status colors and a steel blue for targets (color auto-disabled when not a
terminal, plus `NO_COLOR`/`--no-color`). Legibility rules: primary values use
the terminal's default foreground (a fixed light gray vanishes on a light
theme), and the secondary slate tone is bright enough to read on dark. The
banner (`banner.txt`) is printed before every subcommand, followed by the dim
tagline (`mimicry-based packer · vX.Y.Z`); `-q`/`--quiet` skips it. `build` and `audit` open with a
`▸ batesian <cmd> · <target>` echo; `build` logs `✓` steps with compact
path/size detail and a green result line, while `-v`/`--verbose` adds a
resolved-config block plus per-step detail (template, marker, rustc path,
timings); `audit` renders the redesigned report (metadata bar, entropy gauges,
uppercase headings, colored `LOW/MEDIUM/HIGH RISK`); `techniques list` is a
colored table.

**Phase 6 planned.** Indirect syscalls.

**Custom loader stubs (done).** A YAML `loader:` block (`loader.path`) replaces
the builtin stub with a user `.rs` template rendered through the same
substitution engine (see `docs/custom-stubs.md`). Placeholders use the `$X$`
delimiter (`$PAYLOAD_BYTES$`, `$PAYLOAD_LEN$`, `$PAYLOAD_NONCE_DEF$`,
`$PAYLOAD_KEY_DEF$` (embedded only when referenced), `$PREPARATION_BLOCKS$`,
`$EXECUTION_BLOCK$`, `$ARG_<n>$`; YAML build args are `$build.N$`). The stub must
define `fn main()`; ignoring the technique blocks is a warning, not an error.
Build args reuse the existing `$build.N$` positional mechanism (no separate
`--arg` flag). `$X$` is invalid Rust, so `rustfmt` cannot rewrite it; never go
back to `{{X}}` (valid Rust — `rustfmt` reformats it into nested blocks and
silently breaks substitution).
See `.memory.md` for the rolling state.

## Known limitations

- Custom stubs do not obfuscate the key/nonce by default. If the custom stub
  uses `$PAYLOAD_KEY_DEF$` / `$PAYLOAD_NONCE_DEF$`, the values land in `.rdata`.
  Use `$PAYLOAD_KEY_DEF_OBFUSCATED$` when available, or read the key at runtime
  (see `examples/stubs/runtime-key.rs`).

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
