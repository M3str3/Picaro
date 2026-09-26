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
  engine/       crypto, stub generation, compilation, syscall layer
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

**YAML schema 4 (done).** The config document is schema 4; a document that
declares `schema: 3` (or the retired `schema: 1`/`schema: 2`) is rejected at
parse time with a migration hint (mappings in `docs/migration-v1-v3.md`,
`docs/migration-v2-v3.md` and `docs/migration-v3-v4.md`). A `runtime` entry is
`technique: <name>` plus an optional nested `params:` mapping (schema 3 kept the
parameters next to `technique:`); a technique with no parameters omits
`params:`. Unknown keys inside a runtime entry are ignored by serde, so a
half-migrated flat entry silently falls back to the technique's defaults
(`process_hollowing` then hollows `svchost.exe`). `build` has exactly three
blocks: `payload` (`source` + `crypto`), `stub` (`path`/`syscalls`/`strings`)
and `output`; `build.output.arch` is `x64` only (`x86` is recognized but
rejected in validation as not integrated yet). String obfuscation lives at
`build.stub.strings` (it only ever affected stub literals). Build args move from
`$build.N$` to `$arg.N$` (`$arg.0$`, `$arg.1$`, or a named `$arg.foo$` from a
`foo=value` CLI arg); the stub still accesses already-resolved args as
`$ARG_<key>$`. The old `InputConfig`/`LoaderConfig` are gone
(`src/config/schema.rs`); `PipelineStep` is renamed `RuntimeStep`
(`src/techniques/mod.rs`). `build.payload.source` is a single string:
`http(s)://` is fetched in memory, `file://` is read from disk, `ftp://` is
rejected, anything else is a local path.

**Payload import resolution (done).** New `src/engine/imports.rs` renders
`$IMPORTS_BLOCK$`: one `resolve_imports(image, import_rva, import_size,
RVA→offset)` walk that loads each imported DLL (`LoadLibraryA`; API set names
are resolved by the OS loader, with a CRT/`kernel32` family fallback) and
returns `(IAT RVA, address)` pairs. Gated by `TechniqueDef.resolves_imports`
(both execution techniques). `process_hollowing` patches the payload's IAT after
relocations and before writing the image (failures abort before
`SetThreadContext`); `reflective_loading`'s duplicated `fix_imports` was
replaced by the shared resolver. The hollowing fragment now uses a 16-byte
aligned `CONTEXT` for `Get/SetThreadContext` (x64 requirement).

**Process hollowing still does not run a full PE — see Known limitations.**
A `CREATE_SUSPENDED` target has not run its loader (`PEB->Ldr == NULL`; only
`ntdll` + the main image mapped), so the payload's imported DLLs are absent.
Measured evidence + proposed follow-up: `docs/techniques/process_hollowing.md`.

**Phase 6a: indirect syscalls (Hell's Gate) done.** New `build.stub.syscalls`
block (`mode: none|indirect`, `resolver: hells_gate`; defaults
`none`/`hells_gate`).
It is a *loader* config, not a pipeline technique. The stub template gains
`$SYSCALLS_BLOCK$`, rendered by `src/engine/syscalls.rs` from the union of
`TechniqueDef::syscalls` requirements (only `process_hollowing` opts in for
now: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`,
`NtResumeThread`, `NtUnmapViewOfSection`). Technique fragments always call the
`nt_*` helpers (`crate::nt_alloc_vm`, ...) — `mode: none` maps them to the
Win32 APIs, `mode: indirect` resolves SSNs at runtime (prologue
`4C 8B D1 B8 ?? ?? ?? ??` via `GetProcAddress`) and invokes the kernel through
the first `syscall; ret` gadget in ntdll's `.text` (a `global_asm!` trampoline,
`nt_invoke`; signature + stack-shuffle documented in the generated code).
Verified on `x86_64-pc-windows-msvc` (rustc 1.90, `-C target-feature=+crt-static`
works). All Nt*/DLL names go through `StringsConfig`. IAT after indirect:
`VirtualAllocEx`/`WriteProcessMemory`/`ReadProcessMemory`/`ResumeThread` gone,
`NtUnmapViewOfSection` string gone. Docs: `docs/techniques/indirect_syscalls.md`,
`docs/measurements/phase6a_iat_reduction.md`. Not done (by design): Tartarus
Gate (6b), reflective_loading/patch_amsi migration, stack spoofing, unhooking (7).

**Phase 5 complete.** Static measurement infrastructure:
- `batesian audit <binary>` reports header, sections + entropy, imports/exports,
  strings, YARA (stub) and an optional offline Defender scan.
- The process-hollowing binary's static baseline is documented in
  `docs/measurements/` and `.memory.md`.

**String obfuscation (done).** `build.stub.strings` (`strategy: xor|stack`,
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

**Custom loader stubs (done).** A YAML `build.stub.path` replaces the builtin
stub with a user `.rs` template rendered through the same substitution engine
(see `docs/custom-stubs.md`); `build.stub` may be set for `syscalls`/`strings`
alone.
Placeholders use the `$X$` delimiter (`$PAYLOAD_BYTES$`, `$PAYLOAD_LEN$`,
`$PAYLOAD_NONCE_DEF$`, `$PAYLOAD_KEY_DEF$` (embedded only when referenced),
`$PREPARATION_BLOCKS$`, `$SYSCALLS_BLOCK$`, `$EXECUTION_BLOCK$`, `$ARG_<key>$`;
YAML build args are `$arg.N$`). The stub must define `fn main()`; ignoring the
technique blocks is a warning, not an error (a custom stub that skips
`$SYSCALLS_BLOCK$` while declaring syscall-using techniques also warns). Build
args are the positional args plus optional `name=value` pairs (no separate
`--arg` flag). `$X$` is invalid Rust, so `rustfmt` cannot rewrite it; never go
back to `{{X}}` (valid Rust — `rustfmt` reformats it into nested blocks and
silently breaks substitution). See `.memory.md` for the rolling state.

**Phase 8: `bouncer` environment gate (done).** New
`src/techniques/bouncer/` Preparation technique (T1497.001, T1614.001,
Experimental): it checks the current host and aborts the pipeline before the
payload runs when the declared requirements are not met. All fields are
optional and each activates one check — `hostname`/`username`/`domain`
(case-insensitive globs), `language` (BCP-47), `keyboard` (4-digit layout
codes), `not_in_vm` (CPUID hypervisor leaves), `not_in_sandbox` (aggregate
heuristic, threshold 3), `min_uptime_min`, `min_ram_mb`; `mode: all|any`
combines them and `on_fail: silent|exit` picks the rejection behaviour. No
field declared is a no-op (surfaced by `config::validate::advisories` and
printed as a build warning). **Preparation contract change:** a preparation now
returns `Result<bool, E>` — `Ok(true)` continues, `Ok(false)` aborts — so
the generated `run_preparations` returns `Result<bool, String>` and the builtin
template exits `0` on `false`; `patch_amsi`/`patch_etw`/`anti_debug`/
`sleep_obfuscation` return `Ok(true)`, and `on_fail: exit` calls
`std::process::exit(1)` from the fragment. New `SENSITIVE_LITERALS`
(`vboxservice`, `vmwaretray`, `vmtoolsd`, `wireshark`, `procmon`, `x64dbg`,
`x32dbg`, `sandbox`, `malware`, `analysis`). Every check literal, every
analysis process name and every hypervisor vendor token goes through
`StringsConfig`. Docs: `src/techniques/bouncer/README.md`,
`docs/measurements/phase8_bouncer.md`; examples
`examples/configs/test-bouncer{,-miss,-full}.yaml`. Not done (by design):
`on_fail: decoy` and checks outside the documented list.

**Interactive build (done).** `batesian build interactive <payload>`
(`src/wizard.rs`) asks the questions a schema-4 YAML encodes — name/args, the
execution technique, preparation techniques plus their parameters, the stub
(`strings`/`syscalls`) and the output — assembles a `Config`, prints it and
writes it, then hands the file to the normal build, so the written YAML is the
source of truth and `batesian build <file>` reproduces the artifact.
`--config-out` sets the path (default `dist/<name>.yaml`). `build` gained an
optional `interactive` subcommand (`subcommand_precedence_over_arg`), so `CONFIG`
is now optional and validated in `run`. A technique the wizard has no prompts for
falls back to parsing its `params_example`, so a newly registered technique still
works before its questions exist. Prompts are `Prompter<R: BufRead, W: Write>`,
which keeps the whole session testable; output uses `ui::Palette`
(`question`/`menu`/`glyph::ASK` were added) and `techniques::summary` is now
public so the wizard and `techniques list` share wording. Not prompted yet:
`strings.key`, `build.stub.path`, `args_mode: override`, non-default
`sleep_obfuscation` regions.

## Known limitations

- **`x86` is parsed but rejected.** `Arch::X86` exists so the enum is complete,
  but `config::validate` rejects it: the stub toolchain only produces x64, and
  adding x86 means a 32-bit stub variant plus a per-architecture fragment for
  every technique.

- **`bouncer` is a fragile gate by construction.** `not_in_sandbox` combines
  five indicators and rejects at a score of 3, deliberately preferring false
  negatives (the payload runs where it should not) over false positives (it does
  not run on the target). The full gate's added imports (`GetComputerName*`,
  `GetUserNameW`, `GetUserDefaultLocaleName`, `GetKeyboardLayout*`,
  `CreateToolhelp32Snapshot`, `GetSystemInfo`, `GlobalMemoryStatusEx`) are the
  visible static signature; the check literals themselves stay obfuscated.

- **Process hollowing does not run a full PE even with the IAT fixed.** The
  payload's IAT is now resolved (`src/engine/imports.rs`), but a
  `CREATE_SUSPENDED` target has not run its loader (`PEB->Ldr == NULL`; only
  `ntdll` + the main image are mapped), so the payload's other imported DLLs
  (`kernel32`, `user32`, …) are absent and the first import call jumps to
  unmapped memory (`0xC0000005`). Letting the target's loader initialize the
  swapped-in image fails (`0xC0000142`) even for a bare `jmp $` entry, and
  manually mapped images never get an OS TLS slot (Rust payloads then abort
  with `0xC0000409`). Provisioning loader/TLS state before hand-off is the
  follow-up; evidence in `docs/techniques/process_hollowing.md`.
- Custom stubs do not obfuscate the key/nonce by default. If the custom stub
  uses `$PAYLOAD_KEY_DEF$` / `$PAYLOAD_NONCE_DEF$`, the values land in `.rdata`.
  Use `$PAYLOAD_KEY_DEF_OBFUSCATED$` when available, or read the key at runtime
  (see `examples/stubs/runtime-key.rs`).
- Phase 6a only migrates the hollowing calls. `GetThreadContext`/
  `SetThreadContext`/`WaitForSingleObject`/`GetExitCodeProcess` and the
  reflective-loading APIs still import statically.
- Windows Defender flags the packed artifacts (unavoidable); the dev machine
  had it disabled during the 6a runtime tests.

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
