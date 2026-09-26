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
  engine/       crypto, stub generation, compilation, syscall layer,
                resources, manifest, hash
  audit/        static measurement (pe_info, strings, yara, defender, report)
  techniques/   one directory per technique + the registry (mod.rs)
  error.rs      top-level error types
  ui.rs         terminal output: banner, palette, formatting helpers
templates/
  stub/         Rust stub template with $placeholders$
examples/
  configs/      curated example YAMLs
  payloads/     test payloads for end-to-end verification
tests/
  configs/      CI / validation fixtures
  fixtures/     committed PE fixtures
docs/           docs source (mkdocs.yml lives at the root)
build/          (gitignored) intermediate artifacts
dist/           (gitignored) final packed binaries
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

**Process hollowing runs a full PE (TLS callbacks pending) — see Known
limitations.** The loader state is reconstructed (imported DLLs, TLS index +
per-thread template + main-thread slot, `Rip` hand-off) and the Rust test payload
exits `0`. A relocation bug (DIR64/HIGHLOW swapped in the fragment) was the real
blocker. Measured evidence + the remaining callback work:
`docs/techniques/process_hollowing.md`. Every diagnostic the fragment emits is
obfuscated (`MESSAGES` + `render_fragment`), so no error text — and no technique
keyword such as `loader` — reaches `.rdata`. `reflective_loading`'s shellcode
fragment and the other five techniques still carry cleartext (keyword-free)
diagnostics through `thiserror`.

**Phase 6: indirect syscalls done.** New `build.stub.syscalls` block
(`mode: none|indirect`, `resolver: hells_gate|tartarus_gate|api_hash`; defaults
`none`/`hells_gate`). It is a *loader* config, not a pipeline technique. The
stub template gains `$SYSCALLS_BLOCK$`, rendered by `src/engine/syscalls.rs`
from the union of `TechniqueDef::syscalls` requirements. Technique fragments
always call the `nt_*` helpers (`crate::nt_alloc_vm`, ...) — `mode: none` maps
them to the Win32 APIs, `mode: indirect` resolves SSNs at runtime and invokes
the kernel through the first `syscall; ret` gadget in ntdll's `.text` (a
`global_asm!` trampoline, `nt_invoke`, with eleven argument slots). `syscall`
pushes no return address, so the kernel reads arguments 5+ from exactly the slots
the x64 ABI already put them in; the shim only sets `r10`/`eax`/`r11` and jumps
to the gadget). Three resolvers:
- **Hell's Gate (6a)** reads each SSN from the live Nt* stub prologue
  (`4C 8B D1 B8 ?? ?? ?? ??` via `GetProcAddress`); a hooked prologue is
  `PatternMismatch`.
- **Tartarus Gate (6b)** reads each SSN from a clean copy of ntdll read from
  disk (`std::fs::read` + a file-export walk + RVA→file-offset), so hooks in the
  live export stubs do not hide the SSN; the gadget still comes from live ntdll.
- **API hashing (6c)** walks the same clean copy but matches each export by a
  precomputed FNV-1a 64-bit hash of its name (`engine::syscalls::api_hash`,
  mirrored in the stub), so neither `GetProcAddress` nor any Nt* name string is
  needed; the PE-file helpers are shared with Tartarus via `$FILE_PE_HELPERS$`.

Verified on `x86_64-pc-windows-msvc` (rustc 1.90, `-C target-feature=+crt-static`
works). All Nt*/DLL names and the Tartarus path go through `StringsConfig`.
IAT after indirect: `VirtualAllocEx`/`WriteProcessMemory`/`ReadProcessMemory`/
`ResumeThread`/`VirtualAlloc`/`VirtualProtect`/`IsDebuggerPresent`/
`CheckRemoteDebuggerPresent`/`GetThreadContext` gone. Docs:
`docs/techniques/indirect_syscalls.md`, `docs/measurements.md`.

**Techniques migrated to the `nt_*` helpers.** `process_hollowing`
(`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`,
`NtResumeThread`, `NtUnmapViewOfSection`, `NtProtectVirtualMemory`,
`NtSuspendThread`, `NtQueryInformationProcess`, `NtQueryInformationThread`,
`NtGetContextThread`, `NtSetContextThread`, `NtCreateThreadEx`,
`NtWaitForSingleObject`, `NtClose`), `reflective_loading`
(`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`), `patch_amsi`/`patch_etw`
(`NtProtectVirtualMemory`) and `anti_debug` (`NtQueryInformationProcess`,
`NtGetContextThread`). The trampoline carries eleven arguments, so
`NtCreateThreadEx` (which replaced `CreateRemoteThread`) fits; `CreateProcessA`,
`LoadLibraryA`/`GetProcAddress` and `TlsAlloc`/`TlsSetValue` stay Win32 (loader
entry points, not syscalls the stub issues).
Not done (by design): stack spoofing, unhooking (7), and the payload's TLS
*callbacks* under hollowing (a never-started thread has no TLS array to point
at).

**Phase 5 complete.** Static measurement infrastructure:
- `batesian audit <binary>` reports header, sections + entropy, imports/exports,
  strings, YARA (stub) and an optional offline Defender scan.
- The process-hollowing binary's static baseline is documented in
  `docs/measurements.md` and `.memory.md`.

**String obfuscation (done).** `build.stub.strings` (`strategy: xor|stack`,
`key: random|literal:<hex>`) obfuscates every stub string literal through
`src/engine/obfuscation.rs`. Replaces the old hardcoded XOR `0x5A`. Docs in
`docs/techniques/string_obfuscation.md`, measurements in `docs/measurements.md`.

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
`theme), and the secondary slate tone is bright enough to read on dark. The
banner (the `BANNER` literal in `src/ui.rs`) is printed before every subcommand,
followed by the dim tagline (`mimicry-based packer · vX.Y.Z`); `-q`/`--quiet`
skips it. `build` and `audit` open with a
`▸ batesian <cmd> · <target>` echo; `build` logs `✓` steps with compact
path/size detail and a green result line, while `-v`/`--verbose` adds a
resolved-config block plus per-step detail (template, marker, rustc path,
timings); `audit` renders the redesigned report (metadata bar, entropy gauges,
uppercase headings, colored `LOW/MEDIUM/HIGH RISK`); `techniques list` is a
colored table.

**Phase 6 done.** Indirect syscalls (see the “Phase 6” entry above).

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

**Payload formats (done).** `build.payload.format: pe|shellcode|dll` (default
`pe`) plus an optional `build.payload.export` (a DLL's exported entry point;
rejected unless `format: dll`). `src/engine/pe.rs` gained the file-header
`characteristics` and `is_dll()`; `src/main.rs` validates the input per format
(`pe`/`dll` must be the matching x64 PE image, `shellcode` only non-empty) in
`inspect_payload`, shared by `build` and `--dry-run`. The format and export
reach the Execution fragment through `RuntimeStep::render_fragment(strings,
format, export)` → `Params::render_fragment_for`; `reflective_loading` ships two
fragments (`stub_fragment.rs` PE mapper, `stub_fragment_shellcode.rs` runner)
and, for a DLL export, calls `DllMain(DLL_PROCESS_ATTACH)` before invoking the
export with no arguments (both `SHELLCODE_FRAGMENT` and the placeholder
substitution are tested). `process_hollowing` only runs `pe`;
`config::validate` rejects the other formats with a pointer to
`reflective_loading`. DLL/shellcode payloads run in-process, so
`patch_command_line()` still delivers `build.payload.args` through the PEB.
Examples: `examples/configs/shellcode.yaml` (+ `examples/payloads/demo_shellcode.bin`,
`mov eax, 42; ret`). Verified end to end on Windows (shellcode exits 42; a Rust
cdylib export ran and wrote its file). The `dll` format ships no example (the old
`test-dll.yaml` pointed at a payload that was never committed). Wizard/`--dry-run`
do not prompt for the format yet (edit the YAML).

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
`docs/measurements.md`; examples `tests/configs/bouncer.yaml` and
`tests/configs/bouncer-miss.yaml`. Not done (by design): `on_fail: decoy` and
checks outside the documented list.

**Interactive build (done).** `batesian build interactive <payload>`
(`src/wizard.rs`) asks the questions a schema-4 YAML encodes — name/args, the
execution technique, preparation techniques plus their parameters, the stub
(`strings`/`syscalls`) and the output — assembles a `Config`, prints it and
writes it, then hands the file to the normal build, so the written YAML is the
source of truth and `batesian build <file>` reproduces the artifact.
`--config-out` sets the path (default `dist/<name>.yaml`). `build` gained an
optional `interactive` subcommand (`subcommand_precedence_over_arg`), so `CONFIG`
is now optional and validated in `run`. Prompts are a `Prompt` trait with two
backends: `InquirePrompt` (arrow-key menus, checkbox multi-select, confirmations;
the `inquire` crate) when stdin/stdout is a terminal, and `LinePrompt` (plain
line reader) otherwise — so the session is scriptable in tests. A final **review**
screen (`build now` / `edit answers` / `quit`) re-asks the questions with the
previous answers as defaults; `Esc` cancels via a new `PackerError::Cancelled`
(exit 0). A technique the wizard has no prompts for falls back to parsing its
`params_example`. `ui.rs` gained `question`/`menu`/`glyph::ASK`; `techniques::summary`
is now public so the wizard and `techniques list` share wording. **Compiler fix:**
`windows_crate_version` resolves the import-lib version through
`windows` → `windows-targets` → the per-arch crate, because a second
`windows-targets` (e.g. `windows-sys 0.48` via `inquire`'s `crossterm`/`mio`)
made the old "first match" pick the wrong `windows_x86_64_msvc`. Not prompted
yet: `strings.key`, `build.stub.path`, `args_mode: override`, non-default
`sleep_obfuscation` regions.

**PE resources (done).** `build.output.resources` embeds an icon (`RT_GROUP_ICON`
+ `RT_ICON`), `VERSIONINFO` (`RT_VERSION`) and the Windows application manifest
(`RT_MANIFEST`, UAC/DPI) into the artifact. All generated in Rust — no
`rc.exe`/`windres`, so the build stays cross-platform. `src/engine/resources/`
(`tree.rs` directory builder, `icon.rs`, `version.rs`, `manifest.rs`, plus
`inject.rs` which appends a `.rsrc` section to the compiled stub). Directory
offsets are section-relative, but `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` is an
image RVA — that is why `embed()` resolves the RVA before building the blob.
Verified against `FindResource`/`LoadResource` and `version.dll`
(`GetFileVersionInfo`/`VerQueryValue`) on Windows. Example:
`tests/configs/resources.yaml`, asset `examples/assets/sample.ico`.
Note the name clash: `build.output.manifest` (bool) is the provenance JSON;
`build.output.manifest` is **not** the embedded manifest — that is
`build.output.resources.manifest`.

**Signing + subsystem (done).** `build.output.sign` signs the artifact with
`signtool.exe` (`src/engine/signing.rs`) after resources are embedded and before
the manifest, in three modes: `lab` (an automatic CA + leaf — a self-signed
`<subject> Root CA` in `Cert:\CurrentUser\My` via PowerShell, plus a
code-signing leaf signed by it; the CA's public cert is exported next to the
artifact as `<stem>.ca.cer` and **no trust store is modified**: the lab installs
that file in its own Trusted Root), `store` (an existing cert by
`thumbprint`/`subject`) and `file` (a `.pfx`; password from `password_env`, never
the YAML). `signtool` is discovered in PATH → `BATESIAN_SIGNTOOL` → Windows Kits
(`...\Windows Kits\10\bin\<ver>\x64`) → `output.sign.signtool`. Optional
`timestamp_url` (RFC 3161). `src/engine/identity.rs` generates plausible metadata
when `output.resources.version_info.randomize: true` (company/product/
description/versions/copyright; explicit fields win), and the generated company
becomes the lab certificate subject when none is set, so the artifact and the
signature agree. The manifest records `signature.{mode,subject,issuer,thumbprint,
ca_file}` and the resolved `version_info`. `build.output.subsystem`
(`console`|`windows`) prepends `#![windows_subsystem = "windows"]` to the
rendered stub (skipped if the stub sets its own). A lab signature verifies only
where its CA is trusted; it gives no SmartScreen reputation.
`.pfx`/`.p12`/`.pem`/`.key` are gitignored. Example:
`examples/configs/mimikatz.yaml` (randomized identity + lab signature).

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

- **Process hollowing runs a full PE, but not its TLS callbacks.** The IAT
  (`src/engine/imports.rs`), the imported DLLs, the TLS index/block/slot and the
  `Rip` hand-off are all provisioned, so a Rust payload completes (exit `0`).
  What is still missing is running the payload's `DLL_PROCESS_ATTACH` TLS
  callbacks: a callback needs a thread, and a never-started thread has no TLS
  array in its TEB to point a slot at (writing one faults the target). Either
  run them on the main thread (parked on a `jmp $` stub between calls) or build
  the callback thread's TLS array by hand. Evidence in
  `docs/techniques/process_hollowing.md`.
- Custom stubs do not obfuscate the key/nonce by default. If the custom stub
  uses `$PAYLOAD_KEY_DEF$` / `$PAYLOAD_NONCE_DEF$`, the values land in `.rdata`.
  Use `$PAYLOAD_KEY_DEF_OBFUSCATED$` when available, or read the key at runtime
  (see `examples/stubs/runtime-key.rs`).
- `GetThreadContext`/`SetThreadContext` (process hollowing's loader hand-off),
  `WaitForSingleObject`/`GetExitCodeProcess` (reflective loading) and
  `CreateRemoteThread`/`CreateThread` still import statically: `NtCreateThreadEx`
  takes eleven arguments, more stack arguments than the indirect trampoline
  currently shuffles.
- Windows Defender flags the packed artifacts (unavoidable); the dev machine
  had it disabled during the 6a runtime tests.

## Session workflow

At the **start** of a session:
- Read this file.
- Read `.memory.md` for the last session's state.
- The docs are a Material for MkDocs site (`mkdocs.yml`, `docs_dir: docs`); the
  nav lives in `mkdocs.yml`. Preview with `python scripts/docs.py` (runs the
  official container; standard library only) or `mkdocs serve`.

At the **end** of a session:
- Update `.memory.md` with what was done, open questions, and next steps.
- Keep it short (one screen max). It's a rolling log, not a journal.
