# picaro — Agent Instructions

## What this project is

A malware loader packer for authorized red team engagements and security
research. Takes a PE file and a YAML plan, produces a packed PE with
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
  plan/       YAML parsing and validation
  engine/       crypto, stub generation, compilation, syscall layer,
                resources, manifest, hash
  audit/        static measurement (pe_info, strings, yara, defender, report)
  techniques/   one directory per technique + the registry (mod.rs)
  error.rs      top-level error types
  ui.rs         terminal output: banner, palette, formatting helpers
templates/
  stub/         Rust stub template with $placeholders$
examples/
  plans/      curated example YAMLs
  payloads/     test payloads for end-to-end verification
  stubs/        custom stub templates (build.stub.path)
  assets/       sample icon for build.output.resources
tests/
  plans/      CI / validation fixtures
  fixtures/     committed PE fixtures
scripts/        Docker wrappers (picaro.py, docs.py)
yara/           YARA rules (engine not wired yet)
docs/           docs source (mkdocs.yml lives at the root)
build/          (gitignored) intermediate artifacts
dist/           (gitignored) final packed binaries
code_examples/  (gitignored) local reference scratch
```

Each technique lives under `src/techniques/<name>/` (README + stub fragment +
tests). The registry (`src/techniques/mod.rs`) is metadata-only; inspect it with
`picaro techniques {list,show,validate}`. Adding a technique is documented in
`src/techniques/README.md`.

## Current state

**Multi-stage plans (schema 5, done).** `schema: 5` adds an ordered top-level
`stages:` list so one artifact delivers several payloads. A stage is an action:
`technique` (an embedded payload + its own pipeline, the single-payload shape
generalized), `exec` (launch a process — a living-off-the-land binary or any
command) or `sleep`. `build.payload` is now **optional**: a schema-4 document
(accepted unchanged) is the single-payload shorthand and normalizes to one
`technique` stage (`src/plan/stages.rs`); a stages-only plan omits it. The
multi-stage build path renders `templates/stub/main_stages.rs.tpl` via
`src/engine/stages.rs`: each payload is embedded and encrypted with its own
key/nonce, each stage's pipeline is wrapped in `mod stage_<index>` (so two
stages can reuse a technique without colliding), and a generated runner walks
the stages with the declared gating (`on_success`/`on_fail`/`delay_ms`). The
single-payload path is **unchanged** (still `main.rs.tpl`, byte-identical
output). **The rule that shapes it:** a chain only continues if the loader gets
control back, so `reflective_loading` of a PE *executable* and `dotnet_hosting`
are *terminal* and must be the last stage (`plan::validate` rejects them
otherwise); `exec`, `process_hollowing` and `reflective_loading` of a DLL
always return. `api_resolution.mode: proxy` is rejected on multi-stage (it is
loader-wide). Known limits: per-stage payload args and a stages-aware manifest
are follow-ups; two reflectively loaded EXEs cannot chain without an
`ExitProcess` interceptor. Docs: `docs/multistage.md`; example:
`examples/plans/multistage.yaml`.

**YAML schema 4 (done).** The plan document is schema 4; a document that
declares `schema: 3` (or the retired `schema: 1`/`schema: 2`) is rejected at
parse time with a migration hint (mappings in `docs/migration-v1-v3.md`,
`docs/migration-v2-v3.md` and `docs/migration-v3-v4.md`). A `runtime` entry is
`technique: <name>` plus an optional nested `params:` mapping (schema 3 kept the
parameters next to `technique:`); a technique with no parameters omits
`params:`. Unknown keys inside a runtime entry are ignored by serde, so a
half-migrated flat entry silently falls back to the technique's defaults
(`process_hollowing` then hollows `svchost.exe`). `build` has exactly three
blocks: `payload` (`source` + `crypto`), `stub`
(`path`/`syscalls`/`api_resolution`/`strings`/`debug`) and `output`;
`build.output.arch` is `x64` or `x86` and the stub, the payload and (for
hollowing) the target must all share it; `x86` is fully supported for
`reflective_loading`, `process_hollowing`, `anti_debug`, `patch_amsi`,
`patch_etw` and `bouncer` (`sleep_obfuscation` stays x64-only, and an x86
pipeline that uses it is rejected by the capability check with a message naming
the technique). String
obfuscation lives at
`build.stub.strings` (it only ever affected stub literals). Build args move from
`$build.N$` to `$arg.N$` (`$arg.0$`, `$arg.1$`, or a named `$arg.foo$` from a
`foo=value` CLI arg); the stub still accesses already-resolved args as
`$ARG_<key>$`. The old `InputConfig`/`LoaderConfig` are gone
(`src/plan/schema.rs`); `PipelineStep` is renamed `RuntimeStep`
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
`none`/`hells_gate`). It is a *loader* configuration, not a pipeline technique. The
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
- `picaro audit <binary>` reports header, sections + entropy, imports/exports,
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
technique. Validation in `src/plan/validate.rs`; the stub renders into
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

**CLI UX, app named `picaro` (done).** The crate, binary and CLI are `picaro`.
UX lives in `src/ui.rs`:
a truecolor `Palette` with a soft violet brand accent, clear green/yellow/red
status colors and a steel blue for targets (color auto-disabled when not a
terminal, plus `NO_COLOR`/`--no-color`). Legibility rules: primary values use
the terminal's default foreground (a fixed light gray vanishes on a light
`theme), and the secondary slate tone is bright enough to read on dark. The
banner (the `BANNER` literal in `src/ui.rs`) is printed before every subcommand,
followed by the dim tagline (`mimicry-based packer · vX.Y.Z`); `-q`/`--quiet`
skips it. `build` and `audit` open with a
`▸ picaro <cmd> · <target>` echo; `build` logs `✓` steps with compact
path/size detail and a green result line, while `-v`/`--verbose` adds a
resolved-plan block plus per-step detail (template, marker, rustc path,
timings); `audit` renders the redesigned report (metadata bar, entropy gauges,
uppercase headings, colored `LOW/MEDIUM/HIGH RISK`); `techniques list` is a
colored table.

**Phase 6 done.** Indirect syscalls (see the “Phase 6” entry above).

**API resolution (Phases A–D done, E parked).** New loader-level
`build.stub.api_resolution` (`mode: none|proxy`, `apis: [dll!func]`,
`unmatched: forward|abort`). In `proxy` mode the loader serves selected payload
imports from proxies generated in the stub: the catalogue
(`src/engine/api_resolution.rs`) is `ntdll!NtReadVirtualMemory`,
`ntdll!NtOpenProcess`, `kernel32!ReadProcessMemory` and `kernel32!OpenProcess`
rebuilt on the `Nt*` calls through the syscall layer, plus a
`kernel32!GetProcAddress` handler. `$API_RESOLUTION_BLOCK$` is rendered by
`render_block` (the selected `Nt*` names are merged into the syscall block via
`render_block_with`); the shared `patch_imports` serves catalogue hits, and the
shadowed names never enter the loader's IAT (`verify_no_intercepted_imports` in
the build flow). Requires `syscalls.mode: indirect` and a `pe`/`dll` payload;
rejected with `process_hollowing` (the proxies live in the loader image, which is
not mapped in the target — Phase E, D-23). The generated `resolution_policy`
returns `crate::ImportPolicy` (`Proxy(u64) | Forward | Abort`); `unmatched: abort`
makes `resolve_imports` fail the load on the first non-catalogue import (with an
advisory printed at build time). Design, phases and decision log:
`docs/api-resolution.md` (in the docs nav under Architecture).

**`build.stub.debug` (done).** `true` compiles the stub without the hardening
(`opt-level=0`, `debuginfo=2`, no strip, no path remapping) and makes the
techniques log to stderr (`[+] [<technique>] <message>`). Markedly less evasive;
laboratory only, never for delivery.

**Custom loader stubs (done).** A YAML `build.stub.path` replaces the builtin
stub with a user `.rs` template rendered through the same substitution engine
(see `docs/custom-stubs.md`); `build.stub` may be set for
`syscalls`/`api_resolution`/`strings` alone.
Placeholders use the `$X$` delimiter (`$PAYLOAD_BYTES$`, `$PAYLOAD_LEN$`,
`$PAYLOAD_NONCE_DEF$`, `$PAYLOAD_KEY_DEF$` (embedded only when referenced),
`$PREPARATION_BLOCKS$`, `$SYSCALLS_BLOCK$`, `$ARGS_BLOCK$`, `$IMPORTS_BLOCK$`,
`$API_RESOLUTION_BLOCK$`, `$EXECUTION_BLOCK$`, `$ARG_<key>$`;
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
`plan::validate` rejects the other formats with a pointer to
`reflective_loading`. DLL/shellcode payloads run in-process, so
`patch_command_line()` still delivers `build.payload.args` through the PEB.
Examples: `examples/plans/shellcode.yaml` (+ `examples/payloads/demo_shellcode.bin`,
`mov eax, 42; ret`). Verified end to end on Windows (shellcode exits 42; a Rust
cdylib export ran and wrote its file). The `dll` format ships no example (the old
`test-dll.yaml` pointed at a payload that was never committed). Wizard/`--dry-run`
do not prompt for the format yet (edit the YAML).

**`.NET` payloads (`format: dotnet` + `dotnet_hosting`, done).** A managed image
is not native code, so `pe`/`dll` on one is a build-time error that names the
right combination (`PeInfo::is_dotnet()` reads the CLR header / COM descriptor,
data directory 14, and its `flags`); `format: dotnet` and
`technique: dotnet_hosting` imply each other in `plan::validate`. The technique
hosts the CLR in the stub's process and loads the assembly from memory; the
assembly's bitness is checked against `output.arch` (`32BITREQUIRED` ⇒ `x86`).
Fixtures: `tests/fixtures/managed_x86.exe` (32BITREQUIRED) and
`managed_anycpu.exe` (IL-only), from `tests/fixtures/managed_marker.cs` with
`csc -nologo -target:exe -platform:x86|anycpu`. Acceptance: `SharpHound.exe` in
the repo root packs with `arch: x86` and its output matches the unpacked run.

**Phase 8: `bouncer` environment gate (done).** New
`src/techniques/bouncer/` Preparation technique (T1497.001, T1614.001,
Experimental): it checks the current host and aborts the pipeline before the
payload runs when the declared requirements are not met. All fields are
optional and each activates one check — `hostname`/`username`/`domain`
(case-insensitive globs), `language` (BCP-47), `keyboard` (4-digit layout
codes), `not_in_vm` (CPUID hypervisor leaves), `not_in_sandbox` (aggregate
heuristic, threshold 3), `min_uptime_min`, `min_ram_mb`; `mode: all|any`
combines them and `on_fail: silent|exit` picks the rejection behaviour. No
field declared is a no-op (surfaced by `plan::validate::advisories` and
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
`docs/measurements.md`; examples `tests/plans/bouncer.yaml` and
`tests/plans/bouncer-miss.yaml`. Not done (by design): `on_fail: decoy` and
checks outside the documented list.

**Interactive build (done).** `picaro build interactive <payload>`
(`src/wizard.rs`) asks the questions a schema-4 YAML encodes — name/args, the
execution technique, preparation techniques plus their parameters, the stub
(`strings`/`syscalls`) and the output — assembles a `Plan`, prints it and
writes it, then hands the file to the normal build, so the written YAML is the
source of truth and `picaro build <file>` reproduces the artifact.
`--plan-out` sets the path (default `dist/<name>.yaml`). `build` gained an
optional `interactive` subcommand (`subcommand_precedence_over_arg`), so `PLAN`
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
made the old "first match" pick the wrong `windows_x86_64_msvc`. The wizard asks
for the architecture (second question, `x64` by default) and hides
`syscalls: indirect` on x86, so it only assembles plans the packer accepts. Not
prompted yet: `strings.key`, `build.stub.path`, `args_mode: override`,
non-default `sleep_obfuscation` regions.

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
`tests/plans/resources.yaml`, asset `examples/assets/sample.ico`.
Note the name clash: `build.output.manifest` (bool) is the provenance JSON;
`build.output.manifest` is **not** the embedded manifest — that is
`build.output.resources.manifest`.

**Signing + subsystem (done).** `build.output.sign` signs the artifact after
resources are embedded and before the manifest. Two backends are selected by
availability (`src/engine/signing.rs::locate_signer`): **`signtool.exe`** on
Windows (PATH → `PICARO_SIGNTOOL` → Windows Kits → `output.sign.signtool`) and
**`osslsigncode`** everywhere else, so the Docker image signs too. Three modes:
`lab` (an automatic CA + leaf — on Windows via PowerShell in
`Cert:\CurrentUser\My`, on other platforms via `openssl` under
`<artifact dir>/.picaro/lab/<subject>/`, overridable with `PICARO_SIGN_DIR`; the
CA's public cert is exported next to the artifact as `<stem>.ca.cer` and **no
trust store is modified**), `store` (an existing cert by `thumbprint`/`subject`;
**Windows only**, it reads the certificate store) and `file` (a `.pfx`; password
from `password_env`, never the YAML). Optional `timestamp_url` (RFC 3161:
signtool `/tr`, osslsigncode `-ts`). The Dockerfile ships `osslsigncode` +
`openssl` and its smoke test builds a lab-signed artifact and extracts the
signature. `src/engine/identity.rs` generates plausible metadata when
`output.resources.version_info.randomize: true` (company/product/description/
versions/copyright; explicit fields win), and the generated company becomes the
lab certificate subject when none is set, so the artifact and the signature
agree. The manifest records `signature.{mode,subject,issuer,thumbprint,
ca_file}` and the resolved `version_info`. `build.output.subsystem`
(`console`|`windows`) prepends `#![windows_subsystem = "windows"]` to the
rendered stub (skipped if the stub sets its own). A lab signature verifies only
where its CA is trusted; it gives no SmartScreen reputation.
`.pfx`/`.p12`/`.pem`/`.key` and `**/.picaro/` are gitignored. Examples:
`examples/plans/mimikatz.yaml` (randomized identity + lab signature) and
`examples/plans/lab-signed.yaml` (a backend-agnostic lab signature).

## Known limitations

- **`x86` is supported for everything except the one parked workstream.** M0–M5
  landed (see `docs/x86.md` for the phase table): both execution techniques, the
  four preparation techniques, the arch-aware shared blocks
  (`$IMPORTS_BLOCK$` reads PE32/PE32+ magic, `$ARGS_BLOCK$` uses the x86 PEB
  offsets), the i686 compiler path, the WOW64-aware hollowing-target check and
  `dotnet_hosting` (the stub hosts the CLR and runs a managed assembly from
  memory). Verified end to end: `packs_and_runs_an_x86_reflective_payload`,
  `packs_and_runs_an_x86_hollowed_payload` (a 32-bit payload hollowed into the
  WOW64 `svchost.exe`, marker + `tls=42` + exit code 42),
  `x86_preparations_run_before_the_payload`,
  `packs_and_runs_a_managed_payload` and `packs_and_runs_sharphound`.
  **Parked by decision:** x86 indirect syscalls (needs a Heaven's Gate thunk plus
  64-bit SSN resolution — a redesign of the syscall layer, not a flag;
  `syscalls.mode: indirect` and `api_resolution` stay x64-only and are rejected
  on x86). Fixture:
  `tests/fixtures/minimal_x86.exe` (`scripts/build_test_fixture.sh x86`); the
  example plan is `examples/plans/x86.yaml` (payload
  `examples/payloads/test_payload_x86.exe`). Plan and checklist: `.plan.md`
  (repo root; not tracked yet — add it to the commit if you want it kept).
- **A managed (.NET) payload needs `format: dotnet` + `dotnet_hosting`.** A
  managed assembly's entry point calls `mscoree.dll!_CorExeMain`, which starts
  the CLR for the *stub*, not the mapped payload, so `format: pe`/`dll` on a
  managed image is a build-time error. The technique hosts the CLR in the stub's
  process (`CLRCreateInstance` → `ICorRuntimeHost` → `_AppDomain.Load_3` →
  `GetEntryPoint` → `Invoke_3`), so it is `reflective_loading`-only in practice
  (one execution technique per pipeline) and the assembly runs on the CLR of the
  stub's bitness — a `32BITREQUIRED` assembly needs `arch: x86` (checked at
  build time). `SharpHound.exe` (32-bit .NET) is the acceptance case.
- **A mapped image's TLS index can collide with a loaded module's.** Both
  execution techniques give a manually mapped image a TLS index reserved through
  `TlsAlloc` and write its block into the loader's TLS array (`gs:[0x58]` /
  `fs:[0x2C]` — *not* the `TlsSetValue` array, which is what picaro used before
  and which left payloads reading another module's block). `TlsAlloc` returns the
  lowest free index, which can be a loaded module's `_tls_index`; that module then
  sees the payload's template bytes in the affected thread. Measurements and the
  ntdll teardown behaviour that forces this shape: `docs/measurements.md`.

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
- **`api_resolution.mode: proxy` is `reflective_loading`-only.** The proxies are
  ordinary Rust functions bound to the loader image (statics, obfuscated data,
  CRT), so a hollowed payload running in another process can only point its IAT
  at the real exports; `plan::validate` rejects the combination. Closing it needs
  a position-independent proxy emitter written into the target
  (`docs/api-resolution.md`, Phase E).
- `CreateProcessA`, `LoadLibraryA`/`GetProcAddress` and `TlsAlloc`/`TlsSetValue`
  still import statically: they are loader entry points, not kernel calls the stub
  issues.
- Windows Defender flags the packed artifacts (unavoidable); the dev machine
  had it disabled during the 6a runtime tests.
- **The container cannot `sign.mode: store`, and cannot run the Defender scan.**
  Both read Windows-only state: the certificate store and `MpCmdRun.exe`. The
  image ships `osslsigncode` + `openssl`, so `lab` and `file` signing work there
  (`audit` still runs; its Defender line reports `unavailable`).

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
