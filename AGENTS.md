# picaro — Agent Instructions

## What this project is

A malware loader packer for authorized red team engagements and security
research. Takes a PE file and a YAML plan, produces a packed PE with
selected evasion techniques applied.

Intended use: lab environments, authorized audits, security research.
Any other use is out of scope and not supported.

## Architecture principles (non-negotiable)

- **Rust first, not Rust only.** The packer and the generated stub are Rust,
  and new code prefers Rust, but a toolchain or runtime in another language is
  acceptable when it is the pragmatic choice — for example, a subprocess `yara`
  scanner, or a future C stub that calls the Rust runtime through an ABI.
  Never reimplement a technique in another language, and never embed a
  toolchain in the repo.
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
                resources, manifest, hash, builtin stub template
  audit/        static measurement (pe_info, strings, yara, defender, report)
  techniques/   one directory per technique + the registry (mod.rs)
  error.rs      top-level error types
  ui.rs         terminal output: banner, palette, formatting helpers
examples/
  plans/      curated example YAMLs
  payloads/     test payloads for end-to-end verification
  stubs/        custom stub templates (build.stub.path)
  hosts/        host-process examples for `kind: dll` (ctypes, P/Invoke, .NET,
                rundll32, Java, Perl, Ruby, PHP, LuaJIT, Node)
  assets/       sample icon for build.output.resources
tests/
  plans/      CI / validation fixtures
  fixtures/     committed PE fixtures
scripts/        Docker wrappers (picaro.py, docs.py)
docker-compose.yml  containers: dev (picaro + msfvenom) and run (no toolchain)
docs/           Markdown sources; full-screen or in the site
  nav.yml         the documentation navigation (single source of truth)
  site/           the Starlight site project (config, styles, assembler, Dockerfile)
build/          (gitignored) intermediate artifacts
dist/           (gitignored) final packed binaries
exchange/       (gitignored) the one host folder shared writable with the containers
code_examples/  (gitignored) local reference scratch
```

Two data files live inside `src/` (read at runtime from `CARGO_MANIFEST_DIR`):
the builtin stub template `src/engine/templates/main.rs.tpl` and the YARA rules
under `src/audit/yara/rules/`.

Each technique lives under `src/techniques/<name>/` (README + stub fragment +
tests). The registry (`src/techniques/mod.rs`) is metadata-only; inspect it with
`picaro techniques {list,show,validate}`. Adding a technique is documented in
`src/techniques/README.md`.

## Current state

**YAML schema 6 (done): a flat `runtime:` of technique steps.** The plan
keeps everything the build needs under `build:` — `crypto` (the default crypto a
payload inherits), `payloads` (a **named map**), `stub`
(`path`/`syscalls`/`api_resolution`/`strings`/`debug`) and `output` — and
expresses the loader as one ordered top-level `runtime:` list. A step is
`technique:` + optional nested `params:` + the loader's own orchestration
(`on_success`/`on_fail`/`delay_ms`, `StepControl`). There are no `stages`, no
nested pipelines and no single `build.payload`: a document that declares any
other schema version is rejected at parse time with one migration hint
(`RETIRED_SCHEMA_MIGRATION` in `src/plan/schema.rs`). `src/plan/steps.rs`
(`resolve`) pins each Execution step to a payload: `params.payload` is optional
when exactly one payload is declared, required (and must exist) with two or
more; only `reflective_loading`/`process_hollowing`/`dotnet_hosting` take one.
`exec` is the technique `living_off_the_land` and `sleep` is the technique
`sleep` (both `Category::Control`). `build.output.arch`/`strip`/`trim_paths`
default to `x64`/`true`/`all`, and crypto defaults to `xchacha20poly1305` +
`random`, so a plan needs no such block — only `output.path`.

`src/engine/steps.rs` renders a single template (`src/engine/templates/main.rs.tpl`):
each Execution step's payload is embedded and encrypted with its own key/nonce,
each step is wrapped in `mod step_<index>` (a Preparation exposes
`run() -> Result<bool, _>`, an Execution `payload(image)`, `living_off_the_land`
`run() -> Result<i32, _>`; `sleep` is one inline line), and a generated runner
walks the steps in order with the declared gating. The shared blocks
(`$SYSCALLS_BLOCK$`, `$ARGS_BLOCK$`, `$IMPORTS_BLOCK$`,
`$API_RESOLUTION_BLOCK$`) come from the union of the steps' techniques. A custom
stub (`build.stub.path`) renders through the same engine with
`$STUB_HELPERS$`/`$STEP_MODULES$`/`$STEP_RUNNER_BODY$` (see
`docs/custom-stubs.md`). `cargo`-level types: `TechniqueKind` (the tagged enum)
and `RuntimeStep { technique, control }` (`src/techniques/mod.rs`). **The rule that
shapes it:** a chain only continues if the loader gets control back, so
`reflective_loading` of a PE *executable* and `dotnet_hosting` are *terminal* and
must be the last step (`plan::validate` rejects them otherwise);
`living_off_the_land`, `process_hollowing` and `reflective_loading` of a DLL
always return. `api_resolution.mode: proxy` is loader-wide, so it is rejected
unless the runtime declares exactly one Execution step, and never with
`process_hollowing`. `build.payloads.<name>.source` is a single string:
`http(s)://` is fetched in memory, `file://` is read from disk, `ftp://` is
rejected, anything else is a local path. Docs: `docs/multistage.md`; examples:
`examples/plans/multistage.yaml`, `examples/plans/multistage-advanced.yaml`.

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

**Process hollowing runs a full PE, TLS callbacks included.** The loader state is
reconstructed (imported DLLs, TLS index + per-thread template + main-thread slot,
`Rip` hand-off) and the payload's `DLL_PROCESS_ATTACH` TLS callbacks run on the
main thread via a `jmp $` parking stub before the entry point, so a Rust test
payload completes (exit `0`). A relocation bug (DIR64/HIGHLOW swapped in the
fragment) was the real blocker. Measured evidence:
`docs/techniques/process_hollowing.md`. Every diagnostic the fragment emits is
obfuscated (`MESSAGES` + `render_fragment`), so no error text — and no technique
keyword such as `loader` — reaches `.rdata`. `reflective_loading`'s shellcode
fragment and the other five techniques still carry cleartext (keyword-free)
diagnostics through `thiserror`.

**Phase 6: indirect syscalls done.** New `build.stub.syscalls` block
(`mode: none|indirect`, `resolver: hells_gate|tartarus_gate|api_hash`; defaults
`none`/`hells_gate`). It is a *loader* configuration, not a pipeline technique. The
stub template gains `$SYSCALLS_BLOCK$`, rendered by `src/engine/syscalls/`
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
  precomputed FNV-1a 64-bit hash of its name
  (`engine::syscalls::resolvers::api_hash::api_hash_with`, mirrored in the stub),
  so neither `GetProcAddress` nor any Nt* name string is needed; the basis is
  seeded per build (`API_HASH_SEED`), and the PE-file helpers are shared with
  Tartarus via `$FILE_PE_HELPERS$`.

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
technique. Validation in `src/plan/validate.rs`; the stub renderer gave each
Preparation fragment its own module (to avoid `use` collisions). Schema 6
superseded the "one Execution per pipeline" rule with the flat `runtime:` list
above.

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
colored table with a short legend (stability colors + a pointer to `show`).
`techniques show` renders the README as styled Markdown behind a metadata header
and pages a document taller than the terminal in an alternate-screen viewer that
restores the terminal on quit; `--raw` prints the Markdown verbatim and
`--no-pager` always prints inline. `ui` gained `markdown` (the renderer) and
`pager` submodules.

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
Placeholders use the `$X$` delimiter (`$STUB_HELPERS$`, `$STEP_MODULES$`,
`$STEP_RUNNER_BODY$`, `$SYSCALLS_BLOCK$`, `$ARGS_BLOCK$`, `$IMPORTS_BLOCK$`,
`$API_RESOLUTION_BLOCK$`, `$ARG_<key>$`;
YAML build args are `$arg.N$`). The stub must define `fn main()`; ignoring the
step blocks is a warning, not an error (a custom stub that skips
`$SYSCALLS_BLOCK$` while declaring syscall-using techniques also warns). Build
args are the positional args plus optional `name=value` pairs (no separate
`--arg` flag). `$X$` is invalid Rust, so `rustfmt` cannot rewrite it; never go
back to `{{X}}` (valid Rust — `rustfmt` reformats it into nested blocks and
silently breaks substitution). See `.memory.md` for the rolling state.

**Payload formats (done).** A payload's `format: pe|shellcode|dll` (default
`pe`) plus an optional `export` (a DLL's exported entry point;
rejected unless `format: dll`). `src/engine/pe.rs` gained the file-header
`characteristics` and `is_dll()`; `src/main.rs` validates the input per format
(`pe`/`dll` must be the matching x64 PE image, `shellcode` only non-empty) in
`inspect_payload`, shared by `build` and `--dry-run`. The format and export
reach the Execution fragment through `TechniqueKind::render_fragment(strings,
format, export)` → `Params::render_fragment_for`; `reflective_loading` ships two
fragments (`stub_fragment.rs` PE mapper, `stub_fragment_shellcode.rs` runner)
and, for a DLL export, calls `DllMain(DLL_PROCESS_ATTACH)` before invoking the
export with no arguments (both `SHELLCODE_FRAGMENT` and the placeholder
substitution are tested). `process_hollowing` only runs `pe`;
`plan::validate` rejects the other formats with a pointer to
`reflective_loading`. DLL/shellcode payloads run in-process, so
`patch_command_line()` still delivers the payload's `args` through the PEB.
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
`csc -nologo -target:exe -platform:x86|anycpu`. Acceptance: `SharpHound.exe`
(dropped in `tests/fixtures/`) packs with `arch: x86` and its output matches the
unpacked run.

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
(`src/wizard.rs`) asks the questions a schema-6 YAML encodes — name/args, the
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

**Parallel technique batch (done): `execution_callbacks`, `module_stomping`,
`fibers`.** Three in-process Execution techniques, `format: shellcode` only
(enforced by `plan::validate::validate_payload_format`), each *returning* control
to the loader and therefore chainable in a schema-6 `runtime:` list.
`execution_callbacks` (T1106/T1620) runs the payload as the callback of a
legitimate enumeration API
(`crypt32.dll!CertEnumSystemStoreLocation`, resolved dynamically and obfuscated);
`module_stomping` (T1055) `LoadLibraryA`s a signed module (`params.module`,
default `wininet.dll`) and overwrites the first bytes of its `.text`;
`fibers` (T1055) runs the payload on a fiber of the loader's own thread
(`ConvertThreadToFiber` → `CreateFiberEx` → `SwitchToFiber`, then back, delete
and `ConvertFiberToThread`). None needed a new syscall helper (they use
`nt_alloc_vm`/`nt_protect_vm`); all three were verified end to end on Windows
(the packed artifact runs the demo shellcode and relays exit `42`).

**Batch 2 (done): `unhook_ntdll`, `early_bird`, `pe_injection`,
`ppid_spoofing`.** Four techniques, one per parallel agent, all verified end to
end (not just compiled; numbers in `docs/measurements.md`). `unhook_ntdll`
(Preparation, T1562.001) restores the live ntdll's `.text` from a clean on-disk
copy — **the write window must be RWX** (a `PAGE_READWRITE` window faults on the
syscall's return, which goes through an ntdll stub inside the region being
rewritten) and **on x86 the section's base relocations must be applied** (the
live 32-bit ntdll differs from the file in 19,004 bytes of HIGHLOW fixups).
`early_bird` (T1055.004) spawns the target suspended, writes the payload and
queues the APC before resuming; the payload's exit code cannot be relayed (it
runs in another process), so the technique returns `STILL_ACTIVE` unless a
bounded `wait_ms` observes the target exiting. It runs on x64 and x86 — note that
the 32-bit `notepad.exe` of recent Windows builds is a launcher shim and
`QueueUserAPC` fails on it with `ERROR_INVALID_HANDLE`. `pe_injection`
(T1055.002) maps a full PE into a suspended process (relocations, imports
resolved against the *target's* module bases, a thread at the entry point)
**without unmapping the target's image**. `ppid_spoofing` (Control, T1134.004)
launches a child with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, verified from
PowerShell. Formats are enforced (`early_bird` shellcode-only, `pe_injection`
pe-only), `validate_injection_target` checks the spawned target's architecture
for the three spawn-a-target techniques, `advisories` warns when `unhook_ntdll`
follows `patch_etw` (the restore would silently undo it), and `nt_queue_apc`
(`NtQueueApcThread`) was added to the syscall layer for `early_bird`.

**Batch 3 (done): `thread_hijacking`, `stack_spoofing`, `self_deletion`.** Three
techniques, all verified end to end on Windows (numbers in
`docs/measurements.md`). `thread_hijacking` (T1055.003, Execution,
shellcode-only) finds a running process by image name (`target`) or `pid`, places
the payload and redirects the target's *first* thread: `nt_suspend_thread` →
`nt_get_context_thread` → `Rip`/`Eip` (plus `Rsp`/`Esp` on the private stack
`dedicated_stack: true` asks for) → `nt_set_context_thread` → `nt_resume_thread`;
no thread is ever created, and `wait_ms` relays the *target's* exit code.
`self_deletion` (T1070.004, Preparation, x86+x64) reads its own path and either
renames the image into an alternate data stream of itself
(`mode: rename_ads`, the default — the only variant that works on a *mapped*
image: four `FileDispositionInformation*` combinations measured
`ERROR_ACCESS_DENIED`, `FileRenameInformation` succeeded) or spawns a detached
`cmd.exe` that deletes the file after the loader exits (`mode: helper`); the
stream name is random per build. `stack_spoofing` (T1036, Preparation, x64 only)
is the syscall layer's stack half: it *replaces* the trampoline
(`nt_invoke` becomes its own asm, the raw one is renamed `nt_invoke_raw`), shifts
`Rsp` down by `decoy_bytes` on every call, copies the nine stack arguments so the
kernel still reads them at `[rsp+0x28]..[rsp+0x70)`, fills the gap with ntdll
`ret` sites discovered from the live ntdll at `init_syscalls` time, and unwinds
through a five-slot fabricated chain back to a restore label that puts `Rsp` and
`Rbx` where they were. `decoy_bytes` is clamped to `0x80..=0x8000` because
`0x70` — the structural minimum — faults in the first spoofed syscall on the
verification host (sweep script: `code_examples/stack_spoofing/bisect.py`). The
step is skipped by the renderer (nothing runs at pipeline time) and
`advisories` warns when `syscalls.mode` is not `indirect`. The wizard's
`default_format` maps `thread_hijacking` to shellcode.

**`Stability::Unimplemented` (new state).** The registry's maturity enum is
`Stable | Experimental | Unimplemented | Deprecated`. `Unimplemented` means the
technique is registered and wired (metadata, docs, tests) but its implementation
is **not finished**: either the stub fragment is a placeholder or a required part
of the loader contract is missing. `picaro techniques list` shows it in red, and
`plan::validate::advisories` warns on every build that selects one — the build
still succeeds, because an unfinished technique is often still useful in a lab.
No registered technique carries it today (`pe_injection` was the last; it moved
to `Experimental` once its TLS provisioning landed). A technique that enters as
a skeleton (the batch-2 pre-wiring pattern) should declare it too, which
replaces the older "placeholder fragment that fails at run time" idiom.

**PE resources (done).** `build.output.resources` embeds an icon (`RT_GROUP_ICON`
+ `RT_ICON`), `VERSIONINFO` (`RT_VERSION`) and the Windows application manifest
(`RT_MANIFEST`, UAC/DPI) into the artifact. All generated in Rust — no
`rc.exe`/`windres`, so the build stays cross-platform. `src/engine/resources/`
(`tree.rs` directory builder, `icon.rs`, `version.rs`, `manifest.rs`, plus
`inject.rs` which appends a `.rsrc` section to the compiled stub). `icon: random`
(the schema's `IconPlan`) is rendered by `icon_gen.rs`: pure `std`,
seed-deterministic, BMP `DIB` images at 16/32/48/64 (no PNG encoder, so no new
dependency); the build picks the seed in `resolve_resources` and records it as
`generated_icon` in the manifest. Directory
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

**Host-loaded DLL output (`kind: dll`, done: A–D verified).** `build.output.kind: dll`
(ship the same plan as a DLL the host loads, for environments where
application whitelisting only allows interpreters) is specified in
`docs/design/dll-output.md`, from the `void-loader` reference
(`code_examples/void-loader`, `origin/experimental`, commit `00c93ce`). The
shape: `--crate-type=cdylib`, a no-op `DllMain`, a non-blocking `JNI_OnLoad`
(Java `System.load`) plus a blocking `export:<name>` in the rundll32 four-argument
shape (CPython `ctypes`, P/Invoke, `rundll32`), the chain on a worker thread
with `catch_unwind` (`panic=unwind` for DLL builds) and
`AttachConsole(ATTACH_PARENT_PROCESS)` for output. It drops the reference's argv
plumbing (picaro's plan is baked in) and rejects, for DLL builds:
`subsystem: windows`, `resources.manifest`, `self_deletion`, `sleep_obfuscation`
(both act on the *running image* — the host, in a DLL), `bouncer` `on_fail: exit`
and custom stubs. Touchpoints: `src/plan/schema.rs`
(`kind`/`entry`), `src/plan/validate.rs`, `src/engine/entry.rs` (new: the entry
block), `src/engine/steps.rs` (`$ENTRY_BLOCK$`), `src/engine/compiler.rs`
(`cdylib`, `--crate-name`, `IMAGE_FILE_DLL` verification) and `src/main.rs`.
**Verified 2026-09-30** (`cargo` available again): clippy clean, the §5
validation table has one test per row, and the artifact loads in three hosts —
CPython `ctypes` and .NET P/Invoke both report the chain's `42` (the second also
sees the module in the host's module list), `rundll32` runs the chain (marker on
the redirected stderr) but exits `0` because it does not relay the export's
return value. `entry: auto` exports `DllMain`/`JNI_OnLoad`/`Run`; the PE records
the delivered stem (`strings` shows `test_dll.dll`); icon + version info embed in
a DLL and `GetFileVersionInfo` reads them back; `sign.mode: lab` signs it with
`signtool` and Defender stays clean. The e2e
`a_dll_artifact_runs_the_chain_when_a_host_loads_it` (`tests/cli.rs`) host-loads
the artifact and asserts the export's `42`; the copy-paste host examples are in
`examples/hosts/` (with `examples/plans/dll-shellcode.yaml`, a non-blocking
`entry: auto` build whose chain returns `42`), the catalogue of host programs is
`docs/hosts.md` (nav: Hosts), the scratch measurement plans are in
`code_examples/dll-output/`, and the numbers are in `docs/measurements.md`. **Java was not
measured** (no JDK on the host) and `dumpbin` was unavailable, so `picaro audit`
+ `strings` stand in for the export dump. The design's Phase E (custom stubs with
`$ENTRY_BLOCK$`, `AttachCurrentThread` so the JVM waits) is still parked.

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
  (repo root, local only — not published).
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

- **Process hollowing runs a full PE, TLS callbacks included.** The IAT
  (`src/engine/imports.rs`), the imported DLLs, the TLS index/block/slot and the
  `Rip` hand-off are all provisioned, and the payload's `DLL_PROCESS_ATTACH`
  TLS callbacks now run on the main thread via a `jmp $` parking stub before the
  entry point. Runtime verification of the callbacks on a Defender-off host is
  still pending; the implementation is compile-verified only.
- Custom stubs keep the per-step payload keys in the runner: each Execution
  step's key and nonce are emitted as hex literals in `$STEP_RUNNER_BODY$`. A
  stub that wants no key material embedded must decrypt the payloads itself, or
  take the value from a build argument (see `examples/stubs/runtime-key.rs`).
- **`api_resolution.mode: proxy` is `reflective_loading`-only.** The proxies are
  ordinary Rust functions bound to the loader image (statics, obfuscated data,
  CRT), so a hollowed payload running in another process can only point its IAT
  at the real exports; `plan::validate` rejects the combination. Closing it needs
  a position-independent proxy emitter written into the target
  (`docs/api-resolution.md`, Phase E).
- **`pe_injection` is now `Experimental`** (TLS is provisioned and the payload's
  `DLL_PROCESS_ATTACH` callbacks run before the entry thread). Runtime
  verification of the TLS path on a Defender-off host is still pending; the
  implementation is compile-verified only, so a payload that relies on dynamic
  TLS may still misbehave in ways a lab build should confirm.
- **`unhook_ntdll` silently undoes `patch_etw` if it runs after it** (both
  rewrite ntdll's `.text`); `plan::validate::advisories` warns about the order.
- **`early_bird` needs a real target image.** The 32-bit `notepad.exe` of recent
  Windows builds is a launcher shim on which `QueueUserAPC` fails with
  `ERROR_INVALID_HANDLE`; `cmd.exe` and the 64-bit `notepad.exe` are fine, and
  the default target is `svchost.exe`.
- **The three in-process shellcode runners are shellcode-only by construction.**
  `execution_callbacks`, `module_stomping` and `fibers` enter the payload as flat
  position-independent code, so `plan::validate` rejects `pe`/`dll`/`dotnet` for
  them (use `reflective_loading`/`dotnet_hosting`). All three compile for x86
  and were run end to end on x86 and x64 (`code_examples/<name>/smoke-x86.yaml`).
- `CreateProcessA`, `LoadLibraryA`/`GetProcAddress` and `TlsAlloc`/`TlsSetValue`
  still import statically: they are loader entry points, not kernel calls the stub
  issues.
- Windows Defender flags the packed artifacts (unavoidable); the dev machine
  had it disabled during the 6a runtime tests.
- **The container cannot `sign.mode: store`, and cannot run the Defender scan.**
  Both read Windows-only state: the certificate store and `MpCmdRun.exe`. The
  image ships `osslsigncode` + `openssl`, so `lab` and `file` signing work there
  (`audit` still runs; its Defender line reports `unavailable`).

- **`stack_spoofing` fabricates the top of the stack, not the whole of it.** The
decoy region and the five-slot return chain sit above the loader's real frames,
so a check that reads the *whole* thread stack still reaches them; it is the
cheap checks (the immediate return address, the first frames) that stop looking
like the loader. `decoy_bytes`'s floor is `0x80`, measured — `0x70` is the
structural minimum and faults. The save slots are process-global statics, so a
payload driving the loader's `nt_*` helpers from two threads at once can corrupt
them.
- **`self_deletion` cannot delete a *running* image on current Windows**
  (`FileDispositionInformation*` is refused with `ERROR_ACCESS_DENIED`; measured
  four ways — see `docs/measurements.md`). The default `rename_ads` mode moves the
  image's bytes into an alternate data stream and leaves a 0-byte file at the
  path; only `mode: helper` removes the file, and its two-second sleep is a budget
  the loader has to meet by exiting.
- **`thread_hijacking` takes the first thread the ToolHelp snapshot returns** (a
  thread parked in a wait would be a safer choice, but reading per-thread state
  needs more access than the hijack itself) and with the default
  `dedicated_stack: true` a payload that *returns* jumps to a null return address
  and takes the target down. The hijacked target's crash code depends on the
  payload: `ud2` gives `0xC000001D`, a `ret` gives `0xC0000005`.
- **A DLL host's lifetime is its own, and `rundll32` hides the return code.**
  `JNI_OnLoad` returns at once, so a Java host that does not keep running kills
  the chain (the parked `AttachCurrentThread` is the fix, Phase E); the *Java* row
  of the host matrix was never run (no JDK on the measurement host). `rundll32`
  runs the chain but exits `0` regardless of the export's return value, and being
  a GUI-subsystem binary it needs `Start-Process -RedirectStandard*` for its
  output to be observable at all — `AttachConsole(ATTACH_PARENT_PROCESS)` cannot
  attach a console that does not exist. Blocking techniques still wait: the
  `export:<name>` form holds the caller's thread for the payload's lifetime.
- **A DLL build changes the *host's* process state.** Process-scoped techniques
  (`patch_etw`, `unhook_ntdll`, `patch_amsi`) patch `java.exe`/`python.exe`, and
  `reflective_loading` rewrites the host's PEB `CommandLine`; `patch_amsi` can
  even *load* `amsi.dll` into a host that had none. `output.sign` is the most
  valuable mitigation (an unsigned module inside a signed host is the first EDR
  report), but a lab signature verifies only where its CA is trusted.

## Session workflow

At the **start** of a session:
- Read this file.
- Read `.memory.md` for the last session's state.
- The docs are an Astro + Starlight site. The nav lives in `docs/nav.yml` (the
  single source of truth the Rust doc tests also read); `scripts/docs.py`
  builds the Node image and serves it, and `docs/site/scripts/assemble-docs.mjs`
  inlines the READMEs into the pages at build time. Preview with
  `python scripts/docs.py`.

At the **end** of a session:
- Update `.memory.md` with what was done, open questions, and next steps.
- Keep it short (one screen max). It's a rolling log, not a journal.
