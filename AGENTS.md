# Picaro — Agent Instructions

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

## Tests and hosting safety (non-negotiable)

- **The project has no CI, by decision.** Testing that compiles a stub or runs an
  artifact does not belong in one: never add a workflow that does it, and if CI
  ever returns it may only run the inert checks below.
- **A plain `cargo test` must stay inert.** Any test that compiles a stub or runs
  an artifact is behind the `live-tests` cargo feature **and** `#[ignore]`d, so
  the default suite neither compiles nor runs a loader.
- **Dangerous tests run by hand only, on the dedicated lab machine** (the
  isolated host with Defender disabled): `cargo build` first, then
  `cargo test --features live-tests -- --ignored`. Agents may run them on that
  machine; never on a shared/hosted one, and never as part of a default run.
  **Verify the premise at the start of every round** —
  `Get-MpComputerStatus | select RealTimeProtectionEnabled` must say `False`: a
  reboot can silently restore it (measured 2026-10-15, and the round that
trusted an earlier "it is off" ran under the wrong premise; with it on, the
  CLR refuses flagged assemblies at load and `packs_and_runs_sharphound` fails
  for host reasons — AMSI, not the stub).
- The `picaro-debugger` MCP server (`.agents/mcp/`) draws the same boundary in
  code: its execution and debugger tools only exist with `--lab`, and
  launching refuses while Defender real-time protection is on. A debug session
  runs the artifact under lldb — treat it like any other live test.
- The local pre-commit gate is inert and reproducible: `cargo fmt --all --
  --check`, `cargo clippy --all-targets -- -D warnings` and the pure unit suite
  (`cargo test`).
- Never commit real offensive tool binaries (mimikatz, LaZagne, nxc, …); fixtures
  are built from source in the repo.
- Prefer a private repo.

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
  plans/      validation fixtures
  fixtures/     committed PE fixtures
scripts/        Docker wrappers (picaro.py, docs.py)
.agents/mcp/    the picaro-debugger MCP server: analysis plus a gated lldb debugger (see its README)
.agents/skills/ project skills (picaro-debugger: driving the MCP; picaro-analysis: static triage)
docker-compose.yml  containers: dev (Picaro + msfvenom) and run (no toolchain)
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
  `fs:[0x2C]` — *not* the `TlsSetValue` array, which is what Picaro used before
  and which left payloads reading another module's block). `TlsAlloc` returns the
  lowest free index, which can be a loaded module's `_tls_index`; that module then
  sees the payload's template bytes in the affected thread. Measurements and the
  ntdll teardown behavior that forces this shape: `docs/measurements.md`.

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
  entry point. Runtime-verified on x64 (2026-10-14): the callback's marker lands
  before the entry point's. The emulated call is based on the stack pointer the
  thread parked with, rounded down to 16 bytes, and the parked pointer is
  restored before the hand-off — a callback entered with `rsp % 16 == 0`
  faults as `0xC0000005` at address `-1` in a `movaps` of a frame local
  (measured). The x86 callback path is compile-verified only.
- Custom stubs keep the per-step payload keys in the runner: each Execution
  step's key and nonce are emitted as hex literals in `$STEP_RUNNER_BODY$`. A
  stub that wants no key material embedded must decrypt the payloads itself, or
  take the value from a build argument (see `examples/stubs/runtime-key.rs`).
- **`api_resolution.mode: proxy` is `reflective_loading`-only.** The proxies are
  ordinary Rust functions bound to the loader image (statics, obfuscated data,
  CRT), so a hollowed payload running in another process can only point its IAT
  at the real exports; `plan::validate` rejects the combination. Closing it needs
  a position-independent proxy emitter written into the target
  (`docs/design/api-resolution.md`, Phase E).
- **`pe_injection` is `Stable`** on x64: the payload's plain path and its TLS
  path (provisioned through a target-resident prologue: index, template, slot and
  the `DLL_PROCESS_ATTACH` callbacks before the entry thread) are verified end to
  end (2026-10-14). The prologue's callback loop runs under `sub rsp, 8`/
  `add rsp, 8`: a thread start routine is entered with `rsp % 16 == 8`, so a
  `call` from that state enters the callback with `rsp % 16 == 0` and its first
  `movaps` frame-local faults (`0xC0000005` at `-1`, measured). x86 is
  compile-verified only.
- **`process_ghosting` is `Unimplemented`** — registered, wired and documented,
  but its Win32 design cannot work as written: a delete-pending file refuses a
  writable `CreateFileMappingW` (`ERROR_ACCESS_DENIED`), a read-only *data*
  mapping keeps file offsets (so RVAs do not line up), and creating the writable
  section before the delete mark makes the mark fail. A working design needs an
  image section (`NtCreateSection(SEC_IMAGE)` + `NtMapViewOfSection`), which the
  syscall layer does not have; `plan::validate::advisories` warns when a runtime
  selects it. Numbers: `docs/measurements.md`.
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
- **The lab host's AMSI provider is inert with real-time protection off**, so no
  technique can produce a *detection-bypass* number there: `patch_amsi` and
  `hardware_breakpoints` are verified by what they make the real export do
  (`AmsiScanBuffer` never runs its body / returns `S_OK` + `AMSI_RESULT_CLEAN`),
  not by a "blocked vs allowed" comparison. Numbers:
  `docs/measurements.md`. The same condition is what lets `dotnet_hosting` load
  a flagged assembly from memory: with real-time protection on, AMSI refuses it
  and the host sees `0x8007000b` (`ERROR_BAD_FORMAT`) on `Load_3` — measured
  2026-10-15 in both directions.
- **`sleep_obfuscation` is the one-shot demo shape.** It encrypts the *whole
  loader image* for a single `sleep_ms` window at Preparation time and restores
  it; the operational form (encrypting during the payload's own sleeps, and the
  payload-region enumeration) is a later phase. Measured 2026-10-14: 218/218
  pages RC4 ciphertext + `PAGE_READWRITE` for the whole window, byte-exact
  restore; the plain `sleep` control changes nothing. Numbers:
  `docs/measurements.md`.
- **A manually mapped image has no registered unwind tables on x64**, so a
  payload that raises a native exception cannot unwind through its own frames:
  `reflective_loading`, `process_hollowing` and `pe_injection` all map images
  without `RtlAddFunctionTable`, and the image is absent from the loader list.
  A payload that only returns or calls `ExitProcess` is unaffected. x86 needs
  none; `docs/x86.md` has the difference and registering the tables is a
  separate feature.
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
- Read `.memory.md`: the `## Current state` section first, then the newest log
  entries.
- The docs are an Astro + Starlight site. The nav lives in `docs/nav.yml` (the
  single source of truth the Rust doc tests also read); `scripts/docs.py`
  builds the Node image and serves it, and `docs/site/scripts/assemble-docs.mjs`
  inlines the READMEs into the pages at build time. Preview with
  `python scripts/docs.py`.

At the **end** of a session:
- Update `.memory.md`: add a dated entry at the top of the log (newest first,
  right after the `## Current state` section) with what was done, open questions
  and next steps.
- Keep each entry short. `.memory.md` (the `## Current state` section plus the
  rolling log) is the project's state; this `AGENTS.md` stays static
  instructions.
