# Host-loaded DLL output (`build.output.kind: dll`)

A build mode that emits the loader as a **PE DLL** instead of an executable, so
the same `runtime:` chain runs inside an already-running, already-allowed
process: a JVM that loads it with `System.load`, a CPython interpreter through
`ctypes`, a .NET host through `[DllImport]`, or `rundll32`.

The case is application whitelisting (Software Restriction Policies /
AppLocker / a GPO that only permits certain interpreters). Those policies police
**programs**. A DLL is not a program: the allowed host loads it, so the program
rules never apply to it. The payload still runs in-process, on the loader's own
techniques and syscall layer.

Reference implementation: `void-loader` (`code_examples/void-loader`, branch
`origin/experimental`, commit `00c93ce` *"x32 and Dll"*),
`crates/mountercli/{Cargo.toml,mounter.def,build.rs,src/lib.rs}`. It splits the
crate into lib + bin, compiles the same code as `cdylib` and as an `.exe`, and
exposes `DllMain` + `JNI_OnLoad`; the JNI entry spawns a worker thread and
returns to the JVM at once.

---

## 1. What we take from the reference and what we drop

| void-loader | Picaro |
|---|---|
| args file in `%TEMP%` + scraping the host's command line | **dropped**: Picaro's configuration is baked into the stub at build time; a DLL build needs no argv (§10 D-2) |
| `.def` file + `build.rs` link args | **dropped**: Picaro drives `rustc` directly, so the exports come from the generated source (or `-C link-arg=/DEF:` if it ever proves necessary) |
| `DllMain` = `DisableThreadLibraryCalls` only | **kept**: the chain never runs under the loader lock (§10 D-3) |
| work on a worker thread; the entry returns immediately | **kept for `jni_on_load`**, deliberately inverted for `export:<name>` (§4.3) |
| `AttachConsole(ATTACH_PARENT_PROCESS)` + `CONOUT$` + `SetStdHandle` | **kept** (§4.4) |
| raw `WriteFile` for messages printed before Rust's stdio is usable | **kept** (§4.4) |
| `try_parse_from` instead of `parse` (clap's `parse` calls `process::exit`) | **kept in spirit**: the DLL path must never call `process::exit` |
| `/DEPENDENTLOADFLAG:0x800`, `/DELAYLOAD:api-ms-*` | **parked** (Phase E): only needed when a host loads the DLL from a mapped or unusual path |
| `crate-type = ["cdylib", "rlib"]` | one artifact per build, `kind: exe` or `kind: dll` (§10 D-1) |

---

## 2. Scope

### In scope

- `build.output.kind: exe | dll` (default `exe`).
- `build.output.entry` for DLL builds: `auto`, `jni_on_load`, `export:<name>`.
- A generated entry block (`$ENTRY_BLOCK$`) with the no-op `DllMain`, the
  selected exports, the console attach and the worker.
- Compilation as `cdylib`, output verification, and the interplay with
  resources, signing and the provenance manifest.
- Validation, advisories, docs, examples and lab measurements.

### Non-goals (explicitly rejected)

- **Reading arguments from the host.** Picaro's plan is compiled in; an args
  file is a disk artifact and a race the reference only needs because its
  loader takes its configuration from a CLI (§10 D-2).
- **`entry: dll_main`.** Running the chain from `DllMain` means running it under
  the loader lock, and every execution technique calls `LoadLibraryA` (the
  payload's imports, `api-ms-*`, `bcryptprimitives`), which is the classic
  deadlock shape (§10 D-3).
- **JNI method exports** (`Java_<package>_<Class>_<method>`). `JNI_OnLoad`
  covers the load-and-go case without binding the build to a class or package
  name (§10 D-4).
- **Reflective DLL loading into another process.** That is an execution
  technique, not an output kind; a `kind: dll` build is meant to be loaded by
  its host through the normal image loader.
- **Bypassing DLL rules or WDAC code integrity.** Out of our hands; see §9.
- **`kind: both`** (one plan producing two artifacts).
- **Extra export shapes for x86 callers** beyond the one in §4.2.

---

## 3. Schema

```yaml
build:
  output:
    path: ./dist/loader.dll
    kind: dll
    entry: auto            # auto | jni_on_load | export:Run
    arch: x64
    strip: true
    sign: { mode: lab }
```

- `OutputKind { Exe, Dll }`, serialized lowercase, `Default = Exe`, skipped
  when it is the default, with a `label()` for the UI — same shape as
  `Subsystem` and `TrimPaths`.
- `DllEntry { Auto, JniOnLoad, Export(String) }`, parsed from **one string**
  (`export:<name>`), `Default = Auto`, skipped when it is the default. `FromStr`
  + `Display` with serde's `try_from`/`into`, in the style of the existing
  enums. The *syntax* of the export name is checked in `plan::validate` (§5) so
  the operator gets a normal validation error instead of a serde one.
- `output` is `deny_unknown_fields`, so both fields must be declared on
  `OutputPlan`.
- `entry` is only meaningful with `kind: dll`; declaring it with `kind: exe` is
  an error (§5), not a silent no-op.

---

## 4. The generated stub

### 4.1 `$ENTRY_BLOCK$`

The builtin template stops inline-defining `fn main` and becomes
entry-agnostic; `fn run() -> Result<i32, String>` and every injected block stay
exactly as they are:

```rust
$STUB_HELPERS$

$ENTRY_BLOCK$

fn run() -> Result<i32, String> { /* unchanged */ }
```

`entry.rs` renders one of two blocks.

**Exe (today's behavior, moved out of the template verbatim):**

```rust
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
}
```

**DLL (`kind: dll`):**

```rust
// --- Entry (build.output.kind: dll) ---

/// Attaches the host's console, so `println!`/`eprintln!` (and the
/// `build.stub.debug` trace) reach a terminal instead of nowhere.
fn dll_attach_console() { /* AttachConsole */ }

/// Runs the chain once and reports its code. Never returns on a terminal
/// technique: those hand the thread to the payload.
fn dll_run_chain() -> i32 { /* run() + error path, no process::exit */ }

/// Runs the chain on a worker thread and returns at once, so the host's
/// loader is never blocked and a terminal technique keeps the thread.
fn dll_run_detached() { /* spawn(run_chain) */ }

#[no_mangle]
pub extern "system" fn DllMain(hinst: *mut c_void, reason: u32, _: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe { DisableThreadLibraryCalls(hinst) };
    }
    1
}

#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: *mut c_void, _r: *mut c_void) -> i32 {
    run_detached();
    0x0001_0006 // JNI_VERSION_1_6
}

#[no_mangle]
pub extern "system" fn Run(
    _hwnd: *mut c_void, _hinst: *mut c_void, _cmd: *const u8, _show: i32,
) -> i32 {
    run_chain()
}
```

Points that are not cosmetic:

- The sketch is the `entry: auto` variant: `jni_on_load` emits only
  `JNI_OnLoad`, and `export:<name>` only `<name>` (with the name from the
  plan). `DllMain` is always emitted.

- `DllMain` is emitted for **every** DLL build (it is the one export ordinary
  DLLs have, and it is the only place to call `DisableThreadLibraryCalls`); what
  makes an `auto` build conspicuous is the *combination* of `JNI_OnLoad` and a
  chain-runner export, not `DllMain` (§5).
- No thread **name**: `std::thread::Builder::name` would put a literal in the
  binary, visible to a debugger and to ETW. Use `std::thread::spawn`.
- The export names (`DllMain`, `JNI_OnLoad`, `<name>`) are **ABI data**: they
  necessarily appear in the export directory. That is the documented exemption
  from the "no literals in the stub" rule (§10 D-12); everything a technique
  says at runtime still goes through `StringsConfig`.
- The error path prints the chain's message (`run()` returns an already
  obfuscated `String`) and returns `1`; it must not add a literal of its own.

### 4.2 Host matrix

| Host | Loads it with | Entry | Called as |
|---|---|---|---|
| Java | `System.load("C:\\...\\loader.dll")` | `jni_on_load` | `JNI_OnLoad(JavaVM*, void*)` — fixed JNI signature, `1.6` returned |
| CPython | `ctypes.CDLL(path)` | `export:<name>` | `<name>()`; extra declared args are harmless on x64 |
| .NET / PowerShell | `[DllImport]` / `Add-Type -MemberDefinition` / `NativeLibrary.Load` | `export:<name>` | `<name>()` (`Winapi` == our `extern "system"`) |
| Ruby / PHP / LuaJIT / Node | `Fiddle`, `FFI`, `ffi-napi` | `export:<name>` | `<name>()` |
| `rundll32` | `rundll32 loader.dll,<name>` | `export:<name>` | `<name>(HWND, HINSTANCE, LPSTR, int)` |

Runnable versions of the table: `examples/hosts/` (`ctypes_host.py`,
`pinvoke_host.ps1`, `rundll32_host.ps1`, `java_host/JavaHost.java`), driven
against `examples/plans/dll-shellcode.yaml`.

The `export:<name>` shim takes **the rundll32 shape** (four arguments, ignored)
and returns `i32`. On x64 — a single calling convention, caller-pushed
arguments — a zero-argument `ctypes` or P/Invoke call is fine. On x86 `extern
"system"` is `stdcall`, where a callee that pops four arguments and a caller
that pushed none unbalance the stack: on x86 the export is only safe from a
caller that declares the same four arguments (`rundll32` does natively). That
is why x86 DLL builds carry an advisory (§5) on top of the parked x86 syscall
workstream.

### 4.3 Blocking semantics

The entries differ on purpose, because the hosts differ:

| Entry | Blocks? | Why |
|---|---|---|
| `JNI_OnLoad` | **no** — spawns and returns `JNI_VERSION_1_6` | `System.load` is called from the host's own thread; blocking it would stall the JVM (and any `AttachCurrentThread` work) behind the chain. The reference does the same. |
| `<name>` (export) | **yes** — returns the chain's code | `rundll32` exits as soon as the export returns, which would tear the process (and the payload thread) down; and a `ctypes`/P-Invoke caller gets a real return value. With a terminal technique the export never returns, which is exactly what keeps a short-lived host alive. |

Consequence for a Java host: because `JNI_OnLoad` returns immediately, the JVM
owns the process lifetime. The Java side must keep the process alive long enough
(`Thread.sleep`, a latch, `System.in.read()`) — same requirement as the
reference, whose comment says *"the latch keeps the JVM alive while we work"*.
A native thread created by Rust is invisible to the JVM's exit decision, so a
`main` that loads the DLL and returns would kill the chain. Attaching the
worker to the JVM (`AttachCurrentThread` from the captured `JavaVM*`) so the JVM
waits for it is a parked extension (Phase E).

### 4.4 Console

A DLL has no console of its own. The entry:

1. calls `AttachConsole(ATTACH_PARENT_PROCESS)` — on attach, the OS installs
   the console's standard handles for the process;
2. does that **before the first `println!`/`eprintln!`** — Rust's std resolves
   the standard handles on first use, so a late attach prints nowhere;
3. is best effort: if the host has no console (a GUI host, a service) the
   messages are dropped and the chain runs anyway.

If the host already had *valid* handles (an interpreter started from a
console), the attach is unnecessary; if it had *invalid* ones, `AttachConsole`
alone does not replace them. The reference's `CONOUT$` + `SetStdHandle` +
raw-`WriteFile` recipe covers that case, and whether it is needed here is a
Phase D measurement (which handles a `java.exe`/`python.exe` host actually
has), not an assumption.

The `build.stub.debug` prelude is rendered with `windows_subsystem = false` for
DLL builds, so it takes the plain-stderr variant: `AllocConsole` would open a
*new* console window, which is a visual tell in a host that already had one.

### 4.5 The worker

- `std::panic::catch_unwind(AssertUnwindSafe(run_chain))` around the chain, so a
  `should not happen` panic aborts the pipeline and **not** the host.
- That is only meaningful with unwinding: DLL builds are compiled with
  `panic=unwind` (the exe path keeps `panic=abort`) (§10 D-6). The cost is
  unwind tables in the artifact; the benefit is that a bug degrades to "the
  chain did not run" instead of `java.exe`/`python.exe` dying.
- The catch covers Rust panics only. An access violation inside a fragment is
  still a host crash; nothing in-process can make that graceful.
- No `process::exit` anywhere on the DLL path. Its one current caller is
  rejected at build time (`bouncer` with `on_fail: exit`); `self_deletion` is
  rejected for a different reason — it resolves the *running image*, the host
  (§5).

---

## 5. Validation and advisories

`plan::validate` gains a `validate_dll` pass. Hard errors:

| Combination | Reason |
|---|---|
| `kind: dll` + `output.subsystem: windows` | a DLL has no subsystem; the host's applies. (The default `console` is indistinguishable from unset, so only `windows` is detectable.) |
| `kind: dll` + `resources.manifest: true` | a `RT_MANIFEST` in a DLL sets the *DLL's* activation context; UAC and DPI awareness are per-process, so it cannot do what the operator expects (§10 D-9) |
| `kind: dll` + any `self_deletion` step | it resolves the running image with `GetModuleFileNameW(NULL)` — in a DLL build that is the **host** (`java.exe`/`python.exe`), so it would rename or delete the interpreter. A mapped DLL cannot be deleted anyway (§10 D-7) |
| `kind: dll` + any `sleep_obfuscation` step | it encrypts the *running image* (`GetModuleHandleA(NULL)` + `SizeOfImage`), which in a DLL build is the **host's** image — whose code the host's other threads keep executing. It would also miss the payload, which lives in its own allocation outside that image (§10 D-16) |
| `kind: dll` + `bouncer` with `on_fail: exit` | `std::process::exit` kills the host (§10 D-8) |
| `kind: dll` + `build.stub.path` | the custom-stub contract is `fn main()`; the `$ENTRY_BLOCK$` contract lands in Phase E (§10 D-13) |
| `entry: export:<name>` with an invalid name | empty, not `[A-Za-z_][A-Za-z0-9_]*`, or colliding with `DllMain`/`JNI_OnLoad` |
| `entry` set to anything but the default `auto` with `kind: exe` | the field does nothing there; explicit is better than ignored (the default is indistinguishable from unset) |

Advisories (build succeeds, the line is printed):

| Combination | Message |
|---|---|
| `kind: dll` + `entry: auto` | the export table advertises `JNI_OnLoad` + `<name>`; a host-specific `entry` is less conspicuous where that matters (§10 D-11) |
| `kind: dll` without `output.sign` | an unsigned module inside a signed host is the first thing an EDR reports; `lab`/`file` signing only helps where the CA or signer is trusted |
| `kind: dll` + `arch: x86` | the host and the payload must be 32-bit too; the export's `stdcall` shape is only safe from a four-argument caller, and indirect syscalls stay parked on x86 |
| `kind: dll` + `patch_amsi` | the host may not have `amsi.dll` loaded (`java.exe`/`python.exe` do not), and the technique *loads* it — it brings the scanner into a process that did not have it |
| `kind: dll` + `path` not ending in `.dll` | the OS loader and most hosts expect the extension; a different one is a deliberate choice |
| `kind: dll` + a terminal technique + `entry: export:<name>` | informational: the export never returns, so the caller's thread is held for the payload's lifetime (that is the point for `rundll32`, and visible for `ctypes`) |

---

## 6. Code touchpoints

- `src/plan/schema.rs` — `OutputPlan.kind`, `OutputPlan.entry`, `OutputKind`,
  `DllEntry`.
- `src/plan/validate.rs` — `validate_dll` (§5) and the advisories.
- `src/engine/templates/main.rs.tpl` — `$ENTRY_BLOCK$` replaces the inline `fn main`.
- `src/engine/entry.rs` (new) — renders the entry block; unit tests assert the
  exe variant is byte-identical to today's literal, that the DLL variants carry
  the expected exports, and that no `process::exit` appears in a DLL block.
- `src/engine/steps.rs` — `StepsParams` gains `kind`/`entry`; `render_common`
  substitutes `$ENTRY_BLOCK$`.
- `src/engine/debug.rs` — the DLL path passes `windows_subsystem = false`
  (§4.4); no new prelude variant.
- `src/engine/compiler.rs` — `--crate-type=cdylib`, `--crate-name` from the
  output stem, `panic=unwind` for DLL builds, and `verify_output_kind`
  (`IMAGE_FILE_DLL` set for `dll`, clear for `exe`) on top of
  `verify_pe_magic`; `pe::is_dll` already exists.
- `src/main.rs` — skip `apply_subsystem` for DLL builds, name the intermediate
  after the output stem (§7), pass the kind into `CompileOptions`, and show the
  kind in the build log. `--dry-run` and `inspect_payload` are unaffected.
- `src/engine/stub.rs` — the custom-stub contract (Phase E).
- Docs/examples: `docs/architecture.md`, `docs/custom-stubs.md` (Phase E),
  `examples/plans/dll.yaml` + `examples/plans/dll-shellcode.yaml`,
  `examples/hosts/` (the host-process examples for the matrix in §4.2),
  `tests/plans/dll.yaml`, `docs/nav.yml`, `AGENTS.md`.

---

## 7. Build pipeline

Steps 1–4 of the build are unchanged; what changes is compile and after:

1. **Compile** — `rustc --crate-type=cdylib`, with `--crate-name <stem>` (the
   crate name otherwise defaults to the source file's stem, `main`). The
   intermediate is written as `build/<stem>.dll` rather than `build/out.exe`,
   because the linker records the link output's name inside the PE (the export
   directory's `Name` field); `strings dist/test_dll.dll` reports `test_dll.dll`,
   so the delivered name is the one the artifact reports, and `--crate-name`
   covers panic messages and symbol paths.
2. **Verify** — `IMAGE_FILE_DLL`, as above.
3. **Resources** — `.rsrc` injection is unchanged (it appends a section); icons
   and version info are legitimate in a DLL (`version.dll` has both). The
   embedded *application* manifest is rejected (§5).
4. **Sign** — unchanged: `signtool`/`osslsigncode` handle PE DLLs, and this is
   the mitigation with the most value for this mode. A lab signature still only
   verifies where the CA is trusted.
5. **Manifest** — `resolved_plan` is serialized into the provenance JSON, so
   `kind`/`entry` appear there with no extra work; the artifact hash/size lines
   describe the DLL.
6. **Audit** — `picaro audit` already parses any PE; a "DLL" tag in the
   metadata bar is a nice-to-have, not part of Phase A.

---

## 8. Phases

- [x] **Phase A — schema, validation, entry plumbing; no behavior change.**
  `kind`/`entry` parse and round-trip, `$ENTRY_BLOCK$` in the builtin template,
  `entry.rs` renders the exe block, §5 validation and advisories.
  *Acceptance:* the rendered stub for an `exe` plan is byte-identical to the
  current output (golden test); the validation table has one test per row; the
  crate builds and `cargo clippy --all-targets` is clean.
  *Verified 2026-09-30: `cargo clippy --all-targets` clean; one `#[ignore]` test
  per §5 row in `src/plan/validate.rs` (`rejects_a_windows_subsystem_with_a_dll`,
  … `advises_on_a_dll_path_without_the_extension`); `src/engine/entry.rs` asserts
  the exe block is the previous literal.*
- [x] **Phase B — compile as a DLL.** `--crate-type`, `--crate-name`,
  intermediate name, `verify_output_kind`, kind in the build log and the exit
  summary.
  *Acceptance:* `picaro build tests/plans/dll.yaml` produces an artifact whose
  file header has `IMAGE_FILE_DLL`, whose export directory reports the delivered
  name, and which `picaro audit` reads without complaint.
  *Verified 2026-09-30: `picaro audit dist/test_dll.dll` reports `EXPORTS 2
  DllMain Run` and reads it clean; `strings` shows the internal `test_dll.dll`
  (D-15). The `entry: auto` variant exports `DllMain`, `JNI_OnLoad` and `Run`.*
- [x] **Phase C — entry semantics.** `DllMain` no-op, the two export shapes,
  `dll_attach_console`, the worker with `catch_unwind`, `panic=unwind` for DLL
  builds.
  *Acceptance:* unit tests over the rendered entry (exports present, no
  `process::exit`, no `AllocConsole`), plus a `#[ignore]` e2e that loads the DLL
  from a host process and observes the chain's effect.
  *Verified 2026-09-30: `entry.rs` unit tests; the e2e
  `a_dll_artifact_runs_the_chain_when_a_host_loads_it` (in `tests/cli.rs`) builds
  the fixture, `LoadLibraryW`/`GetProcAddress`es it in the test process and gets
  the chain's `42` back from the export.*
- [x] **Phase D — host matrix, measured.** Run one plan three ways — Java
  (`System.load` + a latch), CPython (`ctypes`), `rundll32` — and record:
  console output, the returned value, the module list of the host, the artifact
  as seen by `dumpbin /exports`, Defender's behavior on the file before and
  after `output.sign`, and one negative case (a host that exits immediately
  after `System.load`, to document the lifetime rule).
  *Acceptance:* a new "DLL output" subsection in `docs/measurements.md` with
  the numbers and the exact commands.
  *Verified 2026-09-30 (CPython + .NET + `rundll32`; **Java not run**, no JDK on
  the host): `docs/measurements.md` — "DLL output (`build.output.kind: dll`) —
  host matrix". `dumpbin` was unavailable, so `picaro audit`'s EXPORTS section
  and `strings` stand in for it. The negative Java case is therefore still open*
- [ ] **Phase E (parked) — extensions.** Custom stubs with `$ENTRY_BLOCK$`;
  `AttachCurrentThread` from the worker so the JVM cannot exit mid-chain;
  `/DEPENDENTLOADFLAG:0x800` + `/DELAYLOAD` for hosts that load from a mapped
  drive; a second export shape for x86 `ctypes` callers; `kind: both`.

---

## 9. Limitations

Declared, not hidden:

- **The DLL is still a file on disk.** It has a hash, a path, an entry in the
  MFT, and the host loads it with the normal image loader, so it is scanned on
  load and it appears in the host's module list (image-load telemetry, and
  *unsigned module inside a signed process* for an EDR). What the mode removes
  is the *process* IoC — no process creation, no new `Image`, no separate
  command line — not the file.
- **The policy has to be the one this defeats.** AppLocker DLL rules are off by
  default; with them on, or with WDAC code integrity enforced, an unsigned DLL
  is blocked. `output.sign` shifts the odds only where the CA or signer is
  trusted by the host machine.
- **Bitness must match the host *and* the payload** (in-process execution).
  x64 is the realistic default; x86 carries the advisory in §5 and the parked
  x86 syscall workstream, so an x86 DLL build means `syscalls.mode: none` and no
  `api_resolution`.
- **Process-scoped techniques now patch the host.** `patch_etw`,
  `unhook_ntdll`, `patch_amsi` and the PEB `CommandLine` rewrite act on
  `java.exe`/`python.exe`: that is usually the point, but it is a state change
  in someone else's process, and `patch_amsi` can *load* `amsi.dll` into a host
  that had none (§5).
- **Lifetime is the host's.** `JNI_OnLoad` returns immediately (§4.3): a Java
  host that does not keep running kills the chain. The parked
  `AttachCurrentThread` extension is the fix.
- **A crash is a host crash.** `catch_unwind` covers Rust panics; an access
  violation in a fragment takes the interpreter down, which is loud and
  attributable.
- **The DLL cannot be deleted while loaded** (same as any mapped image): a
  dropper cannot clean up the file until the host exits.
- **`reflective_loading` rewrites the *host's* command line.** `$ARGS_BLOCK$`'s
  `patch_command_line()` patches the current process's
  `RTL_USER_PROCESS_PARAMETERS.CommandLine`, and in a DLL build that is
  `java.exe`/`python.exe`: the payload's args reach it through the PEB, and the
  command line the host reports (`GetCommandLineW`, WMI, an EDR's process
  record) changes with them. `process_hollowing` is unaffected — it passes the
  line to `CreateProcessA` for the target.
- **Detection surface of the build itself.** The export table is a static tell
  (`auto` most of all), and `panic=unwind` leaves unwind tables the exe path
  does not have.

---

## 10. Decision log

| # | Decision | Rationale | Status |
|---|---|---|---|
| D-1 | `output.kind: exe \| dll`, one artifact per build (no `both`) | The chain, the blocks and the techniques are identical; only the entry and the compile shape differ. Two artifacts would double resources/signing for no new capability | accepted |
| D-2 | No argv plumbing (no args file, no host command-line scraping) | Picaro's plan is baked in; the reference needs it only because its loader reads a CLI. An args file is an extra disk IoC plus a polling race | accepted |
| D-3 | `DllMain` is a no-op; no `entry: dll_main` | The loader lock plus `LoadLibraryA` in every execution technique is a deadlock shape | accepted |
| D-4 | `JNI_OnLoad` only, no `Java_*` exports | Covers load-and-go without binding the build to a class/package name | accepted |
| D-5 | `entry: export:<name>` uses the four-argument rundll32 shape and returns `i32` | Compatible with `rundll32` (natively four arguments, `stdcall` on x86) and harmless for zero-argument x64 callers; a zero-argument `stdcall` export would be the one that breaks `rundll32` | accepted |
| D-6 | `panic=unwind` + `catch_unwind` for DLL builds (exe keeps `panic=abort`) | A panic must abort the chain, not the host; unwind tables are the accepted cost | accepted |
| D-7 | `self_deletion` is a validation error with `kind: dll` | It resolves the running image — the host — and a mapped DLL cannot be deleted anyway | accepted |
| D-8 | `bouncer` `on_fail: exit` is a validation error with `kind: dll` | `process::exit` kills the host | accepted |
| D-9 | `resources.manifest` is a validation error with `kind: dll` | A DLL manifest cannot express UAC/DPI (both per-process) | accepted |
| D-10 | `patch_amsi` is allowed but advised against | The technique loads `amsi.dll` when absent, which is the opposite of useful in a host that had no AMSI | accepted |
| D-11 | `entry: auto` is the default, with an advisory | One artifact for every host in the lab; a mixed export table is a delivery tell, so a host-specific entry is preferred where it matters | accepted |
| D-12 | Export names are exempt from the no-literals rule | They are ABI data and must be literal; technique strings stay obfuscated | accepted |
| D-13 | Custom stubs are rejected with `kind: dll` until Phase E | The custom-stub contract today is `fn main()`; the DLL contract is `$ENTRY_BLOCK$` | accepted (Phase E) |
| D-14 | `entry: jni_on_load` does not block; the plain export does | Host lifecycle: the JVM owns its process and stays alive, `rundll32` exits the moment the export returns | accepted |
| D-15 | The intermediate is named after the output stem, and `--crate-name` follows it | The linker records the link output's name in the PE; the artifact should report the name it is delivered under | verified (`strings dist/test_dll.dll` reports `test_dll.dll`) |
| D-16 | `sleep_obfuscation` is a validation error with `kind: dll` | It encrypts the running image (`GetModuleHandleA(NULL)` + `SizeOfImage`) — the host's, in a DLL build — while the payload is *not* in that image, so it breaks the host without covering the payload | accepted |

---

## 11. References

- Reference implementation: `code_examples/void-loader`, branch
  `origin/experimental` (commit `00c93ce`),
  `crates/mountercli/{Cargo.toml,mounter.def,build.rs,src/lib.rs}`.
- Sibling loader design: [API resolution](api-resolution.md) (same
  loader-configuration pattern, same phase/decision-log shape).
- Existing PE helpers: `src/engine/pe.rs` (`is_dll`, `IMAGE_FILE_DLL`),
  `src/engine/resources/inject.rs`, `src/engine/signing.rs`.
- Current stub contract: `docs/custom-stubs.md`, `src/engine/stub.rs`.
