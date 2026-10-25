# Shellcode output (`build.output.kind: shellcode`)

The packed DLL, wrapped in a reflective loader so the chain runs from memory
without a PE on disk.

## What it is

`kind: shellcode` does not introduce a new compile shape. The stub is compiled
exactly as for `kind: dll` (a `cdylib`, `panic=unwind`, `+crt-static`), then
handed to sRDI (`ConvertToShellcode.py`), which prepends a position-independent
reflective PE loader and emits raw bytes. A host that can run shellcode maps
those bytes and jumps to them; the loader maps the DLL, resolves its imports and
calls the plain export (`Run`, or the name from `entry: export:<name>`), so the
chain runs without the image loader ever seeing a DLL and without an EXE being
launched.

## Status

**Verified end to end on the lab host (2026-10-17).**

- The build path works: `rustc` → `cdylib` → sRDI → `.bin`.
- A minimal C DLL, a `#![no_std]` Rust DLL and the **full Rust-std stub** all run
  from the converted `.bin` via `VirtualAlloc` + direct call, and a PE payload
  mapped reflectively prints its marker. The two root causes that previously
  blocked this — a stale upstream sRDI blob and Rust std's thread-local runtime —
  are fixed in the vendored loader (`vendor/srdi/`); see the measurement below.

## Schema

```yaml
build:
  output:
    path: ./dist/loader.bin
    kind: shellcode
    entry: export:Run   # auto | export:<name>  (jni_on_load is rejected)
    arch: x64           # x86 is rejected (see below)
```

- Reuses `OutputPlan.entry` (`DllEntry`); the reflective loader calls the plain
  export after `DllMain`.
- `arch: x86` is rejected: sRDI calls the export with a two-argument `cdecl`
  shape, while the entry's `extern "system"` export is four-argument `stdcall`
  on x86, so the stack unbalances.
- `output.sign`, `output.resources` and `entry: jni_on_load` are validation
  errors: shellcode is not a PE, its mapped DLL is absent from the loader's
  module list, and `jni_on_load` exports no plain runner.

## How it works

```
rustc --crate-type cdylib   (same as kind: dll, `compiles_as_dll`)
        │
        ▼
sRDI ConvertToShellcode.py  (PICARO_SRDI, a Python 3 subprocess)
        │
        ▼
raw .bin = [bootstrap][reflective loader][DLL bytes]
```

sRDI is **vendored** under `vendor/srdi/` (not downloaded): the C loader
(`ShellcodeRDI.c`), the converter CLI (`ConvertToShellcode.py`) and
`build_blob.py`, which compiles the loader with MinGW-w64 and emits the
`ShellcodeRDI.py` the packer imports. Because the converter is pure Python and
the blob is built with the image's own cross-compiler, the **Docker image bakes
it in** exactly like `mcs` for `powershell_hosting` (`ENV
PICARO_SRDI=/usr/local/lib/srdi/ConvertToShellcode.py`); the packer lives on
Linux while the shellcode/PE/DLL artifacts stay Windows-only. On a host build,
point `PICARO_SRDI` at a `ConvertToShellcode.py` and have a Python 3 on `PATH`.

## Validation and advisories

Rejected (errors):

| Combination | Reason |
|---|---|
| `shellcode` + `sign` | shellcode is not a PE; Authenticode does not apply |
| `shellcode` + `resources` | the mapped DLL is absent from the module list, so its resources cannot be queried |
| `shellcode` + `entry: jni_on_load` | the loader calls the plain export; `jni_on_load` exports none |
| `shellcode` + `arch: x86` | sRDI's two-arg `cdecl` call unbalances the four-arg `stdcall` export |
| `shellcode` + a host-resolving technique (`self_deletion`, `sleep_obfuscation`) or `bouncer` with an exiting `on_reject` action | shared with `kind: dll`: they act on the *host* process, not the artifact |

Advisories (informational): the `.bin` extension, the detection surface (RWX +
reflective loader) and the mixed export table under `entry: auto`.

## Static surface

The intermediate DLL is `out.dll`, not a name derived from the artifact: sRDI
converts it in place and the stage is delivered as raw bytes, so echoing the
operator's file stem would leave that codename in the export directory's `Name`
field and in the linker's PDB reference. A release build also passes
`/DEBUG:NONE` on MSVC, because `-C strip=symbols` alone leaves an RSDS record
pointing at `<stem>.pdb`. `kind: dll` keeps the delivered name on purpose (the
DLL is the artifact; see `docs/design/dll-output.md`, D-15).

## Code touchpoints

- `src/plan/schema/mod.rs` — `OutputKind::Shellcode`, `OutputPlan.entry` doc.
- `src/plan/validate/mod.rs` — `validate_dll_like` (shared with `dll`),
  `validate_shellcode`, `shellcode_advisories`.
- `src/engine/entry.rs` — `render` maps `Shellcode` to the DLL entry block.
- `src/engine/compiler/mod.rs` — `compiles_as_dll`, `panic_flag`, `verify_output_kind`.
- `src/engine/shellcode.rs` — sRDI location and the `convert` subprocess.
- `src/cli/helpers.rs` — `intermediate_path`; `src/cli/build.rs` — the post-scrub
  conversion and the tail.
- `Dockerfile` — builds the sRDI blob from `vendor/srdi/` (`ENV PICARO_SRDI`).
- `vendor/srdi/` — the vendored loader source, converter and blob builder.

## Measurement (2026-10-17, lab host)

- Defender real-time protection off (`RealTimeProtectionEnabled: False`).
- Two root causes were fixed and measured in sequence:

1. **The upstream x64 bootstrap swapped its 5th and 6th stack arguments.** The
   loader therefore read the shellcode base pointer as `dwFlags`, took the
   low 16 bits as an `OBFUSCATEIMPORTS` sleep delay, and called `Sleep(delay *
   1000)` after resolving imports — the "hang". Fixing the two offsets makes a
   minimal C DLL (gcc/MinGW) and a `#![no_std]` Rust DLL run and write their
   markers through `VirtualAlloc` + direct call.
2. **Rust std's `#[thread_local]` needs the TLS data a manually-mapped DLL never
   gets.** Upstream sRDI only runs TLS *callbacks*, not the `.tls` *template*, so
   the first thread-local read aborted ("the global allocator may not use TLS
   with destructors"). The 2026-10-17 fix (a `TlsAlloc` index published into
   `TEB->ThreadLocalStoragePointer`) turned out to borrow KERNELBASE's static
   index `1` and corrupt both sides (release-only), and removing the
   provisioning leaves the linker's zero, which aliases the module that owns
   index 0 — measured again 2026-10-21, see `docs/measurements.md`. The current
   design is stub-side: the packer injects a TLS handoff block
   (`src/engine/tls.rs`, `$TLS_HANDOFF_BLOCK$`) that gives the stub an index
   *past every loaded module's* via a private per-thread array
   (`gs:[0x58]` — the array a CRT reads, *not* `TlsSetValue`'s `TlsSlots`),
   pauses around module loads and the payload handoff (a module with static TLS
   loading while the private array is active makes the loader grow an array it
   does not own), and restores the loader's array when the chain finishes.

- Result: the full Rust-std stub (the packed DLL) runs from the `.bin`; a PE
  payload mapped reflectively prints `PAYLOAD_MARKER_7f3a9c2e`, and the runner
  returns cleanly.

## Non-goals

- A host that runs the shellcode: the artifact is the raw bytes; the operator
  chooses the runner (`msbuild` inline task, a JVM via the FFM API, …).
- `arch: x86` (parked until the entry has an sRDI-shaped `cdecl` export).
