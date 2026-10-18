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
| `shellcode` + a host-resolving technique (`self_deletion`, `sleep_obfuscation`) or `bouncer` `on_fail: exit` | shared with `kind: dll`: they act on the *host* process, not the artifact |

Advisories (informational): the `.bin` extension, the detection surface (RWX +
reflective loader) and the mixed export table under `entry: auto`.

## Code touchpoints

- `src/plan/schema.rs` — `OutputKind::Shellcode`, `OutputPlan.entry` doc.
- `src/plan/validate.rs` — `validate_dll_like` (shared with `dll`),
  `validate_shellcode`, `shellcode_advisories`.
- `src/engine/entry.rs` — `render` maps `Shellcode` to the DLL entry block.
- `src/engine/compiler.rs` — `compiles_as_dll`, `panic_flag`, `verify_output_kind`.
- `src/engine/shellcode.rs` — sRDI location and the `convert` subprocess.
- `src/main.rs` — `intermediate_path`, the post-scrub conversion, and the tail.
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
   with destructors"). `vendor/srdi/ShellcodeRDI.c` now reserves a `TlsAlloc`
   index, publishes `_tls_index`, materializes the template into
   `TEB->ThreadLocalStoragePointer` (`gs:[0x58]` — the array a CRT reads, *not*
   `TlsSetValue`'s `TlsSlots`) and restores the slot before the thread exits so
   ntdll's teardown does not free the private block.

- Result: the full Rust-std stub (the packed DLL) runs from the `.bin`; a PE
  payload mapped reflectively prints `PAYLOAD_MARKER_7f3a9c2e`, and the runner
  returns cleanly.

## Non-goals

- A host that runs the shellcode: the artifact is the raw bytes; the operator
  chooses the runner (`msbuild` inline task, a JVM via the FFM API, …).
- `arch: x86` (parked until the entry has an sRDI-shaped `cdecl` export).
