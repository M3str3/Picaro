# Module stomping

## Metadata

- **ATT&CK**: T1055 (Process Injection)
- **Stability**: Experimental (packs, compiles, is statically measured and was
  run end to end: the packed artifact relays the payload's exit code)
- **YAML key**: `module_stomping`
- **Payload format**: `shellcode` only (see “Payload formats”)
- **Introduced in**: v0.1.0 (parallel technique batch, schema 6)

## What it does

Loads a legitimate, signed DLL, overwrites the first bytes of its code section
(`.text`) with the decrypted payload and calls it, so the executing code lives
inside a module the process already maps instead of in a private executable
allocation.

## YAML parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `payload` | string | no | the only declared payload | Name of the payload in `build.payloads` to run |
| `module` | string | no | `wininet.dll` | Module to load and stomp: a name the loader resolves or a full path |

The payload's binary format comes from `build.payloads.<name>`; see “Payload
formats”. `build.output.arch` selects the stub's bitness, and the module is
loaded by the stub's own loader, so it must be of that bitness too.

Do not name a module another step patches or hooks — `patch_amsi` (which patches
`amsi.dll`) is the obvious example: the stomp would overwrite the patched code.

## YAML example

```yaml
build:
  payloads:
    implant:
      source: ./beacon.bin
      format: shellcode
runtime:
  - technique: module_stomping
    params:
      payload: implant
      module: wininet.dll
```

```yaml
# Defaults: the only payload, and wininet.dll as the stomp target.
runtime:
  - technique: module_stomping
```

## How it works

1. `LoadLibraryA` maps the stomp target. If it is already loaded the call only
   bumps its reference count, and the module keeps whatever base it has; the
   loader (not this technique) does the mapping, the catalog/hash bookkeeping and
   the `DllMain(DLL_PROCESS_ATTACH)` call.
2. The module's *mapped* PE headers are copied into a local buffer and walked to
   the `.text` section: `VirtualAddress` gives the section's address in the
   mapped image, `max(VirtualSize, SizeOfRawData)` its capacity. The walk is
   bounds-checked slice arithmetic; a malformed target fails the load instead of
   faulting the stub.
3. The payload's length is checked against that capacity. A payload that does not
   fit **fails the step** — it is never truncated, and it is never written past
   the section into whatever the loader mapped next.
4. Only the pages the payload occupies are made writable
   (`PAGE_READWRITE` through `nt_protect_vm`, the captured old protection is kept
   for step 6). The rest of the section keeps its protection, and the section is
   writable and non-executable during the write, so it is never RWX.
5. The payload is copied over the section's first bytes with a plain `memcpy`
   (`ptr::copy_nonoverlapping`). This is the loader's own address space, so a
   write API would only add a call to hook and a partial-write failure mode.
6. The captured protection is restored — `.text` ships `PAGE_EXECUTE_READ`, so
   the section is executable and read-only again. If the restore fails, the
   payload does not run (a read-write section would fault on the first
   instruction).
7. The PEB command line is repointed at the payload's configured arguments
   (`crate::patch_command_line`, shared with `reflective_loading`), and control
   is transferred with a **direct call** to the section's first byte. The
   payload's return value becomes the step's result, so the technique *returns*
   and the runtime chain can continue (a payload that calls `ExitProcess` ends
   the whole stub instead).

### Decisions

- **Whole-section stomp, starting at the section's first byte.** The classic
  variant overwrites `AddressOfEntryPoint` instead, which puts the payload in the
  middle of the section and forces the capacity check to account for the entry
  offset. The section's first byte is page-aligned and 16-byte aligned in every
  real image, and the whole section is the natural size bound.
- **No restore of the original bytes.** The sacrificial module is left broken by
  design: it is unusable after the stomp either way (its entry stub is gone), and
  keeping a copy of the original bytes in the loader would be a fresh signature.
- **`memcpy`, not `nt_write_vm`.** `NtWriteVirtualMemory` on one's own process is
  a call an EDR can watch and can fail halfway; the copy needs neither.
- **Direct call, not a new thread.** A thread would make the payload's start
  address visible in thread telemetry (its start address is inside a module that
  never called anything), and it would break the “execution techniques return”
  contract used by the runtime chain. The cost is that the payload runs on the
  loader's thread and stack.
- **Restore before executing.** Keeps the section out of the RWX state some
  scanners flag, and keeps the final protection indistinguishable from the
  module's normal one. It also means the payload may not self-modify its own
  first bytes (see “Implementation notes”).
- **No `FlushInstructionCache`.** The x86/x64 instruction cache is coherent with
  data writes on the same core; every stub fragment also crosses a kernel
  boundary (`NtProtectVirtualMemory`) before the call. A `nt_flush_instruction_cache`
  helper would be needed to add the call through the syscall layer.

### Payload formats

The technique runs **`format: shellcode`** only: the bytes are placed in the code
section as-is and called with a no-argument contract, exactly like
`reflective_loading`'s shellcode runner. A `pe`/`dll` payload would need a mapper
(relocations, imports, per-section protections) and `dotnet` a CLR host —
`reflective_loading` and `dotnet_hosting` do that. `plan::validate` rejects
`pe`/`dll`/`dotnet` for this technique at build time, and the fragment also
detects a PE payload at runtime (`MZ` + `PE\0\0`) and fails the step with a clear
message instead of jumping into a DOS header.

## What it evades

- The payload never touches disk: it is decrypted in memory and written into a
  module the image already maps.
- No private executable allocation and no `VirtualAlloc`/`VirtualAllocEx` for the
  payload, so a “fresh executable memory” heuristic has nothing new to flag.
- No `Add-Type`-style child process, no remote target, no new thread.
- The pages the payload runs from belong to a Microsoft-signed module: a memory
  scan that groups executable regions by module reports the payload under
  `wininet.dll`'s image, not under an anonymous region.
- The write itself is not an API call: `LoadLibraryA` (a common, boring import)
  plus two `NtProtectVirtualMemory` calls are the whole kernel-visible surface,
  and `build.stub.syscalls.mode: indirect` takes the `VirtualProtect` import away
  as well.

## What detects it

- **Page-protection telemetry.** `NtProtectVirtualMemory` (ETW-TI
  `Microsoft-Windows-Threat-Intelligence`, kernel callbacks, userland hooks in
  `mode: none`) fires twice per stomp on a *signed module's* code pages:
  `RX → RW` and `RW → RX`. A module's `.text` becoming writable and writable code
  pages appearing inside a loaded module are both high-signal.
- **Image-load telemetry and module integrity checks.** `LoadLibraryA` on a
  module the process never uses is itself a signal, and anything that
  re-validates a module after load — comparing the mapped section against the
  file on disk, hashing `.text`, or checking for executable pages that differ
  from the module's on-disk image — sees the payload. The stomped pages are no
  longer file-backed (copy-on-write private pages inside the module's address
  range), which is exactly what the phantom-DLL-hollowing literature describes as
  the residual artifact of this technique family.
- **Stack and call-graph inspection.** The payload runs from the loader's own
  thread, so a stack walk shows a return address inside a module that has no
  legitimate caller on that thread; a thread-start-address heuristic does *not*
  fire (no new thread), which cuts both ways.
- **In-memory scanning / YARA.** The payload's own signatures apply unchanged
  once its bytes are in the section.
- **Import-based heuristics.** `LoadLibraryA` + `GetCurrentProcess` in the import
  table of a stub that does not otherwise use those modules.
- `patch_amsi`-style combinations break *each other* (see the parameter warning),
  which some products detect as a patched function reverting to its original
  bytes.

## Measurements

Static baseline of the smoke artifact
(`code_examples/module_stomping/smoke.yaml`, the 6-byte
`examples/payloads/demo_shellcode.bin`, x64, `strings: xor`, `syscalls: none`),
as reported by `picaro audit`:

```text
size 387 584 bytes · x64 · console · unsigned · no overlay
.text 276 KB (entropy 6.26)   .rdata 84 KB (5.19)   .data 3 KB
.pdata 11 KB (5.61)           .reloc 3 KB (5.35)
imports: 3 DLLs, 94 functions — includes LoadLibraryA, GetCurrentProcess and
         VirtualProtectEx (the syscalls.mode: none mapping of nt_protect_vm);
         no VirtualAlloc, WriteProcessMemory, CreateThread or CreateRemoteThread
strings: 0 sensitive, 0 technique names, 0 paths/URLs — the stomp target and
         the diagnostics are rebuilt at runtime
summary: LOW RISK
```

The `Sensitive:` line is empty, which is the property the `StringsConfig`
routing buys: neither `wininet.dll` (the default target) nor any diagnostic text
appears in the artifact. `docs/measurements.md` still needs this as its own
section (owned by the docs workstream), together with the runtime baseline once
the technique is verified end to end.

## Implementation notes

- **The target is a parameter, not a constant.** The default (`wininet.dll`) is a
  Microsoft-signed module present on every SKU with a code section large enough
  for a staged payload. On a host where it is missing (some Server Core images),
  `LoadLibraryA` fails and the step reports it — pick another signed module
  (`dbghelp.dll`, `xpsservices.dll`, `iertutil.dll`, `mshtml.dll`, ...).
  Measured `.text` capacity on Windows 11 26100 with
  `code_examples/module_stomping/pe_walk_check.rs`: `wininet.dll` 1.87 MB,
  `xpsservices.dll` 1.79 MB, `dbghelp.dll` 1.63 MB, `iertutil.dll` 561 KB,
  `mshtml.dll` 17.8 MB, `amsi.dll` **52 KB** — a staged payload rarely fits
  `amsi.dll`, on top of the `patch_amsi` conflict above.
- **The stomp target is obfuscated.** Its name is rebuilt at runtime by
  `render_fragment_for` (`StringsConfig`), like every other runtime string in the
  fragment, and the `.text` name is a compile-time byte pattern
  (`u64::from_le_bytes([b'.', b't', b'e', b'x', b't', 0, 0, 0])`), so no section
  name reaches `.rdata` either.
- **`LoadLibraryA` stays a Win32 import.** Loading a module is a loader entry
  point, not a kernel call the stub issues itself — the same position as
  `CreateProcessA` in `process_hollowing`. Everything kernel-facing
  (`nt_protect_vm`) goes through the syscall layer, so `mode: indirect` removes
  the `VirtualProtect`/`VirtualProtectEx` imports.
- **Limitations.** The payload may not be larger than the target's `.text` and
  may not self-modify its own first bytes (the section is read-only again when it
  runs; a payload that needs writable code needs a custom stub or a different
  protection policy). Stomping a module the process actually uses breaks that
  module. Stomping the module a previous step patched (`amsi.dll` after
  `patch_amsi`) undoes that patch. Like the rest of the family, the win is
  *memory-region provenance*, not “no private executable memory”: the stomped
  pages are private copies inside the module's range once written.
- **Not implemented here (follow-ups).** A `pe`/`dll` mapper into the stomped
  section (would need `resolves_imports: true` and the shared resolver), and a
  knob for the final protection (`pagerwx` for payloads that need writable code).

## References

- ired.team — *Module Stomping for Shellcode Injection*:
  <https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection>
  (the classic write-up: load a benign DLL, overwrite its entry point, run a
  thread there; this fragment stomps the section's first bytes and calls them
  directly instead).
- MITRE ATT&CK T1055 — *Process Injection*: <https://attack.mitre.org/techniques/T1055/>
  (no module-stomping sub-technique exists; ATT&CK's own procedure examples put
  `.text`-section stomping of a system DLL here — e.g. DUSTTRAP, S1159).
- Microsoft Learn — *LoadLibraryA*:
  <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya>
  (reference-counting and “already loaded” semantics the fragment relies on).
- Microsoft Learn — *FlushInstructionCache*:
  <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache>
  (the documented call for modified code; deliberately skipped here, see
  “Decisions”).
