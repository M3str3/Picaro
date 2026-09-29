# ntdll unhooking

## Metadata

- **ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)
- **Stability**: Experimental (runs end to end on x64 and x86; the
  `docs/measurements.md` baseline is still pending)
- **Category**: Preparation
- **YAML key**: `unhook_ntdll`
- **Introduced in**: unreleased (pre-wired skeleton batch)

## What it does

Restores the code section of the loaded `ntdll.dll` from a clean copy read from
disk, removing the userland hooks an EDR placed in the stub's own process. The
payload — and the loader's own `nt_*` helpers under `syscalls.mode: none` —
then call the real export prologues again. It does not run the payload; it only
modifies process state, which is why it is a Preparation technique.

The restore covers the whole code section, not just the `Nt*` syscall stubs, so
hooks on any other ntdll export (`Ldr*`, `Rtl*`, the `Etw*` family) go with it.

## YAML parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| — | — | — | — | No parameters: the target is always the loaded `ntdll.dll`, and the clean copy comes from the same path the syscall layer reads (`C:\Windows\System32\ntdll.dll`) |

The technique is deliberately parameterless. Letting a plan point the restore at
a different file would let the restored `.text` disagree with the SSN table
`init_syscalls()` resolved from the disk copy (see the interaction notes below),
and the loaded module is always the right target.

## YAML example

```yaml
runtime:
  - technique: unhook_ntdll
  - technique: patch_etw
  - technique: reflective_loading
    params:
      payload: implant
```

`unhook_ntdll` runs first: `patch_etw` writes into ntdll's `.text`, and the
restore would silently undo an earlier patch (see "Implementation notes").

## How it works

1. `GetModuleHandleA` fetches the loaded `ntdll.dll` base. The module is already
   loaded (the stub links against it), so this loads nothing.
2. `std::fs::read` reads a clean copy of the same file from disk. The path is
   obfuscated with `StringsConfig`, so it never appears in `.rdata`.
3. The fragment walks the *file's* PE headers to the `.text` section: it reads
   `NumberOfSections` and `SizeOfOptionalHeader` from the file header, finds the
   section named `.text` (compared as an 8-byte constant, not a string literal)
   and keeps `VirtualAddress`, `Misc.VirtualSize`, `SizeOfRawData` and
   `PointerToRawData`.
4. Guards, each with its own obfuscated diagnostic: the file must start with
   `MZ` and carry a `PE\0\0` signature, the section must be non-empty, and its
   raw range must lie inside the file (`PointerToRawData + SizeOfRawData <=
   file.len()`, overflow-checked). Nothing is ever truncated or skipped
   silently.
5. The live target is `module_base + VirtualAddress`; the copy length is
   `min(Misc.VirtualSize, SizeOfRawData)`, so the write stays inside the mapped
   section and the read stays inside the file.
6. `nt_protect_vm` makes exactly those bytes `PAGE_EXECUTE_READWRITE`, the
   clean bytes are copied over, and `nt_protect_vm` restores the original
   protection (`PAGE_EXECUTE_READ`). The write window has to stay executable:
   the protection call itself returns through ntdll's own
   `NtProtectVirtualMemory` stub, which is inside the region being rewritten, so
   a `PAGE_READWRITE` window would fault on the syscall's return path (measured;
   see "Implementation notes").
7. Before the protection is restored, the fragment applies the base relocations
   the loader would have applied to that section. A PE32 image stores absolute
   addresses in its code, so the file's bytes still hold the *preferred-base*
   values; each fixup inside the restored range is shifted by `live_base -
   preferred_base`. PE32+ ntdll is RIP-relative and has no fixups in `.text`,
   so the walk is a no-op there (see "Implementation notes").
8. The section is back to its original protection before the next step runs,
   and the step returns `Ok(true)`, so the pipeline continues.

Only the section is touched. The PE headers keep the offsets the system loader
already resolved, and the rest of the image (data, relocations, the export
directory) is left alone, so every export still points where it did.

## What it evades

- Userland API hooks an EDR installed in the stub's own process. This is the
  same problem `syscalls.mode: indirect` works around for the *loader's own*
  kernel calls; `unhook_ntdll` repairs the exports the *payload* (and the
  loader's Win32 entry points such as `LoadLibraryA`/`GetProcAddress`) call.
- Hooks beyond the syscall stubs: the whole `.text` is restored, so an EDR that
  hooks `LdrLoadDll`, an `Rtl*` helper or an `Etw*` export loses those hooks
  too.

## What detects it

- **Kernel telemetry on the protection change.** A page that was mapped from an
  image section becoming writable is a classic image-tampering signal. The
  kernel sees the `NtProtectVirtualMemory` call (ETW-TI,
  `Microsoft-Windows-Threat-Intelligence`, reports it) and the write that
  follows; going through the syscall layer hides the userland stub, not the
  kernel event. The window is `PAGE_EXECUTE_READWRITE` (the section contains the
  code returning from the protection call, so it cannot lose execute
  permission), which is exactly the RWX-on-an-image-page pattern heuristics
  look for.
- **Memory scanning.** An EDR that periodically re-reads ntdll's `.text` from
  disk, or compares it to a known-good copy, sees the hooks disappear — and
  some vendors simply re-install them after an unhook.
- **Hook-integrity self-checks.** A product that watches its own trampolines can
  notice they were overwritten and respond.
- **The file read itself.** Opening `ntdll.dll` for reading right before
  execution is suspicious on its own.
- Kernel callbacks (`PsSetCreateProcessNotifyRoutineEx`, etc.) are unaffected:
  this is a userland restore. It buys the payload a clean userland view, not
  kernel invisibility.

## Measurements

- Baseline and the two measured constraints (RWX window, x86 fixups) are in
  `docs/measurements.md`. Verified at run time with
  `code_examples/unhook_ntdll/smoke.yaml`:
  `unhook_ntdll` followed by `fibers` running the `mov eax, 42; ret` demo
  shellcode exits `42` on x64 with `syscalls: none` and `syscalls: indirect`,
  and on x86 (`smoke-x86.yaml`) — the restore ran first and did not break the
  following step. The debug trace confirms the size restored
  (`restored 1482908 bytes at 0x...`, i.e. the file's `.text` VirtualSize).
- The two scratch probes behind the design are in
  `code_examples/unhook_ntdll/harness/`: `probe_protect` (the `PAGE_READWRITE`
  fault vs. the working `PAGE_EXECUTE_READWRITE`) and `probe_relocs` (the x86
  fixups: 19 004 differing bytes before, 0 after).

## Implementation notes

### Order against the other preparations

- **`patch_etw` after, not before.** `patch_etw` overwrites
  `EtwEventWrite`/`EtwEventWriteFull` inside ntdll's `.text`. Because the
  restore copies the whole clean section over the live one, a `patch_etw` that
  ran earlier is silently undone. Put `unhook_ntdll` first, then `patch_etw`.
- **`patch_amsi` is unaffected.** It patches `AmsiScanBuffer` in `amsi.dll`, a
  different module, so the ntdll restore neither removes it nor depends on it.
  The general rule stands: any preparation that writes into ntdll's `.text`
  must run *after* this step, or its patch will be overwritten.
- **`bouncer` and the other preparations do not read ntdll's hooked stubs.**
  They use their own imports, so unhooking buys the payload a clean userland
  view — it does not change what the gate checks, and it is not kernel
  invisibility.
- **`syscalls.mode: indirect` is safe in either order, with one caveat.** The
  stub resolves the SSN table and the `syscall; ret` gadget inside live ntdll's
  `.text` in `init_syscalls()`, *before* any step runs, so the restore cannot
  invalidate something resolved later. The caveat: if the clean file on disk is
  a **different build** than the loaded image (e.g. Windows Update replaced
  `ntdll.dll` on disk between process start and step execution), the restored
  `.text` is not the code whose gadget address was found, and the gadget/SSNs
  could disagree with the bytes now at that address. The technique reads the
  same path the syscall layer reads precisely so both see the same build.
- **Only the loader's own process benefits.** A payload run in another process
  (`process_hollowing`, `early_bird`, `pe_injection`) executes against *that*
  process's ntdll, which is untouched.

### x86 needs the section's base relocations

A PE32 image stores absolute addresses in its code, and the loader rewrites each
of them when it maps the image at a base other than the preferred one. Measured
on this host: the live 32-bit ntdll (WOW64) differed from the file in **19 004
bytes** of its 1.25 MB `.text`, all of them HIGHLOW fields (`IMAGE_REL_BASED_HIGHLOW`,
9 502 entries inside the section plus 130 padding entries). Copying the raw file
bytes therefore installs a section whose absolute addresses point at
`0x4b280000` (the file's preferred base) instead of the live base — every call
through such an address crashes. The fragment walks the file's base-relocation
directory (data directory 5), keeps the entries that fall inside the restored
range and shifts each field by `live_base - preferred_base` (`wrapping_add`, so
the arithmetic is defined for both header formats). The same probe shows the
result is byte-identical to the live section: `probe_relocs` reports 19 004
differing bytes before the fixups and **0** after.

PE32+ ntdll is RIP-relative and has no fixups inside `.text` (measured: 0
differing bytes on x64), so the walk is a no-op there. A relocation kind the
fragment does not know (anything but ABSOLUTE, HIGHLOW and DIR64) *inside* the
restored range is a loud error, never a silent skip.

### Why the PE walk is a self-contained copy

The syscall layer's disk-reading resolvers (Tartarus Gate, API hashing) already
contain an RVA→offset walk, but it lives in `$FILE_PE_HELPERS$` inside the
*resolver body*: it is rendered only for those resolvers and is private to the
syscall block, so it does not exist under `syscalls.mode: none` or
`hells_gate`. Promoting it to a shared block would touch `src/engine/`
(outside this technique's scope). The fragment therefore carries its own
bounds-checked `read_u16`/`read_u32`/`read_u64` plus the section walk — small,
documented, and available in every configuration.

### Other notes

- **WOW64.** For an x86 stub, `C:\Windows\System32\ntdll.dll` is redirected by
  the WOW64 filesystem redirector to `SysWOW64\ntdll.dll`, which is exactly the
  32-bit image the process mapped, so the same obfuscated path works on both
  architectures — and the relocation fixups above make the file's bytes valid at
  the base the loader actually chose.
- **The write window is RWX, and it is brief.** The section being rewritten
  contains the `NtProtectVirtualMemory` stub (mode `none`) or the `syscall; ret`
  gadget (mode `indirect`) that the protection call returns through, so the
  window cannot be `PAGE_READWRITE`: dropping execute permission faults on the
  syscall's return path. The standalone probe
  `code_examples/unhook_ntdll/harness/probe_protect.rs` measured exactly that —
  `rw` dies inside `VirtualProtectEx`, `rwx` completes the copy and the
  restore. The original `PAGE_EXECUTE_READ` protection is restored before the
  step returns, so the section is never left writable; a failed restore is a
  loud error, not a silent skip.
- **The `.text` name is a constant, not a string.** It is compared as
  `u64::from_le_bytes([b'.', b't', b'e', b'x', b't', 0, 0, 0])`, so it lands in
  the code as an immediate, never in `.rdata`.
- **Every runtime string is obfuscated.** The module name, the path and all
  eight diagnostics go through `StringsConfig::obfuscate` in `render_fragment`
  (`MESSAGES`), so no diagnostic text and no technique keyword reaches `.rdata`.
- **The protection change is itself a target.** With `mode: none` the change
  goes through `VirtualProtectEx` (kernel32 → ntdll), so a hook on it can block
  or revert the restore — MDSec notes exactly this. `mode: indirect` issues the
  change as a direct `syscall` from the loader and skips the userland stub; the
  kernel still sees the event.
- **`GetModuleHandleA` and `std::fs::read` stay Win32/host entry points**, like
  `LoadLibraryA` elsewhere; only the protection change goes through the syscall
  layer (`nt_protect_vm`), so `mode: indirect` removes the `VirtualProtect`
  import.
- **No relocations are applied.** ntdll's `.text` has none, and the headers are
  not restored, so this is correct for this target.

## References

- ired.team — *Full DLL Unhooking with C++*:
  <https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++>
- MDSec — *Bypassing User-Mode Hooks and Direct Invocation of System Calls for
  Red Teams*:
  <https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/>
- SysWhispers (direct system calls, and the related-reading list):
  <https://github.com/jthuraisamy/SysWhispers>
- MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools.
