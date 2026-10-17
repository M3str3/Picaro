# Process ghosting

*Runs the payload from a delete-on-close temporary file mapped as a section, so
the mapped image outlives the file name and executes with no on-disk backing.*

## What it does

Runs the decrypted payload with no backing file on disk. The payload is
written to a unique temp file that is immediately marked delete-on-close,
turned into a section, and mapped into the current process; the file handle is
then closed so the file's name disappears while the section keeps the bytes
alive. The mapped image is relocated, its imports are resolved, and its entry
point runs in the loader's process.

## How it works

```mermaid
flowchart TD
    A[Write payload to a unique temp file] --> B[Reopen and mark delete-on-close]
    B --> C[Create RWX section over the file]
    C --> D[Map the section into the current process]
    D --> E[Close the handle - the name vanishes]
    E --> F[Relocate and resolve imports]
    F --> G[Jump to the entry point, relay exit code]
```

### 1. Stage the payload as a file

1. Writes the decrypted payload to a unique file under the process temp
   directory.
2. Re-opens it with `CreateFileW` (`FILE_READ_DATA | FILE_WRITE_DATA | DELETE`,
   sharing `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`) and marks
   it delete-on-close with `SetFileInformationByHandle` +
   `FileDispositionInfo` (`DeleteFile = true`).

### 2. Map it while the name disappears

3. Creates a `PAGE_EXECUTE_READWRITE` section over the file
   (`CreateFileMappingW`) and maps it into the current process
   (`MapViewOfFile`).
4. Closes the file handle. The delete-on-close disposition takes effect — the
   file's name disappears — but the section (and the view) keep the bytes
   alive.

### 3. Run the mapped image

5. Applies base relocations for the view's actual base, resolves the payload's
   imports through the shared resolver (`crate::patch_imports`), and jumps to
   the entry point, relaying its exit code.

## Integration

An **Execution** step: it runs a `pe` payload from the loader's own
process. It maps the image from a delete-on-close file, so there is no
backing file on disk.

## What it evades

- **Fileless execution**: by the time the entry point runs, the payload has no
  file name on disk — a scanner that walks the temp directory sees nothing to
  inspect.
- **No `VirtualAlloc`-style RWX allocation**: the image lives in a
  file-backed section, not in a freshly committed private region the way manual
  mapping allocates it.

## What detects it

- **The temp file exists transiently on disk** between the write and the
  handle close, so a file-system monitor (or a minifilter) can still catch the
  write and the delete-on-close disposition.
- **A `PAGE_EXECUTE_READWRITE` section** is a strong signal to memory scanners;
  the whole mapped view is RWX rather than per-section protected.
- **The delete-on-close / `FileDispositionInfo` pattern** is itself a known
  process-ghosting tell, as is a mapped section whose backing file has vanished.

## Measurements

- Measured on Windows 11 26200 (2026-10-14): **the technique does not run.** The
  first host run failed at `CreateFileMappingW(PAGE_EXECUTE_READWRITE)` with
  `ERROR_ACCESS_DENIED` — a delete-pending file refuses a writable mapping. The
  alternatives were measured too: mapping it read-only fails later because a data
  mapping keeps *file* offsets, so the image's RVAs do not line up; creating the
  writable section first makes the delete-on-close mark fail with the same error.
  A working implementation needs an image section (`NtCreateSection(SEC_IMAGE)`
  + `NtMapViewOfSection`), which the syscall layer does not have yet — so the
  registry marks the technique `Unimplemented` and a build that selects it warns.
  Full diagnosis: `docs/measurements.md`.

## Implementation notes

- **Win32 only, no syscalls.** The file → section → map flow uses
  `CreateFileW`, `SetFileInformationByHandle`, `CreateFileMappingW`,
  `MapViewOfFile` and `CloseHandle` directly (they are loader entry points, not
  kernel calls the stub issues), so `DEF.syscalls` is empty and the fragment is
  identical for `syscalls.mode: none` and `indirect`.
- **The mapped view is treated as an image-layout view** (`RVA == offset`), the
  same assumption reflective loading makes. A production implementation must
  confirm this against `SEC_IMAGE` versus a raw data section, and either apply
  per-section protections or expand the sections manually; the current fragment
  keeps the whole view `PAGE_EXECUTE_READWRITE`. This is the main open
  verification item.
- **PE only.** The fragment is a PE mapper; `plan::validate` rejects
  `shellcode`/`dll`/`dotnet` payloads for this technique.
- **Runs in-process and returns.** The entry point is called on the loader's
  thread and its exit code is relayed, so the technique is chainable in a
  schema-6 `runtime:` list (it is not terminal the way reflective loading of a
  PE *executable* is).

## References

- Elastic Security Labs, "Process Ghosting: A New Executable Image Tampering
  Attack" (Gabriel Landau, 2021).
- MITRE ATT&CK, "Process Injection: Process Doppelgänging" (T1055.012).
- Microsoft, `SetFileInformationByHandle` and `FILE_DISPOSITION_INFO`
  (`winbase.h`).
