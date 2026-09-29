# Self-deletion

## Metadata

- **ATT&CK**: T1070.004 (Indicator Removal: File Deletion)
- **Stability**: Experimental
- **YAML key**: `self_deletion`
- **Introduced in**: unreleased (self-deletion)

## What it does

Deals with the running artifact's own image while the loader executes from it:
by default it renames the file into an alternate data stream of its own path, so
the loader's bytes leave the file that the path names; with `mode: helper` it
spawns a detached child that deletes the file once the loader has exited.

## YAML parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `mode` | string | no | `rename_ads` | `rename_ads` (moves the image into an ADS of its own path) or `helper` (a detached `cmd.exe` deletes the file after the loader exits) |
| `stream` | string | no | random per build | `mode: rename_ads` only: the alternate data stream name, starting with `:` |

## YAML example

```yaml
runtime:
  - technique: self_deletion
    params:
      mode: rename_ads
  - technique: thread_hijacking
    params:
      target: notepad.exe
```

## How it works

### `rename_ads` (default)

1. Reads the running image's path with `GetModuleFileNameW(NULL)`. Nothing is
   embedded in the stub: the loader acts on whatever file it was launched from.
2. Opens it with `DELETE | SYNCHRONIZE` and `FILE_SHARE_READ` — the share mode a
   mapped image tolerates.
3. `nt_set_info_file` with `FileRenameInformation` (class 10) and a
   `FILE_RENAME_INFO` naming `:stream`: the file is renamed into an alternate
   data stream *of itself*. The default stream is left empty and the loader keeps
   executing from the still-mapped section.
4. Closes the handle. A preparation returns `Ok(true)`, so the chain continues.

### `helper`

1. Reads the path the same way.
2. `CreateProcessA` a detached `cmd.exe` (`CREATE_NO_WINDOW`, handles closed
   immediately) running
   `ping -n 3 127.0.0.1 >nul & del /f /q "<path>"` — a two-second sleep and a
   delete. The loader is expected to exit right after its last step, so the image
   is no longer mapped when the delete lands.

### Why not `FileDispositionInformation`?

Because a *mapped* image cannot be deleted on current Windows, and it is worth
recording how that was established rather than assumed. A stand-in process (a
.NET exe, same loader semantics: open its own path, set the disposition) was run
against this host with four combinations — the probe is committed as
`code_examples/self_deletion/probe.cs`:

| Variant | Result |
|---------|--------|
| `FileDispositionInformationEx` (64) with `DELETE \| POSIX_SEMANTICS`, share `READ\|WRITE\|DELETE` | `FALSE`, `ERROR_ACCESS_DENIED` (5) |
| `FileDispositionInformation` (13), share `READ\|WRITE\|DELETE` | `FALSE`, `ERROR_ACCESS_DENIED` (5) |
| `FileDispositionInformation` (13), share `READ` | `FALSE`, `ERROR_ACCESS_DENIED` (5) |
| `FileDispositionInformationEx` (64) with `DELETE`, share `READ` | `FALSE`, `ERROR_ACCESS_DENIED` (5) |
| `FileRenameInformation` (10) to `:stream`, share `READ` | **`TRUE`** |

The memory manager refuses the delete of a file with a live image section
(`STATUS_CANNOT_DELETE` through the native call, `ERROR_ACCESS_DENIED` through
`SetFileInformationByHandle`), while the rename goes through. That is the whole
reason the default is what it is.

### Where it goes in `runtime:`

A preparation returns `Ok(true)`, so the chain always continues. Its position
decides *when* the file is dealt with:

- **Before a terminal execution step** (`reflective_loading` of a PE,
  `dotnet_hosting`): the correct and most common placement — the image is dealt
  with before the payload takes over, and it stays dealt with even if the payload
  crashes. `plan::validate` forces this shape anyway: a terminal step must be
  last.
- **After a returning execution step** (`thread_hijacking`, `early_bird`,
  `process_hollowing`, the shellcode runners): the file is dealt with once the
  payload has returned. With `mode: helper` this is also when the loader is about
  to exit, which is what the helper's sleep budget assumes.

## What it evades

- **Post-run collection.** `rename_ads` empties the file the path names: copying
  the artifact off the host after the fact yields a zero-byte file, not the
  loader. `helper` removes the file entirely.
- **Signature-by-hash lookups.** A responder who reaches for the file at the
  path it ran from gets nothing to hash, unless they enumerate streams.
- **Path-based detection.** A rule watching the artifact's path stops matching
  the image the moment the step runs.

## What detects it

- **The metadata change itself.** A `FileRenameInformation` call on a *running*
  image, or a delete of one, is a strong EDR signal on its own.
- **The alternate data stream.** It is not invisible: `dir /r`,
  `Get-Item -Stream *` and most forensic collectors enumerate streams, and the
  loader's bytes sit there in full until the file is deleted.
- **Memory acquisition.** The image is still mapped in the running process, so a
  memory dump recovers the artifact byte for byte. This technique buys *time*,
  not immunity.
- **`mode: helper`.** The child process, its command line (`cmd.exe`,
  `del /f /q`) and the two-second window are all visible; the technique's own
  README does not pretend otherwise.
- **USN journal, MFT and Prefetch.** The rename and the delete are recorded even
  when the name is not.

## Measurements

Measured on the packing host (`x86_64-pc-windows-msvc`, release stub), a
self-deleting loader that then runs an in-process shellcode payload:

| Quantity | Value |
|----------|-------|
| The artifact's path after `rename_ads` | present and **0 bytes**; the image bytes live in the `:stream` ADS |
| The artifact's path after `helper` | gone once the loader exited |
| The loader's own path open | `DELETE \| SYNCHRONIZE`, share `READ` |
| The process after the step | still running the payload |

## Implementation notes

- The path is read from the process, never embedded, so there is no per-build
  path to obfuscate here — but the stream name, the helper's name and its command
  line all go through `StringsConfig`, and the `tech_dbg!` line is compiled out
  unless `build.stub.debug: true`.
- `FILE_RENAME_INFO` is built as a byte buffer with the exact layout class 10
  expects (`ReplaceIfExists`, `RootDirectory`, the byte length, the UTF-16 name);
  the variable-length tail is why it is not a struct.
- `IO_STATUS_BLOCK` is a local `[u64; 2]`: the loader only needs the space to be
  the right size.
- The stream name defaults to random six bytes per build, so it is not a constant
  a signature can key on.
- `rename_ads` needs NTFS (alternate data streams are an NTFS feature); on FAT
  the rename is refused and the step reports it.
- The helper's two-second delay is a budget, not a guarantee: a loader that is
  still alive when the helper fires leaves the file in place (`del` fails
  silently). It is the reason `rename_ads` — which needs no timing at all — is
  the default.

## References

- MITRE ATT&CK T1070.004 — Indicator Removal: File Deletion.
- Microsoft, `FILE_RENAME_INFO` / `FILE_DISPOSITION_INFO_EX` (`winbase.h`),
  `SetFileInformationByHandle` and `FILE_INFORMATION_CLASS`.
- RustRedOps' *Self-Deletion* example (local reference, visitable in
  `code_examples/RustRedOps/Self-Deletion/`): the ADS-rename recipe this
  technique's default follows.
- The probe that established the table above:
  `code_examples/self_deletion/probe.cs`.
