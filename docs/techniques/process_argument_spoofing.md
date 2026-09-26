# Payload arguments

- ATT&CK: T1036 (Masquerading), T1055 (Process Injection) context
- YAML: `build.payload.args`, `build.payload.args_mode`

## What it does

A packed binary is a stub, not the payload: the operator runs the stub, which
decrypts the payload and hands control to it. The payload therefore needs an
explicit command line. `args` fixes arguments at build time and `args_mode`
decides how they combine with the arguments the operator passes to the packed
binary.

```yaml
build:
  payload:
    source: "./mimikatz.exe"
    args:                          # optional
      - "privilege::debug"
      - "log"
      - "C:\\temp\\out.log"
    args_mode: join                # join (default) | override
```

- `join`: the payload gets the YAML args followed by the runtime args.
- `override`: the runtime args replace the YAML args; with no runtime args, the
  YAML ones are used.

With `join`, running `./dist/mimi.exe "sekurlsa::logonpasswords"` yields:

```
privilege::debug
log C:\temp\out.log
sekurlsa::logonpasswords
```

The first token of a Windows command line is always the executable name, so the
payload's `argv[0]` is the exe and its args start at `argv[1]`.

## How the stub builds it

`src/engine/args.rs` renders `$ARGS_BLOCK$` once, and both execution techniques
consume it:

- the YAML args are embedded as runtime-reconstructed strings (through
  `StringsConfig`), so a mimikatz module name never lands in cleartext;
- `resolve()`/`build_command_line(exe)` apply `args_mode` and Windows quoting
  (`CommandLineToArgvW` rules);
- `patch_command_line()` rewrites the *current* process's command line for
  reflective loading.

Fragments call `crate::build_command_line` / `crate::patch_command_line` and
never touch the arguments themselves.

## `process_hollowing`

The built line is passed as `lpCommandLine` to `CreateProcessA`. When the
target's image is unmapped and the payload is mapped over it, the target's
`RTL_USER_PROCESS_PARAMETERS` (and the CRT state the target's loader already
initialized from it) keep that command line, so `GetCommandLineW` returns it.

## `reflective_loading`: why the PEB write alone is not enough

The payload runs in the stub's own process, so the stub's command line has to be
replaced first. Repointing
`PEB->ProcessParameters->CommandLine` (a `UNICODE_STRING` at PEB+0x20 → +0x70 on
x64) at a new UTF-16 buffer is the documented step — but measured on Windows 11
it is **not** enough: `GetCommandLineW` does not re-read that field. Instead
`kernelbase.dll` caches the command-line pointer at process start and returns it,
so the payload's CRT still sees the stub's command line.

`patch_command_line()` therefore:

1. repoints the PEB `CommandLine` at the new buffer (what PEB-reading tools see),
   and
2. finds `kernelbase`'s cached pointer **by value** (the original buffer address)
   and repoints it too, so `GetCommandLineW` and the CRT agree.

The scan uses `SizeOfImage` from `kernelbase`'s PE header, so no
version-specific offset is hardcoded, and it is a no-op where no such cache
exists. The new buffer is intentionally leaked: the PEB and the cache must keep
pointing at live memory.

## DLL and shellcode inputs

`format: dll`/`shellcode` run in the current process under `reflective_loading`,
so the same `patch_command_line()` step runs before they start:

- **shellcode** has no PE entry point that reads a command line, but the loader
  still patches the PEB, so shellcode that calls `GetCommandLineW` sees
  `<exe> <yaml args> <runtime args>`. A blob that expects a bespoke hand-off
  struct is out of scope.
- **DLL**: after `DllMain(DLL_PROCESS_ATTACH)`, `build.payload.export` names the
  exported function to call; it is invoked with no arguments, so an export that
  wants the command line reads it from the PEB.

## Detections

- `kernelbase`'s cached command line and the PEB can both be read by userland
  tooling; cross-checking them against the image path / parent's command line
  exposes the mismatch.
- ETW-TI reports the memory writes into `kernelbase` (a signed module).
- The stub's IAT is unchanged by this feature; the YAML args stay encrypted.

## References

- MITRE ATT&CK T1036 — Masquerading.
- Windows internals: `RTL_USER_PROCESS_PARAMETERS`, `GetCommandLineW`.
