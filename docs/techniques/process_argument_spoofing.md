# Process argument spoofing / payload arguments

- ATT&CK: T1036 (Masquerading), T1055 (Process Injection) context
- YAML key: `build.payload.args`, `build.payload.args_mode`
- Introduced in: payload-arguments phase

## What it does

A packed binary is a stub, not the payload: the operator runs the stub, which
decrypts the payload and hands control to it. The payload therefore needs an
explicit command line. `build.payload.args` fixes arguments at build time and
`args_mode` decides how they combine with the arguments the operator passes to
the packed binary.

## YAML

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

Example with `join`, running `./dist/mimi.exe "sekurlsa::logonpasswords"`:

```
privilege::debug
log C:\temp\out.log
sekurlsa::logonpasswords
```

> The first token of a Windows command line is always the executable name, not
> an argument. The payload's `argv[0]` is the exe (the hollowing target's name,
> or the stub's own path for reflective loading); the payload args start at
> `argv[1]`. A payload that wants only the arguments drops `argv[0]`
> (`CommandLineToArgvW` does it automatically).

## How the stub builds it

`src/engine/args.rs` renders `$ARGS_BLOCK$` once, and both execution techniques
consume it:

- the YAML args are embedded as runtime-reconstructed strings (through
  `StringsConfig`), so a mimikatz module name never lands in cleartext;
- `resolve()`/`build_command_line(exe)` apply `args_mode` and Windows quoting
  (`CommandLineToArgvW` rules);
- `patch_command_line()` rewrites the *current* process's command line for
  reflective loading.

The fragment contract mirrors the syscall layer: fragments call
`crate::build_command_line` / `crate::patch_command_line` and never touch the
arguments themselves.

## process_hollowing

The built line is passed as `lpCommandLine` to `CreateProcessA`:

```
CreateProcessA(
  target,                              // C:\Windows\System32\svchost.exe
  "svchost.exe privilege::debug ...",  // built command line
  ...
)
```

When the target's image is unmapped and the payload is mapped over it, the
target's `RTL_USER_PROCESS_PARAMETERS` (and the CRT state the target's loader
already initialized from it) keep that command line, so `GetCommandLineW`
returns it.

## reflective_loading: why the PEB write alone is not enough

The payload runs in the *stub's own* process, so the stub's command line has to
be replaced first. The documented step is to repoint
`PEB->ProcessParameters->CommandLine` (a `UNICODE_STRING` at PEB+0x20 →
+0x70 on x64; Length at +0, MaximumLength at +2, Buffer at +8, 16-byte aligned)
at a new UTF-16 buffer.

Measured on Windows 11, that alone is **not** enough: `GetCommandLineW` does not
re-read that field. Instead `kernelbase.dll` caches the command-line pointer at
process start and returns it, so a patched PEB is visible to tools that read the
PEB but the payload's CRT still gets the stub's command line. The cache was
located by scanning `kernelbase` for the original buffer pointer (found at
`kernelbase+0x3af048` on the test machine).

`patch_command_line()` therefore:

1. repoints the PEB `CommandLine` at the new buffer (PEB readers), and
2. finds `kernelbase`'s cached pointer **by value** (the original buffer
   address) and repoints it too (so `GetCommandLineW` and the CRT agree).

The scan uses `SizeOfImage` from `kernelbase`'s PE header, so no
version-specific offset is hardcoded, and it is a no-op where no such cache
exists.

The new buffer is intentionally leaked: the PEB and the cache must keep
pointing at live memory for the rest of the process.

## Strings

The YAML args are sensitive (e.g. `sekurlsa::logonpasswords` is a mimikatz
signature) and go through `StringsConfig`. `SENSITIVE_LITERALS`
(`src/audit/strings.rs`) includes `sekurlsa::logonpasswords` and
`privilege::debug`, and the `#[ignore]` guardrail
(`no_sensitive_literals_in_generated_stubs`) covers the generated args block.

## DLL and shellcode inputs

`build.payload.format: dll`/`shellcode` run in the current process under
`reflective_loading`, so the same `patch_command_line()` step runs before they
start and the PEB (and `kernelbase`'s cached pointer) carry the configured args:

- **shellcode** has no PE entry point that reads a command line, but the loader
  still patches the PEB first, so shellcode that calls `GetCommandLineW` sees
  `<exe> <yaml args> <runtime args>`. The delivery is the standard Windows
  command line; a blob that expects a bespoke hand-off struct is out of scope.
- **DLL**: after mapping (and `DllMain(DLL_PROCESS_ATTACH)`),
  `build.payload.export` names the exported function to call. It is invoked with
  no arguments (the calling convention is `extern "system"`, i.e. the x64
  default), so an export that wants the command line reads it from the PEB.

Process hollowing cannot run a DLL or shellcode, so those formats are an
in-process (`reflective_loading`) feature.

## Detections

- `kernelbase`'s cached command line and the PEB can both be read by userland
  tooling; cross-checking them against the image path / parent's command line
  exposes the mismatch.
- ETW-TI reports the memory writes into `kernelbase` (a signed module).
- The stub's IAT is unchanged by this feature; the static signature is the
  previously obfuscated arg strings, which stay encrypted.

## References

- MITRE ATT&CK T1036 — Masquerading.
- Windows internals: `RTL_USER_PROCESS_PARAMETERS`, `GetCommandLineW`.
