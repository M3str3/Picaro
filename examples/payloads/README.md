# Payload fixtures

Two kinds of file live here, and the difference matters: a **committed binary**
is part of the repository, so a fresh clone already has it, while a **generated
binary** is ignored by git and has to be built before whatever needs it runs.
`.gitignore` ignores `*.exe` and `*.bin` everywhere, so every committed binary is
re-included there explicitly; `tests/fixture_policy.rs` fails when a committed
binary has no exception or a build script names a missing source.

## Committed binaries

| File | Built from | Used by |
| --- | --- | --- |
| `msgbox.exe` (x64) | `msgbox.rs` | `examples/README.md`, visible hollowing check |
| `test_payload.exe` (x64) | `test_payload.rs` | `examples/plans/*.yaml`, CLI tests |
| `test_payload_x86.exe` (x86) | `test_payload.rs` | `examples/plans/x86.yaml` |
| `demo_shellcode.bin` | six hand-written bytes (`mov eax, 42; ret`) | shellcode plans, `docs/multistage.md` |

Regenerate them with the script that matches the binary:

```powershell
powershell -ExecutionPolicy Bypass -File examples/payloads/build_msgbox.ps1
powershell -ExecutionPolicy Bypass -File examples/payloads/build_test_payload.ps1            # x64
powershell -ExecutionPolicy Bypass -File examples/payloads/build_test_payload.ps1 -Arch x86  # x86
```

`demo_shellcode.bin` has no generator: it is six bytes and stays as it is.

## Generated binaries

Ignored by git; build them right before the run that needs them.

| File | Built from | Needed by |
| --- | --- | --- |
| `hello_world.exe` | `hello_world.rs` | `tests/reproduction.rs`, only under `live-tests` |
| `test_args_payload.exe` | `test_args_payload.rs` | manual runs, alongside the `build_args_payload` script |

```powershell
powershell -ExecutionPolicy Bypass -File examples/payloads/build_hello_world.ps1
powershell -ExecutionPolicy Bypass -File examples/payloads/build_args_payload.ps1
```

The default `cargo test` suite compiles the payload sources it needs — `probe_payload.rs`,
`test_args_payload.rs`, `test_hollow_payload.rs` and `test_tls_payload.rs` — into a
scratch directory at run time, so none of those binaries has to exist beforehand.

## Sources without a binary

`probe_payload.rs`, `test_args_payload.rs`, `test_hollow_payload.rs` and
`test_tls_payload.rs` are compiled on demand by the suite; `demo_script.ps1` is a
PowerShell payload used as a text fixture. None of them is committed as a binary.
