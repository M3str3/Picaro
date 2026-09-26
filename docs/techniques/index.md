# Techniques overview

A pipeline is a list of techniques applied in order. Techniques are split into
two categories (`TechniqueDef.category`):

- **Preparation** — modifies the current process state (e.g. patches AMSI) but
  never runs the payload. The stub runs each one in YAML order.
- **Execution** — runs the decrypted payload. The stub runs exactly one of
  these, after every Preparation technique.

A valid pipeline is `0..N` Preparation techniques followed by **exactly one**
Execution technique; the order is enforced by `src/config/validate.rs`.

Every technique fragment calls the stub's `nt_*` helpers (`nt_alloc_vm`,
`nt_write_vm`, `nt_read_vm`, `nt_resume_thread`, `nt_unmap_view`,
`nt_protect_vm`, `nt_suspend_thread`, `nt_query_info_process`,
`nt_get_context_thread`) and never the Win32 APIs directly. See
[Syscall layer](indirect_syscalls.md).

The registry (`src/techniques/mod.rs`) is metadata-only; inspect it with
`batesian techniques list`, `batesian techniques show <name>` and
`batesian techniques validate`. Adding one:
[Adding a technique](adding-a-technique.md).

## Registered techniques

| Technique | Category | ATT&CK | Stability | Summary |
| --- | --- | --- | --- | --- |
| [patch_amsi](ref/patch_amsi.md) | preparation | T1562.001 | stable | Patches `AmsiScanBuffer` in the current process so it always returns clean, disabling AMSI for in-process callers. |
| [patch_etw](ref/patch_etw.md) | preparation | T1562.006 | stable | Overwrites the ETW event-writing exports in the current process so it emits no ETW events. |
| [anti_debug](ref/anti_debug.md) | preparation | T1622 | stable | Checks the current process for signs of a debugger and, by default, aborts so the payload never runs. |
| [sleep_obfuscation](ref/sleep_obfuscation.md) | preparation | T1027 | experimental | Encrypts the executable image region for the duration of a sleep (ekko variant), so a memory scanner sees RC4 ciphertext. |
| [bouncer](ref/bouncer.md) | preparation | T1497.001, T1614.001 | experimental | Gates the payload on declared host checks (hostname, locale, uptime, RAM, VM/sandbox) and aborts the pipeline when they fail. |
| [process_hollowing](ref/process_hollowing.md) | execution | T1055.012 | experimental | Runs the payload inside a suspended, legitimate process (`svchost.exe` by default). |
| [reflective_loading](ref/reflective_loading.md) | execution | T1620 | experimental | Maps the payload into the current process (manual mapping), resolves imports and relocations, and runs its entry point. |
