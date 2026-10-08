# Techniques overview

A runtime is a list of technique steps applied in order. Techniques are split
into three categories (`TechniqueDef.category`):

- **Preparation** — modifies the current process state (e.g. patches AMSI) but
  never runs a payload.
- **Execution** — runs a decrypted payload; only these take `params.payload`.
- **Control** — orchestrates the chain (`living_off_the_land`, `sleep`).

A step only continues if the loader gets control back, so a **terminal** step
(`reflective_loading` of a PE executable, `dotnet_hosting`) must be the last one;
`src/plan/validate.rs` enforces it. Everything else chains.

Every technique fragment calls the stub's `nt_*` helpers (`src/engine/syscalls.rs`:
`nt_alloc_vm`, `nt_write_vm`, `nt_read_vm`, `nt_protect_vm`,
`nt_create_thread_ex`, `nt_wait_for_single_object`, `nt_get_context_thread`,
…) and never the Win32 APIs directly. See
[Syscall layer](../features/ref/syscalls.md).

The registry (`src/techniques/mod.rs`) is metadata-only; inspect it with
`picaro techniques list`, `picaro techniques show <name>` (a styled page that
pages long documents full-screen; `--raw` prints the Markdown verbatim) and
`picaro techniques validate`. Adding one:
[Adding a technique](adding-a-technique.md).

## Registered techniques

| Technique | Category | ATT&CK | Stability | Summary |
| --- | --- | --- | --- | --- |
| [patch_amsi](ref/patch_amsi.md) | preparation | T1562.001 | stable | Patches `AmsiScanBuffer` in the current process so it always returns clean, disabling AMSI for in-process callers. |
| [patch_etw](ref/patch_etw.md) | preparation | T1562.006 | stable | Overwrites the ETW event-writing exports in the current process so it emits no ETW events. |
| [anti_debug](ref/anti_debug.md) | preparation | T1622 | stable | Checks the current process for signs of a debugger and, by default, aborts so the payload never runs. |
| [sleep_obfuscation](ref/sleep_obfuscation.md) | preparation | T1027 | experimental | Encrypts the executable image region for the duration of a sleep (ekko variant), so a memory scanner sees RC4 ciphertext. |
| [bouncer](ref/bouncer.md) | preparation | T1497.001, T1614.001 | stable | Gates the payload on declared host checks (hostname, locale, uptime, RAM, VM/sandbox) and aborts the pipeline when they fail. |
| [unhook_ntdll](ref/unhook_ntdll.md) | preparation | T1562.001 | stable | Restores the loaded `ntdll.dll`'s code section from a clean on-disk copy (base fixups applied on x86), removing userland hooks. |
| [guardrail](ref/guardrail.md) | preparation | T1480 | stable | Aborts the chain after a deadline or a run-count, so the payload does not run out of scope. |
| [process_hollowing](ref/process_hollowing.md) | execution | T1055.012 | experimental | Runs the payload inside a suspended, legitimate process (`svchost.exe` by default). |
| [process_ghosting](ref/process_ghosting.md) | execution | T1055.012 | experimental | Maps a full PE image from a delete-on-close file, so the payload runs with no backing file on disk. |
| [reflective_loading](ref/reflective_loading.md) | execution | T1620 | experimental | Maps the payload into the current process (manual mapping), resolves imports and relocations, and runs its entry point. |
| [dotnet_hosting](ref/dotnet_hosting.md) | execution | T1620 | experimental | Hosts the CLR in the stub and runs a managed (`format: dotnet`) assembly from memory. |
| [execution_callbacks](ref/execution_callbacks.md) | execution | T1106, T1620 | stable | Runs the payload as the callback of a legitimate Windows enumeration API (`CertEnumSystemStoreLocation`) in the current process, from no dedicated thread. |
| [module_stomping](ref/module_stomping.md) | execution | T1055 | stable | Overwrites a legitimate signed DLL's code section with the payload and runs it from there. |
| [dll_hollowing](ref/dll_hollowing.md) | execution | T1574.002 | experimental | Loads a signed DLL, hollows its code section with the payload and runs it from there, restoring the original bytes so the module keeps proxying its exports. |
| [fibers](ref/fibers.md) | execution | T1055 | stable | Runs the payload on a fiber of the loader's own thread; control returns to the loader when it does. |
| [early_bird](ref/early_bird.md) | execution | T1055.004 | experimental | Creates the target suspended, writes the payload and queues an APC before the target's loader runs, so the payload executes first. |
| [pe_injection](ref/pe_injection.md) | execution | T1055.002 | experimental | Maps a full PE image into a freshly created suspended process and starts it at its entry point, without unmapping the target's own image. TLS is provisioned and the payload's `DLL_PROCESS_ATTACH` callbacks run before the entry thread (runtime verification pending). |
| [thread_hijacking](ref/thread_hijacking.md) | execution | T1055.003 | experimental | Suspends a thread that already exists in a running process, points its instruction pointer at the payload and resumes it — no thread is ever created. |
| [living_off_the_land](ref/living_off_the_land.md) | control | T1218, T1105 | stable | Launches a signed Microsoft binary (or any command) as a chain step, resolving a bare name against System32 and quoting its arguments. |
| [sleep](ref/sleep.md) | control | T1497 | stable | Waits a number of milliseconds between two steps of a runtime chain. |
| [network_stager](ref/network_stager.md) | control | T1105, T1071 | experimental | Fetches a payload over the network at run time (`http`/`https`/`ftp` via `certutil`, `scp`) and hands it to the next Execution step, optionally decrypting it first. |
| [self_deletion](ref/self_deletion.md) | preparation | T1070.004 | stable | Renames the running image into an alternate data stream of its own path (default) or deletes it after exit, so the loader's bytes leave the file the path names. |
| [timestomping](ref/timestomping.md) | preparation | T1070.006 | stable | Copies a reference file's creation/access/write times onto the artifact, so it looks like it has been on disk longer. |
| [stack_spoofing](ref/stack_spoofing.md) | preparation | T1036 | stable | Fabricates the top of the stack for every syscall, so a stack walk during the call sees ntdll code addresses instead of the loader. |
| [ppid_spoofing](ref/ppid_spoofing.md) | control | T1134.004 | stable | Launches a process whose recorded parent is a different, legitimate process. |
