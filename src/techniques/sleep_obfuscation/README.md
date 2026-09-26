# Sleep obfuscation

## Metadata

- **ATT&CK**: T1027 (Obfuscated Files or Information)
- **Stability**: Experimental
- **YAML key**: `sleep_obfuscation`
- **Introduced in**: phase 6 (ekko variant)

## What it does

Encrypts the executable image region of the current process for the duration
of a sleep, so a memory scanner that inspects the process *during* the sleep
sees RC4 ciphertext instead of the payload bytes it would signature-match
against. When the sleep ends, the image is decrypted and restored to its
original protections, and the pipeline continues (the Execution technique then
runs the payload normally).

This phase ships the **ekko** variant (timer queue + ROP chain + `NtContinue`),
which is the canonical, best-documented sleep-obfuscation technique. `foliage`
(APC-based) and `cronos` (waitable timers) are recognized by the parser but
rejected with a "not implemented yet" error; they arrive in later phases.

## YAML parameters

| Parameter        | Type    | Required | Default     | Description                                          |
|------------------|---------|----------|-------------|------------------------------------------------------|
| `variant`        | string  | no       | `ekko`      | Mechanism: `ekko` \| `foliage` \| `cronos` (only `ekko` implemented) |
| `sleep_ms`       | u64     | no       | `5000`      | Length of the obfuscated sleep, in milliseconds      |
| `encrypt_regions`| list    | no       | `[payload]` | Region classes: `[payload]` \| `[payload, stack]` \| `all` (only `[payload]` implemented) |

## YAML example

```yaml
runtime:
  - technique: sleep_obfuscation
    params:
      variant: ekko
      sleep_ms: 5000
      encrypt_regions: [payload]
```

## How it works

The ekko sequence (all on `CreateTimerQueueTimer` timers flagged
`WT_EXECUTEINTIMERTHREAD`, so every step runs on the timer thread outside the
encrypted image):

1. `VirtualQuery` walks `image_base .. image_base + SizeOfImage` and records
   every committed run with its original protection.
2. The image is flipped `PAGE_READWRITE` (once, on the calling thread).
3. A timer runs `RtlCaptureContext` to capture a *timer-thread* context. The
   capture point matters: `RtlCaptureContext` stores `Rsp` just past the
   return address the timer dispatch left on that stack.
4. The captured context is copied into one continuation context per step. Each
   step sets `Rip` to the target function, the argument registers (`Rcx`,
   `Rdx`, `R8`, `R9`) to its parameters, and `Rsp = captured.Rsp - 8`, so when
   the target returns, its `ret` lands on the dispatch's return address and
   the hijacked timer thread unwinds cleanly (the ROP chain is the sequence of
   timer callbacks, each entering through `NtContinue`).
5. The chain, queued with staggered due times:
   1. `SystemFunction032` (RC4, resolved from `advapi32`) encrypts the image
      in ≤ 64 KB chunks. Its data parameter is a `struct ustring` whose
      `Length` is a `DWORD` (u32), so a single call could cover the whole
      image; the fragment splits it anyway as a per-call safety margin. The
      key is the first 16 bytes of the per-build XChaCha key.
   2. `WaitForSingleObject(NtCurrentProcess(), sleep_ms)` performs the real
      sleep on the hijacked thread.
   3. `SystemFunction032` decrypts the same chunks, scheduled to fire **after**
      the sleep (the original PoC let them fire during it; that is its
      best-known flaw).
   4. `VirtualProtect` restores each run to its original protection.
   5. `SetEvent` wakes the main thread.
6. The main thread waits on the event the whole time; no code executes from
   the image while it is encrypted. The queue is deleted and the technique
   returns.

All API and DLL names (`NtContinue`, `RtlCaptureContext`, `SystemFunction032`,
the timer-queue family, …) are resolved at runtime and obfuscated through
`StringsConfig`, so none of them reaches the import table.

## What it evades

- **Memory scans during the sleep.** An EDR that walks the process's
  executable regions while the implant sleeps finds RC4 ciphertext (and,
  during the crypto steps, `RW` pages) instead of payload signatures. The
  payload itself is only ever mapped/executed *after* the sleep completes.

## What detects it

- **Timer callbacks (ETW)**: a thread pool repeatedly entering
  `NtContinue` from `CreateTimerQueueTimer` callbacks is a well-known ekko
  signature.
- **ROP chain anomalies**: call stacks that return into the timer dispatch
  instead of a normal caller, and thread contexts whose `Rsp` does not match
  the executing function's frame.
- **`NtContinue` origin**: threads resuming at addresses like
  `VirtualProtect`/`SetEvent` straight from `NtContinue`.
- **RW during the crypto steps**: the image pages flip `RX → RW` (visible to
  `VirtualQuery`/`NtQueryVirtualMemory` watchers) for the duration of the
  encryption and decryption passes.
- **RC4 key reuse across chunks**: every ≤ 64 KB chunk restarts the RC4
  keystream with the same key, so equal-size chunks share keystream bytes (a
  cryptanalytic weakness; the threat model here is signature scans, not
  offline cryptanalysis).
- **The RC4 key sits in the heap** in cleartext during the whole sleep.

## Measurements

- See `docs/measurements/phase6_sleep_obfuscation.md`. Static metrics barely
  move (the payload is already encrypted at rest in `.rdata`); the value is
  runtime: during the sleep the image region is ciphertext — verifiable with a
  debugger (`VirtualQuery` + memory dump inside the sleep window).

## Implementation notes

- **Variant**: ekko only. The module structure (variant enum + one fragment)
  is ready for foliage and cronos.
- **Timing option C (demo)**: the technique performs one encrypted sleep of
  `sleep_ms` and returns; the payload then runs once, after the sleep. The
  operational form — encrypting *during the payload's own sleeps* — requires
  hooking `Sleep`/`SleepEx` in the target, which is a future phase.
- **Region scope**: this phase encrypts the whole image
  (`image_base + SizeOfImage`), the original Ekko region. Note that at
  Preparation time the decrypted payload buffer still lives on the heap (it is
  only mapped into executable regions by the Execution technique afterwards),
  so this MVP demonstrates the mechanism, not the operational region set; the
  VirtualQuery-based enumeration of the payload's mapped RX/RWX regions is the
  follow-up.
- **CONTEXT alignment**: windows-rs 0.58 exposes the x64 `CONTEXT` with the
  correct field offsets but only 8-byte alignment; the fragment wraps it in
  `#[repr(align(16))]` (same workaround as the `Get/SetThreadContext`
  fragments). No layout divergence beyond that was found.
- **Stable-Rust ROP**: no `global_asm!` is needed. The "chain" is the timer
  queue itself: each step is an independent `NtContinue` continuation context
  (a plain struct copy with `Rip`/`Rsp`/argument registers patched), queued
  with staggered due times. Function pointers are transmuted to the callback
  ABI.
- **`SystemFunction032` is dynamic**: it resolves from `advapi32` at runtime;
  if resolution fails, the stub errors with `CryptFunctionNotFound` (a pure
  ChaCha20 fallback in the stub is possible but not needed — the crate is
  already linked).
- **`SystemFunction032` takes a `struct ustring`, not a `UNICODE_STRING`**: its
  `Length`/`MaximumLength` fields are `DWORD`s (u32). Modeling them as the
  `USHORT`s of a `UNICODE_STRING` truncates the image and smears the two `u16`
  halves of each length into one garbage `u32` (this was the original bug).
- **The sleep is real**: the delay step is `WaitForSingleObject` on a timer
  thread; `std::thread::sleep` cannot be used (it would block the calling
  thread, which must stay parked in the event wait).

## References

- Original Ekko technique and paper: C5pider, <https://github.com/Cracked5pider/Ekko>
- MDSec Nighthawk study that first documented the mechanism: Austin Hudson,
  <https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html>
- Rust port used as reference material (reimplemented, not copied):
  memN0ps, <https://github.com/memN0ps/ekko-rs>
- RustRedOps sleep-obfuscation material:
  <https://github.com/joaoviictorti/RustRedOps>
