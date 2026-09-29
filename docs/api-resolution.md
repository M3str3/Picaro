# API resolution (payload import proxy)

Status: **implemented for `reflective_loading` (Phases A–D, 2026-09-27); Phase E
(`process_hollowing`) is parked as not viable without a redesign and the mode is
rejected at validation there.** All five catalogue entries work end to end, and
`unmatched: abort` fails the load on the first import outside the catalogue.

The goal: let the **loader** (the generated stub) own how the payload's Windows
API
calls are resolved, so a "noisy" payload that reaches the API the normal userland
way — through its IAT, `GetProcAddress`, or `LdrGetProcedureAddress` — is served by
a proxy generated in the stub instead of by the real export. Intercepted calls are
re-implemented on top of the existing syscall layer
(`build.stub.syscalls.mode: indirect`), so they reach the kernel through our
`syscall; ret` gadget and not through the `ntdll` stubs an EDR may have hooked.
The payload is not modified and is not rebuilt.

The payload's own obfuscation is irrelevant to us: it deobfuscates its API names
before handing them to `GetProcAddress`, and its IAT is filled by *us*. We
intercept at resolution, after the payload has done its work.

---

## 1. Spike evidence (phase 0)

A throwaway spike (`code_examples/spike_iat_proxy/`, gitignored scratch) validated
the seam on Windows / `x86_64-pc-windows-msvc` / rustc 1.90. Its findings are
reproduced here because the scratch tree is not kept in the repo.

A payload calling `ReadProcessMemory` both through its IAT and via
`GetProcAddress` was loaded by a harness that repointed **only** those two slots:

- Both paths were intercepted by the local proxy; the payload got correct data in
  every case (`forward` to the saved original, and `route_to_nt` through
  `NtReadVirtualMemory`).
- The loader-module address is reachable from the payload **in-process** (so
  `reflective_loading` first; `process_hollowing` later).
- The IAT page is `PAGE_READONLY` after the loader binds it → the slot write
  faults unless the page is made writable first.
- `forward` needs no static import (the proxy reuses the pointer it replaced).
- CFG: with the default Rust build CFG is off; a proxy whose address is taken is a
  **registered CFG target**; a runtime thunk is not. A CFG-*enforced* process could
  not be produced on the test host (see Limitations).
- `VirtualProtect(range)` is page-granular: one call over the whole IAT span
  covers every touched page; protecting part of the range leaves the rest
  read-only and writing faults.
- Real payloads in the repo (`test_payload.exe` 78 imports, `msgbox.exe` 79) have
  single-page `.rdata` IATs; the multi-page IAT case was covered synthetically
  only (see Limitations).

---

## 2. Scope

### In scope

- Payloads that call Windows APIs the normal userland way:
  - imports resolved through the **IAT**;
  - dynamic resolution through **`GetProcAddress`** (itself an import);
  - **`LdrGetProcedureAddress`** (optional; same handler shape).
- A loader-level configuration block selecting which APIs are proxied.
- Reuse of the syscall layer for the intercepted calls.
- `reflective_loading` first. `process_hollowing` later (see phases).

### Non-goals (explicitly rejected)

- **Payloads that bring their own indirect syscalls** (their own `syscall; ret`
  gadget and SSN resolution). They call no userland API, so there is no seam. Out
  of scope by construction.
- **Manual `PEB`→`Ldr` walks ending in a direct call to the real `ntdll` export.**
  The resolution is not ours; only the call target is. That would need inline
  hooking, which is a separate future technique. Not here.
- **Raw syscalls.** No userland seam.
- **Patching the payload's `.text`.** No.
- **A remote proxy channel** (Malproxy-style). Handle mapping and serialization
  make it a project of its own. Not here.
- **Patching system code** (`ntdll`/`kernel32` inline hooks). Not here.

---

## 3. Placement and schema

It is a **loader property**, not a pipeline technique: it changes how the loader
resolves the payload's imports before running it, exactly like
`build.stub.syscalls` and `build.stub.strings`. It does not fit the
Preparation/Execution contract (it is not a step that modifies process state or
runs the payload), so it does **not** go in `src/techniques/`.

Placement: **`build.stub.api_resolution`**. It sits next to
`build.stub.syscalls`, which it depends on (the coupling is then inside one
block). `build.payload.api_resolution` was considered — the content is
payload-relative — but the generated code and the validation coupling are both
stub concerns, so `build.stub` wins.

```yaml
build:
  stub:
    syscalls:
      mode: indirect          # required when api_resolution.mode: proxy
      resolver: hells_gate
    api_resolution:
      mode: none              # none | proxy
      apis:                   # selections from the catalogue (section 4)
        - "kernel32!ReadProcessMemory"
        - "kernel32!OpenProcess"
        - "ntdll!NtReadVirtualMemory"
        - "ntdll!NtOpenProcess"
      unmatched: forward      # forward | abort
```

- `mode: none` (default) — no behaviour change; the block is a no-op.
- `apis` — only names present in the catalogue; an unknown name is a **validation
  error**, never silently ignored. An empty list with `mode: proxy` is a no-op
  (surfaced as an advisory, like a `bouncer` with no checks).
- `unmatched` — what to do with imports not in the catalogue:
  `forward` (default; resolve normally, no proxy) or `abort` (fail the load; a
  debugging aid). There is deliberately no `stub`/"return a failing function"
  mode: it breaks the payload and adds surface for no gain.

---

## 4. The minimal catalogue (phase 1)

Only what the spike requires and what covers a mimikatz-style payload's critical
path to LSASS. `NtQuerySystemInformation` is deliberately **not** included yet:
its semantics vary per information class, each with its own struct — a rabbit hole
until needed.

Every entry names its **strategy** (phase 2, section 5). A catalogue entry is always
*proxied*; the strategy says what the proxy does. `unmatched` (section 3) governs
imports that are *not* in the catalogue.

| API | Strategy | Nt\* target | New `nt_*` helper |
|---|---|---|---|
| `ntdll!NtReadVirtualMemory` | `route_to_nt` (direct) | `NtReadVirtualMemory` | no — `nt_read_vm` exists |
| `ntdll!NtOpenProcess` | `route_to_nt` (direct) | `NtOpenProcess` | **yes** |
| `kernel32!ReadProcessMemory` | `route_to_nt` (thin wrapper) | `NtReadVirtualMemory` | no |
| `kernel32!OpenProcess` | `route_to_nt` (rebuild) | `NtOpenProcess` | **yes** |
| `kernel32!GetProcAddress` | special handler | — | — |

All five entries are implemented: `NtReadVirtualMemory` and `NtOpenProcess` are
`route_to_nt` (direct), `ReadProcessMemory` is `route_to_nt` (wrapper) and
`OpenProcess` is `route_to_nt` (rebuild); `GetProcAddress` is the `handler`. No
catalogue entry uses `Strategy::Forward` today — the strategy stays available for
"thick" APIs that cannot be re-implemented on a syscall.

So the minimal cut adds **one** syscall helper (`NtOpenProcess`; the syscall layer
lists 14 today) and one special handler. `NtReadVirtualMemory` already exists in
`NT_FUNCTIONS` as `read_vm` / `nt_read_vm`.

The catalogue is a single Rust const (`src/engine/api_resolution.rs`)
that is the source of truth for: the proxy generation, the `GetProcAddress`
name matching, and the plan validation. Adding an entry is a deliberate code
change, not a config-only edit.

---

## 5. Semantics: forwarding vs routing (phase 2)

Per entry, the decision is explicit and documented to the operator:

- **`forward`** — the proxy calls the *original* function, resolved dynamically at
  runtime with an obfuscated name (never a static import of the API it
  intercepts). Semantics are exact; the only goal is interception/observation.
- **`route_to_nt`** — the proxy re-implements the call on top of the native
  (`Nt*`) call, through the syscall layer. Stealthier, but the wrapper's semantics
  must be preserved or the payload may misbehave.

Fidelity notes that must be honoured by a `route_to_nt` proxy:

- **`ReadProcessMemory`**: the exported wrapper returns `BOOL` and sets
  `GetLastError` (e.g. `ERROR_PARTIAL_COPY`), whereas `NtReadVirtualMemory`
  returns an `NTSTATUS` and can report a partial copy. The proxy must translate
  (`NT_SUCCESS(status)` → `TRUE`; otherwise set the error and return `FALSE`) and
  still fill `lpNumberOfBytesRead`.
- **`OpenProcess`**: **not** a thin wrapper. `NtOpenProcess` takes
  `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)` — the proxy must build
  the `OBJECT_ATTRIBUTES` and `CLIENT_ID` for the process id and map the Win32
  access mask. Higher fidelity risk; documented as such.
- The two `ntdll!Nt*` entries are 1:1 (same arity, same arguments).

First cut recommendation: route the two `Nt*` entries and `ReadProcessMemory`;
include `OpenProcess` but treat its rebuild as the riskiest entry (it is also the
highest-value, so it stays in).

---

## 6. The `GetProcAddress` handler

Distinct from a forwarding proxy: it **decides** what to return. It is installed
only in the **payload's own `GetProcAddress` IAT slot**; the loader's internal
`GetProcAddress` calls (the import resolver, the syscall resolvers) keep the normal
import and are never intercepted, so there is no recursion and no interference
with the loader's own resolution. When the handler forwards, it calls the
*original* `GetProcAddress` — the pointer it replaced — not its own.

- **Name lookups only.** If `(module, name)` is in the catalogue, return the
  generated proxy for that API; otherwise call the original and return its result
  unchanged.
- **Ordinals are forwarded.** A `name` with a zero high word is an ordinal; the
  handler never dereferences it as a string and never tries to resolve it — the
  catalogue is name-keyed, so an ordinal is passed through to the original
  unchanged. (Mapping ordinals to names would need an export-table walk.)
- **Module-name normalization.** The handler gets an `HMODULE`, not a name, so it
  resolves the handle to a module name and normalizes both sides identically: take
  the file-name component (after the last `\` or `/`), drop a trailing `.dll`
  (case-insensitively), ASCII-lowercase. Catalogue entries store the same
  normalized form (e.g. `kernel32`, `ntdll`). If the handle cannot be resolved to
  a name, the handler forwards to the original — it never guesses.
- **CFG.** The returned proxy address is an ordinary Rust function whose address is
  taken, so it is a valid CFG target (see Limitations / Decision log).
- `LdrGetProcedureAddress` (if the payload imports it) shares the handler shape,
  adapted to its `(module, PANSI_STRING, ULONG, PVOID*)` signature and `NTSTATUS`
  return. Optional in the first cut.

---

## 7. Validation (phase 3)

In `src/plan/validate.rs` (mirroring the existing technique checks):

1. **`api_resolution.mode: proxy` requires `syscalls.mode: indirect`** — otherwise
   the re-routed calls fall back to the direct Win32 APIs and the intercepted
   imports reappear in the **stub's** IAT: the feature becomes a placebo that moves
   the signature instead of removing it. This is a hard error, not an advisory.
2. **Every `apis` entry must be in the catalogue.** Unknown name, or a selector
   without `dll!function`, → error.
3. **`unmatched` must be `forward` or `abort`** (serde already rejects anything
   else).
4. **Advisory:** `mode: proxy` with an empty `apis` list → no-op (same pattern as
   a `bouncer` with no checks).
5. **Advisory (nice to have):** a catalogue entry the payload does not import
   (needs a build-time parse of the payload's import table) → warn that it will
   never be hit by the IAT path (it may still be hit via `GetProcAddress`).
6. **`api_resolution.mode: proxy` requires a payload with an import table** —
   `build.payloads.<name>.format: pe` or `dll`. With `format: shellcode` there is no IAT to
   rewrite, so the mode can never apply; that is an **error**, not a silent no-op.
   (`process_hollowing` is already `pe`-only, so this only concerns
   `reflective_loading`.)

No separate "an Execution technique is active" check is needed: the pipeline
contract already enforces exactly one Execution technique (`validate_runtime`), and
both execution techniques resolve imports, so the resolver is always emitted.

---

## 8. How it works

1. The resolver walks the payload's import descriptors (unchanged).
2. For each `(dll, func)` it consults the policy: a catalogue hit yields a proxy
   address; a miss yields the real resolved address (`forward`) or aborts.
3. Before writing the IAT, the loader records each page's original protection in
   the slot range and makes the whole range writable; after the writes it restores
   each page to its recorded protection. The range is contiguous within one section
   in practice (one page for every payload measured), so this is usually a single
   page; recording per page also covers a range that reaches a page with a
   different protection.
4. The proxies call the `nt_*` helpers, so `mode: indirect` routes them through
   the `syscall; ret` gadget.
5. `GetProcAddress`'s own IAT slot is repointed at the handler (section 6).

---

## 9. Code touchpoints

- `src/plan/schema.rs` — `StubPlan.api_resolution: Option<YamlApiResolutionPlan>`.
- `src/engine/api_resolution.rs` — the catalogue, the resolved config, and the
  renderer (`render_block`: policy, proxies, handler; `required_syscalls`).
- `src/engine/imports.rs` — `resolve_imports` takes the policy; `patch_imports`
  resolves, protects the slot range per page, writes and restores (safe API: the
  fragments never write the IAT themselves).
- `src/techniques/reflective_loading/stub_fragment.rs` — calls `patch_imports`
  with `crate::resolution_policy`.
- `src/techniques/process_hollowing/stub_fragment.rs` — passes a no-op policy
  (Phase E; the proxies are not mapped in the target).
- `src/engine/syscalls.rs` — `NtOpenProcess` in `NT_FUNCTIONS` (both bodies), and
  `render_block_with` (merges the `Nt*` names `api_resolution` routes to).
- `src/engine/stub.rs` + `templates/stub/main.rs.tpl` — `$API_RESOLUTION_BLOCK$`
  and the `render_*_with` variants that thread the config.
- `src/plan/validate.rs` — section 7.
- `src/main.rs` — `verify_no_intercepted_imports` (D-21/D-22).
- Every catalogue/compare name goes through `StringsConfig`; nothing new in
  clear text (the proxy identifiers are index-based, names live in comments).

---

## 10. Phases

- [x] **Phase A — schema + validation, no behaviour change.** `mode: none` only;
  parse, default, validate the coupling and the catalogue names. *Implemented
  2026-09-27: `build.stub.api_resolution` (`YamlApiResolutionPlan`), the
  `CATALOGUE` const (`src/engine/api_resolution.rs`), and
  `validate_api_resolution` + the no-op advisory.*
- [x] **Phase B — resolver policy + proxies, `reflective_loading` only.**
  *Implemented 2026-09-27:* the shared `patch_imports` (per-page protect/restore),
  generated proxies + policy (`src/engine/api_resolution.rs`), the
  `$API_RESOLUTION_BLOCK$` placeholder, and `route_to_nt` for
  `ntdll!NtReadVirtualMemory` (direct) and `kernel32!ReadProcessMemory` (wrapper:
  NTSTATUS → BOOL, `GetLastError`, partial count). Entries not implemented yet
  (`NtOpenProcess`, `OpenProcess`, `GetProcAddress`) render as `forward`. The
  `audit` stub-IAT check is deferred to Phase C (D-21).
- [x] **Phase C — `GetProcAddress` handler + audit check.** *Implemented
  2026-09-27:* the handler (normalized module lookup via `GetModuleFileNameA`,
  catalogue hit → proxy, ordinal or miss → the original), the `Handler` strategy
  in the catalogue, and `verify_no_intercepted_imports` in the build flow (D-21,
  D-22).
- [x] **Phase D — `OpenProcess` rebuild + `NtOpenProcess`.** *Implemented
  2026-09-27:* `NtOpenProcess` in the syscall layer (both bodies) and
  `kernel32!OpenProcess` rebuilt on it (`OBJECT_ATTRIBUTES` + `CLIENT_ID`, access
  mask passed through, `inherit` → `OBJ_INHERIT`), plus the direct
  `ntdll!NtOpenProcess` route.
- [ ] **Phase E — `process_hollowing`: parked, not viable without a redesign.**
  The proxies are ordinary Rust functions in the loader image; they reference the
  loader's statics (the SSN table, the gadget, the `OnceLock` caches), its
  obfuscated byte arrays and its CRT allocator. A hollowed payload runs in another
  process that has none of that, so its IAT there can only point at the real
  exports. Making it work needs a **new mechanism**: a position-independent proxy
  emitter (raw stubs written into the target, with the SSN and gadget baked in)
  plus in-target allocation and the wrapper's `NTSTATUS`→`BOOL` translation in
  asm. Until then `mode: proxy` with `process_hollowing` is a validation error
  (D-23), so it fails loudly instead of silently not proxying.
- [ ] **Phase F (parked) — `LdrGetProcedureAddress` handler; remote channel.**

---

## 11. Limitations

Declared, not hidden:

- **CFG enforced was not reproduced.** On the test host, `-C
  control-flow-guard=yes` produced a fully instrumented image (`CF_INSTRUMENTED`,
  a 360-entry function table, the real validator installed) but the process did
  **not** enforce CFG — not from the image flag, and not when the child was
  created with `CONTROL_FLOW_GUARD_ALWAYS_ON`. Mechanism evidence is solid: an
  address-taken Rust proxy **is** a registered CFG target; a runtime thunk is not.
  *Path to close:* run the spike on a host where CFG is enforced (or force it via
  system policy) and confirm a Rust proxy is callable while a runtime thunk faults.
  The implementation decision does not depend on it: generate proxies as ordinary
  Rust functions.
- **A payload that writes its own IAT at runtime** (lazy binding / hot-patching)
  would need the IAT page left writable; we restore the original (read-only)
  protection. Such a payload can break. None of the repo payloads do this.
- **A genuinely multi-page IAT was not covered.** No repo payload has one (the
  largest is 78 imports / 688 B / one page); the case was covered synthetically.
  The implementation must protect/restore the **whole** slot range, not one page.
- **`process_hollowing` is out of the first cut** (Phase E).
- **Out-of-scope payloads** (section 2): own syscalls, manual `PEB`→`Ldr` walk with
  a direct call, raw syscalls, patched `.text`.
- **Detection trade.** Repointing an IAT slot makes it point outside the expected
  module — a classic IAT-hook signal. You remove the API *name* from the payload's
  in-memory IAT; you introduce a non-module pointer there.
- **Win32↔Nt\* fidelity** (section 5) — `ReadProcessMemory`'s error/partial-copy
  semantics; `OpenProcess` is a rebuild, not a wrapper.
- **Concurrency / reentrancy** of the proxies is untested; the payload may call
  from many threads.
- **`process_hollowing` is not supported (Phase E).** The proxies live in the
  loader image, which is not mapped in the target; the payload's IAT there can only
  point at the real exports. `mode: proxy` with `process_hollowing` is a validation
  error. Closing it needs a position-independent proxy emitter written into the
  target (raw stubs with the SSN and the gadget baked in) — a redesign, D-23.
- **`Strategy::Forward` has no catalogue entry yet.** It is implemented and
  tested, but every shipped entry is a route or the handler; a forwarding proxy
  re-resolves the original by name at first call, so the call still lands on the
  real export, not the syscall path (D-19).
- **`OpenProcess` rebuild fidelity.** The Win32 `PROCESS_*` constants are the NT
  access masks, so the mask passes through unchanged, and `bInheritHandle` maps to
  `OBJ_INHERIT`; the returned handle is verified usable with `ReadProcessMemory`.
  `PROCESS_ALL_ACCESS` keeps its Win32 value (`0x1F0FFF`, a subset of the NT
  mask), so the granted rights match what `OpenProcess` would request. No diverging
  case has been observed; this entry remains the highest-risk one.
- **`audit` is static** and cannot see the payload's in-memory IAT (the payload is
  encrypted on disk); the check targets the **stub** and exempts the
  `GetProcAddress` handler (D-22).

---

## 12. Decision log

| # | Decision | Rationale | Status |
|---|---|---|---|
| D-1 | Loader property, not a pipeline technique | Changes how imports are resolved, not process state | accepted |
| D-2 | `build.stub.api_resolution` (not `build.payload.*`) | Sits with `syscalls`; the coupling and generated code are stub concerns | accepted |
| D-3 | `mode: none \| proxy` (no `stub` mode name) | "stub" collides with the loader | accepted |
| D-4 | `unmatched: forward \| abort` only (no failing-stub mode) | A failing stub breaks the payload and adds surface | accepted |
| D-5 | Catalogue is a Rust const, validated | Per-entry semantics cannot be config-only | accepted |
| D-6 | `apis` unknown name is a hard error | Never silently ignore an operator's selection | accepted |
| D-7 | `proxy` requires `syscalls.mode: indirect` (hard error) | Otherwise the imports move to the stub's IAT (placebo) | accepted |
| D-8 | Proxies are ordinary Rust functions (address taken) | Registered CFG targets; no runtime thunks | accepted |
| D-9 | Protect the whole IAT range, then restore | Page-granular; a RW IAT page is a detection signal | accepted |
| D-10 | `reflective_loading` first, `process_hollowing` parked | In-process only; the target has no proxies | accepted |
| D-11 | No `NtQuerySystemInformation` in the catalogue yet | Per-class structs; add when needed | accepted |
| D-12 | Handler resolves `HMODULE`→name; normalize both sides (basename, strip `.dll`, ASCII-lowercase); unresolvable handle → forward | The handler gets a handle, the catalogue is `dll!func` | accepted |
| D-13 | Record original protection **per page** and restore per page (uniform in practice: the range is one section/page) | A single `VirtualProtect` returns one old value; a range can touch a differently-protected page | accepted |
| D-14 | `mode: proxy` with `format: shellcode` is a hard error | No IAT to rewrite; the mode can never apply | accepted |
| D-15 | The handler is installed only in the payload's IAT; the loader's own `GetProcAddress` is never intercepted | Avoids recursion and interference with the loader's resolution | accepted |
| D-16 | Phase B lands `forward` before `route_to_nt` | Separates a seam failure from a translation failure | accepted |
| D-17 | Ordinals are forwarded unchanged, never resolved | The catalogue is name-keyed; ordinal→name needs an export walk | accepted |
| D-18 | Phase B renders not-yet-implemented entries (`NtOpenProcess`, `OpenProcess`, `GetProcAddress`) as `forward` | Forwarding is exact and keeps selections valid until Phases C/D | superseded (C/D implemented; no entry uses `forward`) |
| D-19 | `forward` proxies re-resolve the original at first call (`GetModuleHandleA`+`GetProcAddress`, cached in a `OnceLock`) | Self-contained; the intercepted name stays dynamic (never a static import) | accepted |
| D-20 | Test-only convenience wrappers (`render_main_rs`, `render_custom_stub`, `syscalls::render_block`) kept with `#[allow(dead_code)]`; the build calls the `_with` variants | Avoids churning ~15 call sites | retired (schema 6 deleted the single-payload path and its wrappers) |
| D-21 | The `audit` "the stub's IAT must not gain the intercepted names" check is deferred to Phase C | `audit` is plan-agnostic; the render tests cover the structural guarantee for now | accepted (implemented in C, `verify_no_intercepted_imports`) |
| D-22 | The audit check exempts `Strategy::Handler` entries | The loader itself imports `GetProcAddress` (import resolver, SSN resolvers), so its presence cannot be told apart from the handler's resolver and is not a regression | accepted |
| D-23 | `mode: proxy` with `process_hollowing` is a validation error, and Phase E is parked | The proxies are Rust functions bound to the loader image (statics, obfuscated data, CRT); the target has none of it. Closing it needs a position-independent proxy emitter written into the target | accepted (E parked) |

---

## 13. References

- Spike evidence: `code_examples/spike_iat_proxy/REPORT.md` (gitignored scratch;
  summary reproduced in section 1).
- Syscall layer: `docs/techniques/indirect_syscalls.md` (Hell's Gate / Tartarus
  Gate / API hashing; the `nt_*` helpers).
- Shared import resolver: `src/engine/imports.rs`.
- Sibling loader config: `build.stub.syscalls` (`src/engine/syscalls.rs`).
- Malproxy (djhohnstein) — the remote-proxy variant that is explicitly parked.
