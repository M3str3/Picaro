# Wizard

**Status:** implemented as a sequential form. The one-screen TUI was rejected
after use. The stub is configured **before** the runtime, and the runtime is an
ordered list where preparation, execution and control steps can be mixed freely,
subject only to the packer's model limits.

Goal: an operator who has never read the technique catalog can configure the
loader, build a coherent chain and see exactly what will be written.

---

## 1. Flow

```
1. PAYLOAD   source (format detected), name, fixed arguments, arch, output kind
2. STUB      strings strategy, syscall mode, resolver, stack spoofing
3. RUNTIME   add / edit / remove / move steps; any category, any order
4. OUTPUT    path, strip, path trimming (and the DLL entry, if a DLL)
5. REVIEW    the exact YAML, then [ build now ] [ edit answers ] [ quit ]
```

The payload format is not a question: `plan::format::detect` reads the file and
reports it in the PAYLOAD section (`PE executable`, `DLL`, `.NET assembly`,
`shellcode`, `PowerShell script`). The runtime editor then offers only the
techniques whose `formats` accept it.

Output kind is `exe`, `dll` or `shellcode`; the default path gets the matching
extension (`.exe`, `.dll`, `.bin`).

The stub comes first because the runtime depends on it: `requires_indirect_syscalls`
techniques are only offered when the stub selected indirect, and the resolver /
stack-spoofing choices change what the generated chain can do. The runtime comes
next, and the artifact path last.

### Navigation

- **Esc** (interactive) or **`:b` / `back` / `..`** (line backend) goes back one
  section, keeping the answers as defaults.
- Esc inside a step's parameters re-opens the runtime editor; Esc at the runtime
  action menu leaves the section; Esc at the review is `edit answers`; Esc on the
  first section cancels. `Ctrl-C` always cancels.
- Section state is a `Partial` filled section by section, so going back does not
  lose earlier answers.

---

## 2. Stub

| Question | Values |
|---|---|
| strings | `xor` (default) or `stack` |
| syscalls | `none` (default) or `indirect`; `indirect` is hidden on x86 because the trampoline is x64-only |
| resolver | `hells_gate`, `tartarus_gate`, `api_hash`, `halos_gate` (only with `indirect`) |
| stack spoofing | yes/no (only with `indirect`); the decoy size keeps the default and is edited in the YAML |

The resolver is written to `build.stub.syscalls.resolver`; stack spoofing to
`build.stub.syscalls.stack_spoofing`. With `mode: none` the block is omitted.

---

## 3. Runtime editor

The runtime is one ordered list, not three buckets:

```
  1. bouncer        preparation
  2. patch_amsi     preparation
  3. sleep          control
  4. reflective_loading  execution
```

Actions: **add**, **edit**, **remove**, **move up**, **move down**, **done**.
New steps are appended (before a terminal step, see below); move/remove give the
operator full control of the order.

### What is offered

Every registered technique is a candidate except `drop` (needs a second payload)
and `import_powermodule` (psmodule-only). The editor reports the unavailable ones
with a reason, computed from the model:

| Limit | Effect |
|---|---|
| single payload format | the chain has one payload; an execution technique whose format differs from the first execution's is unavailable |
| terminal step | a terminal execution must stay last; additions are inserted before it and moving past it is rejected |
| architecture | `requires` capabilities are checked against `arch` |
| syscalls | `requires_indirect_syscalls` needs `mode: indirect` |
| conflicts | either direction of `TechniqueDef::conflicts` |
| DLL | `self_deletion` / `sleep_obfuscation` mutate the host image |

`done` requires at least one execution technique; the review runs
`plan::validate` before writing, so a combination the model rejects fails with
the packer's own message.

### Parameters

`ask_step_params` dispatches by category:

- Preparation → its tailored questions (bouncer, AMSI/ETW variants, process
  mitigations, …) or its `params_example`;
- Execution → its tailored questions (hollowing target, stomping module, early
  bird wait, injection timeout, `reflective_loading`'s `patch_exit` for a
  PE/DLL payload) or `params_example`;
- Control → `sleep` (ms), `living_off_the_land` (binary/args), `ppid_spoofing`
  (binary/args/parent/wait), `network_stager` (url; the payload is the wizard's).

---

## 4. Menus

Menus list names only (a technique list with concatenated summaries was
unreadable). The runtime add menu appends the category (`bouncer preparation`);
after the choice, `announce` prints the summary, stability, ATT&CK id and
requirements. The step editor shows the current chain as a numbered list.

---

## 5. Backends

| Backend | When |
|---|---|
| `InquirePrompt` | stdin **and** stdout are terminals: arrow-key `Select`, editable `Text`, `Confirm` |
| `LinePrompt` | redirected input and the unit tests: `? label [default]:` |

No `ratatui`, no alternate screen. `inquire = "0.7"` shares crossterm 0.25 with
the pager.

---

## 6. Tests

The line backend runs full sessions from a scripted `Cursor`: defaults, stub
indirect + resolver + stack spoofing, a bouncer before hollowing, a mixed
fiber/sleep/LOTL/stomping chain, DLL builds, edit/quit, terminal placement and
truncated input. They are terminal-free and part of `cargo test`.

The live contract tests live in `tests/reproduction.rs` and stay opt-in.

---

## 7. Decisions

| # | Decision | Alternatives |
|---|---|---|
| W-1 | Sequential form | one-screen dashboard (rejected after use) |
| W-2 | Stub before runtime | execution first (the stub can make techniques available or unavailable) |
| W-3 | One ordered runtime list | preparation/execution/control buckets (the stub order is free) |
| W-4 | Model limits, not fixed slots | separate "appendable" list (too restrictive) |
| W-5 | Names-only menus + `announce` | one line per technique with its summary (unreadable) |
| W-6 | Two backends behind one `Prompt` trait | terminal-only (no scripting/tests) |
