# Adding a technique

Each technique lives in its own directory under `src/techniques/` and is
registered in `src/techniques/mod.rs`. This file walks through adding a new
one.

## Categories

Every technique has one of three categories (`TechniqueDef.category`):

- **Preparation** (`Category::Preparation`) — modifies the current process
  state (e.g. patches AMSI) but never runs the payload. It takes no payload
  argument.
- **Execution** (`Category::Execution`) — runs the decrypted payload.
- **Control** (`Category::Control`) — neither prepares state nor runs the
  payload: it orchestrates the chain (`living_off_the_land` launches a process,
  `sleep` pauses).

The runtime is a flat `runtime:` list of `0..N` steps, run in YAML order; each
step is one technique. There is no fixed Preparation-before-Execution shape and
several Execution steps may appear. The one ordering rule is the *terminal
step*: a step that hands the whole process to the payload never returns, so it
must be last. `reflective_loading` of a PE executable, `dotnet_hosting` and
`process_ghosting` are terminal; `living_off_the_land`, `process_hollowing` and
`reflective_loading` of a DLL or shellcode all return control, so the steps
after them still run. `src/plan/validate.rs` rejects a terminal step that is not
last.

## 1. Copy the template

```bash
cp -r src/techniques/_template src/techniques/my_technique
```

Then replace every `<technique_key>` / `<Technique name>` placeholder in the
copied files.

## 2. Fill in `mod.rs`

- Define `Params` — the technique's YAML parameters. Use `#[serde(default =
  "default_...")]` for optional fields.
- Implement `Default for Params` (or derive it). A runtime entry's `params:`
  mapping is optional, so `RuntimeStep` relies on `Params: Default` to fill in a
  technique whose parameters were omitted.
- Fill in `DEF` — the `TechniqueDef` metadata (name, ATT&CK, stability,
  category, …). `params_example` is a YAML snippet that must parse as a
  `RuntimeStep`; write the parameters under a nested `params:` mapping, exactly
  as they appear in a plan:

  ```yaml
  technique: my_technique
  params:
    some_field: value
  ```

- Implement `Params::render_fragment` — substitute the technique's
  `$PLACEHOLDER$` values into `DEF.stub_fragment`.
- Set `formats` — the payload formats an Execution technique accepts (`&[]` for a
  Preparation/Control step, which runs no payload). `plan::validate` checks the
  loaded payload against it and the docs/plan builder read it, so it is the
  single source for the accepted formats.
- Set `requires_indirect_syscalls` — `true` only when the technique works *only*
  with `build.stub.syscalls.mode: indirect` (the renderer skips its step and
  `advisories` warns otherwise). `false` for everything else.

An **Execution** technique also gets the payload's binary format
(`build.payloads.<name>.format`) and export (`build.payloads.<name>.export`) through
`TechniqueKind::render_fragment`. A technique that runs more than one payload
format exposes `Params::render_fragment_for(&self, strings, format, export)` and
picks the fragment or substitutes the format-specific values there (see
`reflective_loading`, which ships a PE mapper and a shellcode runner); one that
only runs a PE may delegate to `render_fragment`, since `plan::validate`
rejects the other formats first.

## 3. Fill in `stub_fragment.rs`

Write the Rust snippet injected into the generated stub. It must be
self-contained: its own `use` statements plus the functions/constants the
technique needs. Use `$PLACEHOLDER$` for any per-build value and substitute it
in `render_fragment`.

**No string literals.** Every string that reaches the generated stub must be
built through `StringsConfig::obfuscate` (the `TODO`/`docs` convention; the
`no_sensitive_literals_in_generated_stubs` test enforces it).

**Kernel-facing calls go through the syscall layer, never the Win32 APIs
 directly.** List the technique's Nt* requirements in `TechniqueDef::syscalls`
 (e.g. `&["NtAllocateVirtualMemory", ...]`) and call the `nt_*` helpers
 (`crate::nt_alloc_vm`, `crate::nt_write_vm`, …) from the fragment. The stub
 provides the helpers with two implementations — direct Win32 calls when
 `build.stub.syscalls.mode` is `none`, indirect syscalls when it is `indirect` — so
 the fragment must not care which mode is active. See
 `src/features/syscalls/README.md`.

The engine wraps every step in its own `mod step_<index>`, so a fragment defines
an entry point and the module re-exports it under a fixed name:

- **Preparation** — `pub fn <name>() -> Result<bool, E>` (where `<name>` is the
  technique key); the module wraps it as `run() -> Result<bool, String>`.
- **Execution** — `execute_payload(&mut [u8]) -> Result<i32, String>`; the
  module wraps it as `payload(image) -> Result<i32, String>`.
- **Control** — `run_exec() -> Result<i32, E>`; the module wraps it as
  `run() -> Result<i32, String>`. `sleep` is the exception: it renders as one
  inline line, not a module.

### Preparation contract: `Ok(true)` continues, `Ok(false)` aborts

The generated runner walks the `runtime:` steps in order, one straight-line
block per step. For a Preparation it matches on `step_<index>::run()`:

- `Ok(true)` — the step accepted the host; the runner goes on to the next step.
- `Ok(false)` — the step declined the host; the runner returns `Ok(0)` and the
  stub exits without running any later step, so the payload never runs (the
  builtin template exits `0`).
- `Err(_)` — the step failed while doing its work (not a policy decision); the
  runner takes the step's `on_fail` action.

Most preparations always return `Ok(true)` (e.g. `patch_amsi`, `patch_etw`).
The `bouncer` and `guardrail` gates return `Ok(false)`; `bouncer` configured
with `on_fail: exit` exits the process with code `1` itself.

## 4. Register the technique

In `src/techniques/mod.rs`:

1. `pub mod my_technique;`
2. A `TechniqueKind` variant: `MyTechnique(my_technique::Params)`.
3. An entry in `all()`: `&[process_hollowing::DEF, my_technique::DEF]`.

Also add match arms to `TechniqueKind::render_fragment`, `TechniqueKind::name`
and `TechniqueKind::category` so the stub renderer and validation dispatch
correctly. The variant's metadata (including `formats`) lives in `DEF`. An
Execution technique that supports several payload formats gets the
`format`/`export` arguments in `render_fragment` (see step 2).

## 5. Write tests

`tests.rs` must cover, at minimum:

- the params parse (with defaults and with explicit values);
- `render_fragment` substitutes the placeholders;
- `DEF` is well-formed.

## 6. Write the README

Copy the fixed template `src/techniques/_template/README.md` and fill in every
section. `picaro techniques validate` checks them.

The README is the **explanation** of the technique, not its datasheet. Its
metadata — category, stability, ATT&CK, platforms, conflicts, syscalls, the
payload formats, the YAML parameters and the example — lives once in `DEF`
(`mod.rs`) and is rendered from the registry by `picaro techniques show` and by
the docs site, which panels and badges the technique page from the same source.
The README must not repeat it: `validate` rejects the `## Metadata`,
`## YAML parameters` and `## YAML example` headings.

Required sections (checked by `validate`): *What it does*, *How it works*,
*Integration*, *What it evades*, *What detects it*, *Measurements*,
*Implementation notes*, *References* — and `## How it works` must contain a
**```mermaid** diagram. The shape is the same for every technique, so the site
reads as a catalogue:

1. `# Title`, then one italic **TL;DR** line — a single sentence.
2. `## How it works` opens with a **```mermaid** diagram of the flow, then
   groups the detail under numbered `### N. <phase>` headings.
3. `## Integration` says where the step belongs in `runtime:`, which formats an
   Execution accepts, and how it interacts with the steps around it.

Keep the prose terse; the diagram carries the shape, the phases carry the
substance.

## 7. Update the measurements page

Add a section to `docs/measurements.md` and link it from the README's
"Measurements" section.

## 8. Run

```bash
cargo test
cargo test --features live-tests -- --ignored          # compiles each technique's stub + string-leak check
cargo clippy --all-targets
cargo run -- techniques list
cargo run -- techniques show my_technique
cargo run -- techniques validate
```

`cargo test --features live-tests -- --ignored` includes
`engine::compiler::tests::no_sensitive_literals_in_generated_stubs`: it compiles
a stub for every registered technique and fails if any sensitive literal
(`AmsiScanBuffer`, `amsi.dll`, `ntdll.dll`, ...) leaks in cleartext. A literal
counts as a leak only when it appears both in the compiled stub and in the
generated stub source (comments stripped): names the toolchain embeds
regardless of our code (the import table, `windows-result`'s `ntdll.dll`) are
ignored. This test is mandatory before merging a new technique: mentioning a
name in a doc comment is fine, but hardcoding it as a runtime string literal is
not — route it through `StringsConfig`.

## 9. Conventions

- **Names**: snake_case, matching the YAML key.
- **Stability**: `Stable` once the technique is complete and verified (a
  measurement baseline or passing runtime checks); `Experimental` while gaps
  remain; `Unimplemented` while the technique is registered but its
  implementation is not finished (a placeholder fragment, or a missing part of
  the loader contract) — the listing shows it in red and a build that selects it
  warns; `Deprecated` for techniques superseded by a better one.
- **ATT&CK**: use the specific sub-technique ID when available (e.g.
  `T1055.012`).
- Keep `stub_fragment.rs` self-contained; prefer reusing the stub skeleton's
  helpers over duplicating them.
