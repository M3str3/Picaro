# Adding a technique

Each technique lives in its own directory under `src/techniques/` and is
registered in `src/techniques/mod.rs`. This file walks through adding a new
one.

## Categories

Every technique is either Preparation or Execution (`TechniqueDef.category`):

- **Preparation** (`Category::Preparation`) — modifies the current process
  state (e.g. patches AMSI) but never runs the payload. The stub runs these
  first, in YAML order, and they take no payload argument.
- **Execution** (`Category::Execution`) — runs the decrypted payload. The stub
  runs exactly one of these, after all Preparation techniques.

The pipeline validation (`src/plan/validate.rs`) enforces `0..N` Preparation
followed by exactly one Execution. Preparation techniques must appear before
the Execution technique in the YAML.

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

An **Execution** technique also gets the payload's binary format
(`build.payloads.<name>.format`) and export (`build.payloads.<name>.export`) through
`RuntimeStep::render_fragment`. A technique that runs more than one payload
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

A Preparation fragment must expose a `pub fn <name>() -> Result<bool, E>` entry
point (where `<name>` is the technique key); the stub wraps each Preparation
fragment in its own module and calls that entry point from the generated
`run_preparations` dispatcher. `Ok(true)` continues the pipeline; `Ok(false)`
aborts it, so the payload never runs. An Execution fragment must expose
`execute_payload(&mut [u8]) -> Result<i32, String>` (the stub calls it
unqualified).

### Preparation contract: `Ok(true)` continues, `Ok(false)` aborts

The generated `run_preparations` runs every Preparation in YAML order and
returns `Result<bool, String>`:

- `Ok(true)` — every preparation accepted the host; the stub goes on to run the
  Execution technique.
- `Ok(false)` — a preparation declined the host; `run_preparations` stops and
the stub exits without touching the payload (the builtin template exits `0`).
- `Err(_)` — a preparation failed while doing its work (not a policy decision);
the stub reports the error and exits `1`.

Most preparations always return `Ok(true)` (e.g. `patch_amsi`, `patch_etw`).
The `bouncer` gate is the one that returns `Ok(false)`, or, when configured with
`on_fail: exit`, exits the process with code `1` itself.

## 4. Register the technique

In `src/techniques/mod.rs`:

1. `pub mod my_technique;`
2. A `RuntimeStep` variant: `MyTechnique(my_technique::Params)`.
3. An entry in `all()`: `&[process_hollowing::DEF, my_technique::DEF]`.

Also add match arms to `RuntimeStep::render_fragment`, `RuntimeStep::name`
and `RuntimeStep::category` so the stub renderer and validation dispatch
correctly. An Execution technique that supports several payload formats gets the
`format`/`export` arguments in `render_fragment` (see step 2).

## 5. Write tests

`tests.rs` must cover, at minimum:

- the params parse (with defaults and with explicit values);
- `render_fragment` substitutes the placeholders;
- `DEF` is well-formed.

## 6. Write the README

Copy the fixed template `src/techniques/_template/README.md` and fill in every
section. All sections are required; `picaro techniques validate` checks them.

## 7. Update the measurements page

Add a section to `docs/measurements.md` and link it from the README's
"Measurements" section.

## 8. Run

```bash
cargo test
cargo test -- --ignored          # compiles each technique's stub + string-leak check
cargo clippy --all-targets
cargo run -- techniques list
cargo run -- techniques show my_technique
cargo run -- techniques validate
```

`cargo test -- --ignored` includes
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
