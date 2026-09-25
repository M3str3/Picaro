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

The pipeline validation (`src/config/validate.rs`) enforces `0..N` Preparation
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
- Fill in `DEF` — the `TechniqueDef` metadata (name, ATT&CK, stability,
  category, …).
- Implement `Params::render_fragment` — substitute the technique's
  `{{PLACEHOLDER}}` values into `DEF.stub_fragment`.

## 3. Fill in `stub_fragment.rs`

Write the Rust snippet injected into the generated stub. It must be
self-contained: its own `use` statements plus the functions/constants the
technique needs. Use `{{PLACEHOLDER}}` for any per-build value and substitute it
in `render_fragment`.

A Preparation fragment must expose a `pub fn <name>() -> Result<(), E>` entry
point (where `<name>` is the technique key); the stub wraps each Preparation
fragment in its own module and calls that entry point from the generated
`run_preparations` dispatcher. An Execution fragment must expose
`execute_payload(&mut [u8]) -> Result<i32, String>` (the stub calls it
unqualified).

## 4. Register the technique

In `src/techniques/mod.rs`:

1. `pub mod my_technique;`
2. A `PipelineStep` variant: `MyTechnique(my_technique::Params)`.
3. An entry in `all()`: `&[process_hollowing::DEF, my_technique::DEF]`.

Also add match arms to `PipelineStep::render_fragment`, `PipelineStep::name`
and `PipelineStep::category` so the stub renderer and validation dispatch
correctly.

## 5. Write tests

`tests.rs` must cover, at minimum:

- the params parse (with defaults and with explicit values);
- `render_fragment` substitutes the placeholders;
- `DEF` is well-formed.

## 6. Write the README

Copy the fixed template `src/techniques/_template/README.md` and fill in every
section. All sections are required; `packerman techniques validate` checks them.

## 7. Update `docs/measurements/`

Add a measurement file under `docs/measurements/` and link it from the README's
"Measurements" section.

## 8. Run

```bash
cargo test
cargo clippy --all-targets
cargo run -- techniques list
cargo run -- techniques show my_technique
cargo run -- techniques validate
```

## 9. Conventions

- **Names**: snake_case, matching the YAML key.
- **Stability**: `Stable` only after the technique has a measurement baseline;
  otherwise `Experimental`. Use `Deprecated` for techniques superseded by a
  better one.
- **ATT&CK**: use the specific sub-technique ID when available (e.g.
  `T1055.012`).
- Keep `stub_fragment.rs` self-contained; prefer reusing the stub skeleton's
  helpers over duplicating them.
