# Adding a loader feature

A *loader feature* is stub-level configuration (`build.stub.*` or a per-payload
block), not a `runtime:` step: it changes how the generated stub is built or how
it talks to the kernel and the payload's imports, so it carries no payload and is
not ordered in the pipeline. The ordered preparations/executions/controls are
*techniques* (`src/techniques/`); this page covers features (`src/features/`).

Each feature lives in its own directory under `src/features/` and is registered
in `src/features/mod.rs`.

## 1. Create the directory

```bash
mkdir src/features/my_feature
```

## 2. Fill in `mod.rs`

The module is **metadata only**: the implementation stays in `crate::engine`
(e.g. `engine::syscalls`). Define a `DEF` describing the feature:

```rust
use crate::techniques::Stability;
use super::{FeatureDef, FeatureScope};

pub const DEF: FeatureDef = FeatureDef {
    name: "my_feature",
    attck: &["T1xxx"],
    stability: Stability::Experimental,
    requires: &[],
    conflicts: &[],
    scope: FeatureScope::Loader,      // or FeatureScope::Payload
    yaml: "build.stub.my_feature",    // where it is configured
    doc_path: "src/features/my_feature/README.md",
    readme: include_str!("README.md"),
    params_example: "mode: on\n",
};
```

Add a small `#[cfg(test)] mod tests` asserting the `DEF` is well-formed.

## 3. Register it

In `src/features/mod.rs`:

1. `pub mod my_feature;`
2. An entry in `all()`: `&[syscalls::DEF, my_feature::DEF, …]`.

## 4. Write the README

Copy the section set the other feature READMEs use. All sections are required;
`picaro techniques validate` checks them:

`## What it does`, `## YAML parameters`, `## YAML example`, `## How it works`,
`## What it evades`, `## What detects it`, `## Implementation notes`,
`## References`.

Start with a `# Title` and, optionally, a `## Metadata` block (ATT&CK / YAML /
scope) that `picaro techniques show` replaces with its styled header. Refer to a
`docs/` page with a backticked repo path (e.g. `` `docs/measurements.md` ``),
not a relative link: the docs build inlines the README into `docs/features/ref/`,
so a relative link would resolve against the wrong directory.

## 5. Wire the docs

- Add `docs/features/ref/<name>.md` containing
  `--8<-- "src/features/<name>/README.md"`.
- Add a row to `docs/features/index.md`.
- Add a nav entry under `Loader features` in `docs/nav.yml`.

The `every_feature_is_documented` test fails if any of the three is missing.

## 6. Run

```bash
cargo test
cargo clippy --all-targets
cargo run -- techniques list
cargo run -- techniques show my_feature
cargo run -- techniques validate
```

## Conventions

- **Names**: snake_case, matching the feature's display name.
- **Stability**: `Stable` once the feature is complete and verified (a
  measurement baseline or passing runtime checks); `Experimental` while a gap or
  a caveat remains; `Unimplemented` while the implementation is not finished.
- **ATT&CK**: use the specific sub-technique ID when available.
- Keep `yaml` accurate: it is what `techniques show` prints as the feature's
  configuration path.
