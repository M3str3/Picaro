# Loader features

A **loader feature** is stub-level configuration, not a `runtime:` step. It
changes how the generated stub is built, how it talks to the kernel, or how it
resolves the payload's imports, so it carries no payload and is not ordered in
the pipeline. The ordered preparations/executions/controls are
[techniques](../techniques/index.md).

The registry (`src/features/mod.rs`) is metadata-only: `picaro techniques list`
prints the features in their own table, `picaro techniques show <name>` renders a
feature's README, and `picaro techniques validate` checks the registry.

## Registered features

<!-- registry-table -->

## Adding one

[Adding a loader feature](adding-a-feature.md).
