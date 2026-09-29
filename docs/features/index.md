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

| Feature | Scope | ATT&CK | Stability | Summary |
| --- | --- | --- | --- | --- |
| [syscalls](ref/syscalls.md) | loader | T1106 | stable | Resolves NT SSNs at runtime and calls the kernel through an ntdll `syscall; ret` gadget, so the suspicious Win32 imports leave the IAT. |
| [api_resolution](ref/api_resolution.md) | loader | T1106 | experimental | Serves selected payload imports from proxies built on the syscall layer, so the shadowed names never enter the loader's IAT. |
| [strings](ref/strings.md) | loader | T1027 | stable | Obfuscates every sensitive string literal in the generated stub and rebuilds it at runtime. |
| [args](ref/args.md) | payload | T1036, T1055 | stable | Fixes the payload's command line at build time and merges it with the runtime arguments. |

## Adding one

[Adding a loader feature](adding-a-feature.md).
