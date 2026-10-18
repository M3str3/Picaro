---
name: picaro-techniques
description: "Inspect and review Picaro's technique registry: list techniques with their category, stability and ATT&CK id, read one technique's README, validate the registry, and follow the project's add-a-technique checklist (fragment rules, no cleartext strings, tests, clippy). Use when the user asks which techniques exist, what a technique does or which are experimental, how to add/rename/review a technique, or where a technique's code and docs live."
---

# Picaro techniques

Use this skill to work with the **technique registry** — the module of the
library that maps a plan's `technique:` key to a stub fragment. It answers "what
exists", "what does it do", "is it stable", and "how would I add or change one".

Scope: **read/inspect by default**. Only change the registry or a technique when
the user actually asks for that change.

## Inspect the registry (inert MCP tools)

The `picaro-debugger` MCP server exposes the registry read-only (no sample, no
`--lab` needed; see `.agents/mcp/README.md`):

```
techniques_list()                           # every technique: key, category, stability, ATT&CK, summary
technique_show(name="reflective_loading")   # that technique's full README (what it does + its plan keys)
techniques_validate()                       # keys, fragments and loader features; the verdict is the text
```

Equivalents in a terminal (same output): `picaro techniques list`,
`picaro techniques show <name> --raw`, `picaro techniques validate`.

## Where the truth lives

| What | Where |
| --- | --- |
| How to add a technique (canonical, read this first) | `src/techniques/README.md` |
| The registry (metadata only: keys, categories) | `src/techniques/mod.rs` |
| One technique: README + stub fragment + tests | `src/techniques/<name>/` |
| Project conventions and non-negotiables | `AGENTS.md` |
| The technique pages on the docs site | `docs/nav.yml` (nav) + `src/techniques/*/README.md` inlined by `docs/site/scripts/assemble-docs.mjs` |

The registry entry is metadata only; the behaviour is the stub fragment. If the
two disagree, the fragment is what runs.

## Reading a technique before touching it

1. `technique_show(name=...)` for the overview, or read
   `src/techniques/<name>/README.md` for the full text (identical content).
2. Read the fragment (`src/techniques/<name>/stub_fragment.rs`) — it is the
   Rust that lands in the generated stub. Fragments are rendered by
   `render_fragment(..., &StringsConfig)`.
3. Check the technique's tests (`tests.rs` in the same directory).

## Checklist: adding or changing a technique

Follow `src/techniques/README.md` for the mechanics; this is the order that
avoids the usual misses:

1. **Read the canonical doc** (`src/techniques/README.md`) — it names the trait,
   the `Category`, the stability levels and the fragment contract.
2. **Create/update `src/techniques/<name>/`**: README + `stub_fragment.rs` +
   `tests.rs`. Every new module ships with tests (names describe behaviour).
3. **Register it** in `src/techniques/mod.rs` (metadata only) and pin its
   stability (`Stable` / `Experimental` / `Unimplemented`).
4. **No cleartext strings in the fragment.** Every string the stub uses at
   run time must go through `StringsConfig::obfuscate` (the fragment receives
   `&StringsConfig` for exactly this). Before committing, grep the fragment for
   `"` and justify every hit. Diagnostics count — they are strings the stub
   prints.
5. **Keep the chain rule in mind**: a technique that never returns control
   (`reflective_loading` of a PE, `dotnet_hosting`) must be the last runtime
   step; say so in the README so `plan::validate` and the user agree.
6. **Run the gate**: `cargo fmt --all -- --check`,
   `cargo clippy --all-targets -- -D warnings`, `cargo test` (the default suite
   is inert), and `techniques_validate()`.
7. **If it runs an artifact, it is a lab test**: behind the `live-tests` feature
   **and** `#[ignore]`d, run by hand on the lab host with Defender real-time off
   (see `AGENTS.md`, "Tests and hosting safety"). Never in a default run.

## Traps

- `technique_show`/`techniques_list` describe techniques; they do not tell you a
  technique is *unimplemented*. Check the stability column from
  `techniques_list` (or the README) before trusting a technique in a plan.
- A technique's README is documentation **and** the source of its docs-site page;
  keep it accurate and in English.
- The registry is not where payload keys are resolved: a runtime step pins its
  payload in `src/plan/steps.rs`, not in the technique.
- Do not infer a technique's imports or syscall needs from its README alone;
  the fragment declares them and the build unions them into the stub.
