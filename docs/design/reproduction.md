# Reproduction

**Status:** implemented and live-verified (phases 1–6: entropy, crypto injection,
manifest-as-plan, replay, effective hash and v3 migration). The contract tests
ran on the lab host on 2026-10-24: `42 + 36 + 5` ignored tests green, including
same-seed byte equality and replay with `--verify`.

Goal: a build is a **document**. The artifact's manifest is not a sidecar that
describes a build; it *is* the build, in the same shape as a plan, and feeding it
back reproduces the artifact:

```bash
picaro build hello.yaml            # first build
picaro build hello.manifest.json   # same artifact, same seeds, same bytes
```

This page is the design: the guarantee, the entropy model, the manifest schema,
the replay semantics and the tests that define "done". It is the contract that
the wizard (see [Wizard design](wizard.md)) writes and the CLI honours.

---

## 1. The problem

Today the manifest is **provenance**, not reproduction. `src/engine/manifest.rs`
says so explicitly:

> Reproducing an artifact byte for byte is not possible by design (the payload
> key and nonce are random per build) …

That sentence is true of the current code, and it is the thing this design
changes. The information needed for replay is *almost all* already recorded, but

- there is no command that consumes it (`Commands` is `build | audit |
  techniques`), and
- five independent RNGs decide the bytes, only three of which are recorded:

| Entropy | Source today | Recorded? | Pinnable from the plan? |
|---|---|---|---|
| payload key | `KeySource::Random` (the only variant) | never | no such variant |
| payload nonce | generated inside `encrypt_payload` | `steps[].nonce` | no injection point |
| polymorphism | `mode: full` + random seed | seed + full codegen profile | `seed: literal:<u64>` |
| strings key | random per build | no | no |
| generated icon | `rand::random()` | seed | `icon: random` only, no seed |
| `VERSIONINFO` randomize | `thread_rng` | resolved values only | no seed |
| scrub filler | `thread_rng` | **no** | no |
| signing | CA serial + optional RFC 3161 timestamp | metadata | not reproducible by nature |

Worse, a **release** build of the packer never prints the payload key
(`#[cfg(debug_assertions)]`, `src/cli/`), so even a manual replay is
impossible today: the key exists only inside the artifact.

The fix is not "record more". It is to make entropy a **single, named input**
whose value travels with the build, and to make the manifest that input's home.

---

## 2. The contract

A build is identified by its **effective inputs**:

```
effective = resolved plan
          + payload bytes (sha256)
          + BuildEntropy (one seed)
          + toolchain (rustc version + target + profile)
```

The guarantee, stated so it can be tested:

> Given the same effective inputs, `picaro` produces the same **unsigned**
> artifact, byte for byte, on the same toolchain.

Three levels:

| Level | Stored in the manifest | Reproduces |
|---|---|---|
| `exact` *(default)* | plan + seeds + nonce + **key** | the same artifact bytes (unsigned) |
| `audit` | plan + seeds, **no key** | the same code with fresh ciphertext; `effective_sha256` and `payload_sha256` match |
| `strict` | `exact` + toolchain check | the same bytes or a hard failure |

The manifest stores the payload key by default: a reproducible build that cannot
recover its own key is not reproducible. `audit` exists only for a copy that will
be shared (`--redact`). `strict` is a replay flag (`--strict`), not a manifest
field.

**This does not change how a build behaves.** Entropy stays random per build
(polymorphism on, fresh key and nonce), so two normal builds still differ and
evasion is untouched. The change is that the values a build *already* chose are
recorded, so the same artifact can be produced again. Reproducibility is a
recording property, not a new build mode.

**Signing is outside the contract.** An Authenticode signature carries a serial
and, optionally, an RFC 3161 timestamp; neither is reproducible. The manifest
records both hashes:

- `unsigned_sha256` — the reproducibility target, recorded before signing;
- `artifact_sha256` — the file that was actually written.

A replay comparison always uses `unsigned_sha256`.

---

## 3. The manifest is a plan

The current manifest nests the plan under `resolved_plan`, so it can never be
fed back: `load_plan` expects `schema`/`name`/`build`/`runtime` at the top level.

The new layout **is** that top level, plus one `reproduce` block. Schema `4`:

```json
{
  "schema": 6,
  "name": "hello",
  "build": { "crypto": { ... }, "payloads": { ... }, "stub": { ... }, "output": { ... } },
  "runtime": [ { "technique": "reflective_loading" } ],
  "reproduce": {
    "manifest_schema": 4,
    "picaro": "0.1.0",
    "toolchain": { "rustc": "rustc 1.xx.y (...)", "target": "x86_64-pc-windows-msvc" },
    "entropy": {
      "seed": "0x9f2c...",
      "polymorphism": { "mode": "full", "codegen": { ... } },
      "strings": { "strategy": "xor" }
    },
    "secrets": "exact",
    "payloads": {
      "implant": {
        "sha256": "…",
        "size": 123456,
        "nonce": "…",
        "key": "…"
      }
    },
    "predecessor": {
      "built_at": "2026-10-24T12:00:00Z",
      "artifact": "dist/hello.exe",
      "artifact_sha256": "…",
      "unsigned_sha256": "…"
    }
  }
}
```

Properties that matter:

- **1:1 with the plan.** `build` and `runtime` are the resolved plan, verbatim.
  Serializing a wizard recipe and a manifest use the same code path.
- **JSON is valid YAML.** `load_plan` uses `serde_yml`; a `.manifest.json`
  parses through the existing loader with no second parser. Detection is by
  content (`reproduce` present), not by extension.
- **The `reproduce` block is optional in a plan.** A hand-written YAML with a
  `reproduce: { seed: ... }` is a reproducible plan; the wizard writes exactly
  that.
- **`resolved_plan` disappears.** Keeping both shapes would let them drift, which
  is the failure mode this design exists to remove.
- **`predecessor` is the build the record describes.** On a replay, the source
  manifest's value is what `--verify` compares the new unsigned hash against;
  the manifest written for the new build records that build in the same field.

`Plan` gains `#[serde(default, skip_serializing_if = "Option::is_none")] reproduce:
Option<ReproducePlan>`. `Plan` does not use `deny_unknown_fields`, so the field
is additive and old plans stay valid; `BuildPlan` keeps its stricter gate.

### Why not a sibling recipe file

A `<stem>.repro.json` next to a `<stem>.yaml` was rejected: two documents, two
truths, and the "which one do I edit" problem. One document, one shape.

---

## 4. Entropy: one seed, derived, recorded

```rust
pub struct BuildEntropy {
    pub seed: u64,          // the only input
}

impl BuildEntropy {
    pub fn from_plan(reproduce: Option<&ReproducePlan>, seed: Option<u64>) -> Self;
    fn derive(&self, domain: Domain) -> u64;   // splitmix64 with domain separation
}

pub enum Domain {
    Polymorphism, Icon, Identity, Scrub, StringsKey, PayloadKey, PayloadNonce,
}
```

- **One RNG.** All five `thread_rng`/`rand::random()` call sites
  (`polymorphism.rs`, `src/cli/` icon resolution, `identity.rs`, `scrub.rs`,
  `obfuscation.rs`) take a value from `BuildEntropy::derive`, never from a fresh
  RNG. `Domain` values are constants with fixed spellings; changing one changes
  artifacts, so they are part of `manifest_schema`.
- **Derivation is stable and documented.** `splitmix64(seed ^
  domain_constant)` (the mixer in `src/engine/mixer.rs`), so a
  seed and a domain reproduce a value forever. A test pins a handful of known
  (seed, domain) → value pairs; changing the mixer is a schema bump.
- **What is stored.** The master seed *and* the resolved values that are not
  derivable twice without the compiler: the polymorphism codegen profile (already
  recorded) and the icon seed (already recorded). Everything else is derivable,
  but recording the resolved nonces stays: they are public, and they let a
  verifier check the ciphertext without the key.
- **The seed is a secret in `exact`.** If the key derives from it, the seed is
  key-equivalent. That is a feature (one value reproduces everything) and a
  hazard (the manifest is now as sensitive as the payload). See §8.

`KeySource` gains variants:

```yaml
build:
  crypto:
    key: random            # default
    key: literal:<hex>     # 32 bytes, for tests and reproductions
    key: file:./key.bin    # never committed (already in .gitignore as *.key)
```

and `crypto::encrypt_payload_with_nonce(plaintext, key, nonce)` is added next to
`encrypt_payload` (which keeps generating a random nonce). The stub already
takes key and nonce as hex literals, so nothing in the renderer changes.

---

## 5. `picaro build <manifest>`

### Detection

`load_plan` gains a pre-step:

1. Read the document (unchanged).
2. If it has a `reproduce` block → replay mode.
3. Else → a normal plan; if it has no `reproduce`, entropy is random exactly as
   today.

No extension check, no separate subcommand: `picaro build hello.manifest.json`
works, and so does `picaro build hello.json`.

### Precedence

```
CLI overrides  >  reproduce block  >  plan defaults  >  random
```

| Flag | Effect |
|---|---|
| `--key-file <path>` | supplies payload keys for `secrets: audit` manifests |
| `--seed <u64>` | overrides `reproduce.entropy.seed` |
| `--strict` | fail if `rustc --version` differs from `reproduce.toolchain` |
| `--verify` | compare the new `unsigned_sha256` with `predecessor.unsigned_sha256`; exit `4` on mismatch |
| `--out <path>` | write the artifact elsewhere (never clobbers the source recipe) |
| `--payload <name>=<path>` | relocate a payload whose `source` moved |
| `--redact <path>` | write a copy of the manifest with `secrets: audit` (keys stripped) |

Without `--out`, the delivered path is the plan's `output.path` when set and
the bundle's `dist/` otherwise; the manifest written for the new artifact is
`<bundle>/artifacts/<stem>.manifest.json`, so replaying `hello.manifest.json`
never overwrites the recipe itself.

### Errors

- A payload whose sha256 does not match `reproduce.payloads.<name>.sha256` is a
  hard error (the point of pinning), unless `--payload` supplies a replacement
  that matches.
- `secrets: audit` plus no key plus `--verify`: warn that only the code is
  reproduced (the ciphertext differs) and exit `4`; without `--verify`, build
  succeeds and prints the same warning.
- `--strict` plus a toolchain mismatch: exit `5` before compiling. A different
  `rustc` may still build the same bytes, but the contract does not promise it.

### What replay does *not* do

- It does not re-read the original YAML. The manifest is the source.
- It does not re-run plan validation differently: the same `validate` runs on
  the embedded plan. A manifest that no longer validates (a technique was
  removed between versions) fails with the validation error, not a silent build.
- It does not renegotiate the output path of resources: `output.resources`
  paths are relative to the recipe, so replay resolves them the same way. A
  moved asset is reported by name.

---

## 6. Determinism matrix

What must match for `unsigned_sha256` to match:

| Input | Affects | Where it is fixed |
|---|---|---|
| resolved plan (steps, params, stub, output) | everything | `build`/`runtime` in the manifest |
| payload bytes | ciphertext, sizes | `reproduce.payloads[].sha256` |
| payload key + nonce | ciphertext | `secrets: exact` (`key`, `nonce`) |
| strings strategy + key | `.rdata` literals | `entropy.seed` + `entropy.strings` |
| polymorphism seed + codegen profile | `.text` | `entropy.polymorphism` |
| icon seed | `.rsrc` | `entropy.icon` |
| identity values | `VERSIONINFO` | `reproduce.identity` (resolved, not seed) |
| scrub seed | patched bytes in `.rdata` | `entropy.seed` |
| `strip`, `trim_paths`, remap flags | debug info, paths | plan + compiler flags (unchanged) |
| rustc + target + profile | code | `toolchain` (+ `--strict`) |
| linker `TimeDateStamp` | 4 bytes in the headers + the debug directory | pinned with `/Brepro` (MSVC) or `--no-insert-timestamp` (GNU) |
| build path (scratch dir) | embedded source paths, and the `/Brepro` hash | the stub-dir remap must be the **last** `--remap-path-prefix` (rustc is last-match-wins) |
| signing | final file only | excluded; compare `unsigned_sha256` |

`identity` is recorded resolved rather than seeded because the resolved strings
are what the artifact embeds; a seed only adds an indirection with no
verification benefit. (If the wizard preset promises "same fake company", the
resolved values are the honest record.)

---

## 7. Migration

- `manifest_schema: 3` is read best-effort: `resolved_plan` is lifted to the top
  level, `polymorphism`/`generated_icon`/`steps[].nonce` map into `reproduce`,
  and `secrets` defaults to `audit` (v3 never stored keys). A v3 manifest can be
  replayed with `--key-file`, never byte-identically without it.
- New manifests are schema `4` and are valid plans. `output.manifest` keeps its
  meaning: write the recipe/manifest into the bundle's `artifacts/`.
- `plan_sha256` is replaced by **`effective_sha256`**: the hash of the canonical
  `(resolved plan, entropy, payload sha256s)`, excluding `predecessor`. The old
  hash did not cover the seeds, so two builds could share it while differing;
  that was a contract bug, not a naming problem. Keep emitting `plan_sha256` for
  one release as a deprecated alias.

---

## 8. Security

The manifest is executable material: whoever holds it can rebuild the payload's
plaintext as soon as they hold the artifact and the key.

- `secrets: exact` (key inline) is the **default**, because it is the only
  setting that satisfies the goal. The manifest is payload-equivalent; `--redact`
  writes a shareable copy without the key.
- `secrets: audit` is opt-in, for a copy that leaves the lab.
- `--redact` produces a shareable copy (keys stripped, hashes kept).
- Manifests live in `packed/<plan>-<run>/artifacts/` (gitignored) and must never
  be committed. Add `*.manifest.json` to the existing root-hygiene rules; it is
  already covered by the artifact side-output rule, and the docs must say why.
- The seed is a secret under `exact` for the same reason as the key: it derives
  it. Document it next to the key, not as a "harmless number".

---

## 9. Implementation map

| Piece | File | Change |
|---|---|---|
| `BuildEntropy` + domains | `src/engine/entropy.rs` (new) | one seeded source, `derive`, tests with pinned vectors |
| `ReproducePlan` | `src/plan/schema/mod.rs` | `Plan.reproduce`, `secrets`, payload pins, toolchain |
| manifest layout | `src/engine/manifest.rs` | top-level plan + `reproduce`, `unsigned_sha256`, schema 4 |
| key/nonce injection | `src/engine/crypto.rs` | `encrypt_payload_with_nonce`, `KeySource` variants |
| seed plumbing | `polymorphism.rs`, `obfuscation.rs`, `identity.rs`, `scrub.rs`, `src/cli/` | take values from `BuildEntropy` |
| replay | `src/plan/mod.rs` + `src/cli/` | detect `reproduce`, flag precedence, verify |
| determinism | `src/engine/compiler/mod.rs` | `/Brepro` (MSVC) / `--no-insert-timestamp` (GNU) and the stub-dir remap **after** the manifest remap |
| docs | `docs/architecture.md`, `docs/design/polymorphism.md` | link this page; fix the "impossible by design" claim |

Suggested order: entropy first (it changes every build's bytes), then the
manifest layout, then replay, then `--verify`. Each step is shippable on its
own; the guarantee only holds once all four are in.

---

## 10. Verification

Inert (default `cargo test`):

- `BuildEntropy::derive` pinned vectors per domain.
- `manifest → Plan → manifest` round-trip equality.
- A v3 manifest lifts into schema 4 without loss of the fields that exist.
- `secrets: audit` never serializes a key; `--redact` strips it.

Live (`--features live-tests -- --ignored`, lab host):

- **The contract test:** bake a seeded plan twice → equal `unsigned_sha256`.
- Same plan, different seed → different `.text` (polymorphism still works).
- Replay `hello.manifest.json` → equal `unsigned_sha256`; `--verify` exits `0`.
- Replay with a corrupted payload → fails on the sha256 pin.
- `--strict` against a doctored toolchain string → exits `5`.

The first test is the definition of done. If it is not in the suite, the
contract is prose.

---

## 11. Decisions

| # | Decision | Alternatives considered |
|---|---|---|
| D-1 | The manifest is the plan (one document) | sidecar `.repro.json`; nested `resolved_plan` (rejected: drift) |
| D-2 | `secrets: exact` inline keys, **default**; `audit` opt-in | never store the key (rejected: `build manifest` must reproduce); out-of-band master secret (deferred) |
| D-3 | Guarantee covers the unsigned artifact | sign deterministically (rejected: timestamps) |
| D-4 | One master seed with domain separation | per-domain seeds (more knobs, more drift) |
| D-5 | Detection by content, not extension | `.manifest.json` only (rejected: a plan may carry `reproduce`) |
| D-6 | `--verify` compares `unsigned_sha256` | compare the signed file (rejected: not reproducible) |

Open: none. Keys are recorded and `exact` is the default; the remaining risk is
handling (a manifest is as sensitive as the payload), which §8 covers. Signing
stays outside the guarantee: with `sign.mode` set, the final file differs by its
signature even when `unsigned_sha256` matches.
