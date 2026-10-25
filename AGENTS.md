# Picaro — Agent Instructions

## What this project is

A malware loader packer for **authorized red team engagements and security
research**: it takes a PE file and a YAML plan and emits a packed PE with the
selected evasion techniques baked into a generated Rust stub. Lab environments,
authorized audits and research only — any other use is out of scope and
unsupported. Full description and pipeline: `README.md`,
`docs/architecture.md`.

## Architecture principles (non-negotiable)

- **Rust first, not Rust only.** The packer and the generated stub are Rust,
  and new code prefers Rust, but a toolchain or runtime in another language is
  acceptable when it is the pragmatic choice — for example, a subprocess `yara`
  scanner, or a future C stub that calls the Rust runtime through an ABI.
  Never reimplement a technique in another language, and never embed a
  toolchain in the repo.
- **Compilers live in PATH.** Never embed toolchains in the repo.
  If `rustc` is missing, error out with clear instructions.
- **FFI via `windows-rs`.** No raw `extern "system"` unless absolutely
  necessary, and if so, encapsulated behind a safe wrapper.
- **Crypto: XChaCha20-Poly1305.** Both packer and stub. Nonce = 24 bytes.
  Crate: `chacha20poly1305`.
- **No unsafe in the packer.** Minimal, encapsulated unsafe is allowed
  only in the generated stub, for FFI.
- **Errors via `thiserror`.** Never `panic!` in user-facing code paths.
  Never `.unwrap()` outside tests.
- **No string literals in stub fragments.** Every string that ends up in the
  generated stub must go through `StringsConfig::obfuscate`. The packer's
  `render_fragment` receives `&StringsConfig` for exactly this reason. Literals
  that never reach the generated stub (compile-time constants, format strings
  in build-time code) are exempt.
- **`cargo clippy --all-targets` must be clean** before any commit.

## Tests and hosting safety (non-negotiable)

- **The project has no CI, by decision.** Never add a workflow that compiles a
  stub or runs an artifact; if CI ever returns it may only run the inert checks
  below.
- **A plain `cargo test` must stay inert.** Any test that compiles a stub or runs
  an artifact is behind the `live-tests` cargo feature **and** `#[ignore]`d, so
  the default suite neither compiles nor runs a loader.
- **Dangerous tests run by hand only, on the dedicated lab machine** (the
  isolated host with Defender disabled): `cargo build` first, then
  `cargo test --features live-tests -- --ignored`. Agents may run them on that
  machine; never on a shared/hosted one, and never as part of a default run.
  **Verify the premise at the start of every round**:
  `Get-MpComputerStatus | select RealTimeProtectionEnabled` must be `False` — a
  reboot can silently restore it, and with it on a live run fails for host
  reasons (AMSI), not because of the stub.
- The `picaro-debugger` MCP server (`.agents/mcp/`) draws the same boundary in
  code: its execution and debugger tools only exist with `--lab`, and launching
  refuses while Defender real-time protection is on. A debug session runs the
  artifact under lldb — treat it like any other live test.
- The local pre-commit gate is inert and reproducible: `cargo fmt --all --
  --check`, `cargo clippy --all-targets -- -D warnings` and the pure unit suite
  (`cargo test`).
- Never commit real offensive tool binaries (mimikatz, LaZagne, nxc, …); fixtures
  are built from source in the repo.
- Prefer a private repo.

## Coding conventions

- **Code, comments, doc comments, READMEs, commit messages: English.**
- **Personal notes, chat with the assistant, session memory: Spanish is fine.**
- Every new module ships with tests.
- Public functions get doc comments explaining *why*, not *what*.
- Test names describe behavior, not implementation.
- Prefer explicit over clever.
- **User-facing output goes through `src/ui/mod.rs`.** Use `Palette` (`banner`,
  headings, `field`/`step`/`done`) instead of hand-written ANSI escapes or
  ad-hoc formatting; color degrades to plain text when redirected.
- When adding a technique, grep the fragment for `"` before committing. If the
  string is used at runtime by the stub, it must come from `StringsConfig`.

## Where to look

- **Repo layout and the build/audit pipeline:** `docs/architecture.md`.
- **Techniques:** one directory per technique (README + stub fragment + tests)
  under `src/techniques/<name>/`. The registry (`src/techniques/mod.rs`) is
  metadata-only; inspect it with `picaro techniques {list,show,validate}`. The
  add-a-technique checklist is `src/techniques/README.md`.
- **A technique's status, measurements and limitations** live in its own
  README — read it before changing a technique.
- **Current state, open debt and the rolling log:** `.memory.md`.
- **Measurements (the numbers behind every claim):** `docs/measurements.md`;
  x86 phases: `docs/x86.md`.
- **Docs site:** Astro + Starlight; the nav is `docs/nav.yml` (the single source
  of truth the Rust doc tests also read); preview with
  `python scripts/docs.py`.

## Session workflow

At the **start** of a session:
- Read this file.
- Read `.memory.md`: the `## Current state` section first, then the newest log
  entries.

At the **end** of a session:
- Update `.memory.md`: add a dated entry at the top of the log (newest first,
  right after the `## Current state` section) with what was done, open questions
  and next steps.
- Keep each entry short. `.memory.md` (the `## Current state` section plus the
  rolling log) is the project's state; this `AGENTS.md` stays static
  instructions.
