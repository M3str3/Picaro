# Manual end-to-end tests

This example uses a test payload (`test_payload.exe`) that shows a
`MessageBoxA` with the fixed marker `PAYLOAD_MARKER_7f3a9c2e`.

## Process hollowing

## 0. Requirements

- `rustc` on the PATH.
- Workspace dependencies already compiled: `cargo build` at the repo root.
- Process Explorer or Process Hacker (to confirm the hollowing in step 5).

## 1. Compile the test payload (if missing)

```powershell
powershell -ExecutionPolicy Bypass -File examples/payloads/build_test_payload.ps1
```

## 2. Pack

```powershell
cargo run -- build examples/configs/test-msgbox.yaml
```

This produces `dist/test_packed.exe` (and leaves intermediate artifacts in
`build/`).

## 3. Open Process Explorer / Process Hacker

Open it *before* running the packed binary so you can see which process owns
the second MessageBox.

## 4. Run the packed binary

```powershell
.\dist\test_packed.exe
```

Two `MessageBox` windows appear, in order:

1. `STUB_MARKER_<hex>` (title `Stub`) — shown by the stub.
2. `PAYLOAD_MARKER_7f3a9c2e` (title `Payload`) — shown by the hollowed payload.

## 5. Confirm the hollowing (the key check)

The second MessageBox must be shown by **svchost.exe**, not `test_packed.exe`.
In Process Explorer, find the process that owns the `PAYLOAD_MARKER_7f3a9c2e`
window: it should be `svchost.exe` (the process the stub hollowed), not the
stub itself.

## 6. Verify no cleartext payload on disk

The stub never writes the decrypted payload. There must be **no**
`payload_decrypted.bin` in the working directory.

## 7. Verify obfuscation (no cleartext markers)

```bash
strings dist/test_packed.exe | grep STUB_MARKER      # should print nothing
strings dist/test_packed.exe | grep PAYLOAD_MARKER   # should print nothing
strings dist/test_packed.exe | grep -i svchost        # should print nothing
```

- `PAYLOAD_MARKER` is encrypted (does not appear).
- `STUB_MARKER` and the target path (`svchost.exe`) are XOR-obfuscated.

## Reflective loading

Loads the payload into the current process (no external target).

```powershell
cargo run -- build examples/configs/test-msgbox-reflective.yaml
.\dist\test_packed_reflective.exe
```

Two `MessageBox` windows appear, in order, **both owned by the packed binary
itself** (there is no `svchost.exe`):

1. `STUB_MARKER_<hex>` (title `Stub`) — shown by the stub.
2. `PAYLOAD_MARKER_7f3a9c2e` (title `Payload`) — shown by the mapped payload.

Verify the payload was mapped, not spawned:

```bash
strings dist/test_packed_reflective.exe | grep -i svchost   # should print nothing
strings dist/test_packed_reflective.exe | grep PAYLOAD_MARKER # should print nothing
```
