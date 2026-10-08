// Minimal custom loader stub.
//
// A custom stub (`build.stub.path`) replaces the builtin one. It is rendered
// through the same substitution engine and may reference any of the valid
// placeholders (documented in docs/custom-stubs.md): the shared helpers, the
// per-step modules, the generated runner, the syscall layer, the payload
// argument/import blocks, the API resolution proxies and the ARG_<key> build
// arguments.
//
// This stub keeps its own `main`/`run` and pulls in the generated machinery.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, Key, XNonce,
};

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
$STEP_RUNNER_BODY$
    Ok(last)
}

$STUB_HELPERS$
$STEP_MODULES$
$SYSCALLS_BLOCK$
$ARGS_BLOCK$
$IMPORTS_BLOCK$
$API_RESOLUTION_BLOCK$
