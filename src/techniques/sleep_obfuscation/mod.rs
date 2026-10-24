//! Sleep obfuscation.
//!
//! Encrypts the executable image while the process sleeps, so a memory scan
//! during the sleep window sees ciphertext instead of payload bytes. A
//! Preparation technique: it modifies the process state and never runs the
//! payload. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Which sleep-obfuscation mechanism the technique uses.
///
/// Only [`Variant::Ekko`] (timer queue + ROP + `NtContinue`) is implemented in
/// this phase. The other two are recognized so the parser can reject them with
/// a clear "not implemented yet" message instead of a generic deserialization
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Variant {
    /// Timer queue + ROP chain + `NtContinue` (C5pider's Ekko).
    Ekko,
    /// APC-based (`NtQueueApcThread` + `NtTestAlert`). Future phase.
    Foliage,
    /// Waitable timers + `NtContinue`. Future phase.
    Cronos,
}

impl Variant {
    /// Lowercase label used in validation messages.
    pub fn label(self) -> &'static str {
        match self {
            Variant::Ekko => "ekko",
            Variant::Foliage => "foliage",
            Variant::Cronos => "cronos",
        }
    }
}

/// One region class in `encrypt_regions`.
///
/// All three values are recognized by the parser; only [`EncryptRegion::Payload`]
/// is implemented in this phase (rejected otherwise in `plan::validate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptRegion {
    /// The payload's region (this phase: the whole stub image region).
    Payload,
    /// Also the current stack (needs its own stack-safe ROP chain). Future.
    Stack,
    /// Every committed executable region. Future.
    All,
}

/// Parameters for the sleep-obfuscation preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Which variant to run (only `ekko` is implemented).
    #[serde(default = "default_variant")]
    pub variant: Variant,
    /// Length of the obfuscated sleep, in milliseconds.
    #[serde(default = "default_sleep_ms")]
    pub sleep_ms: u64,
    /// Which region classes to encrypt while sleeping. Accepts either a bare
    /// name (`all`) or a list (`[payload, stack]`), matching the documented
    /// YAML forms.
    #[serde(
        default = "default_encrypt_regions",
        deserialize_with = "deserialize_encrypt_regions"
    )]
    pub encrypt_regions: Vec<EncryptRegion>,
}

/// Deserializes `encrypt_regions` from either a bare region name or a list.
fn deserialize_encrypt_regions<'de, D>(deserializer: D) -> Result<Vec<EncryptRegion>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct RegionListVisitor;

    impl<'de> serde::de::Visitor<'de> for RegionListVisitor {
        type Value = Vec<EncryptRegion>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter
                .write_str("a region name ('payload', 'stack', 'all') or a list of region names")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let region =
                EncryptRegion::deserialize(serde::de::value::StrDeserializer::<E>::new(value))?;
            Ok(vec![region])
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            Vec::<EncryptRegion>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
        }
    }

    deserializer.deserialize_any(RegionListVisitor)
}

/// Default variant: the canonical ekko.
pub fn default_variant() -> Variant {
    Variant::Ekko
}

/// Default sleep length: 5 seconds.
pub fn default_sleep_ms() -> u64 {
    5000
}

/// Default regions: the payload region only.
pub fn default_encrypt_regions() -> Vec<EncryptRegion> {
    vec![EncryptRegion::Payload]
}

impl Default for Params {
    /// Defaults to the canonical ekko variant, a 5-second sleep and the payload
    /// region only (see [`default_variant`], [`default_sleep_ms`],
    /// [`default_encrypt_regions`]).
    fn default() -> Self {
        Self {
            variant: default_variant(),
            sleep_ms: default_sleep_ms(),
            encrypt_regions: default_encrypt_regions(),
        }
    }
}

/// Static metadata for the sleep-obfuscation preparation.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "sleep_obfuscation",
    attck: &["T1027"],
    // Measured 2026-10-14: the whole image is RC4 ciphertext under
    // `PAGE_READWRITE` for `sleep_ms` and restored byte-for-byte afterwards
    // (README). Not `Stable`: the operational form (encrypting during the
    // *payload's* own sleeps) and the payload-region enumeration are open —
    // this phase is the one-shot demo sleep over the whole image.
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/sleep_obfuscation/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example:
        "technique: sleep_obfuscation\nparams:\n  variant: ekko\n  sleep_ms: 5000\n  encrypt_regions: [payload]\n",
    // The timer-queue mechanism calls Win32 APIs resolved dynamically at
    // runtime; nothing goes through the syscall layer.
    syscalls: &[],
    resolves_imports: false,
};

impl Params {
    /// Renders the thin adapter that calls the shared `sleep_runtime` block.
    ///
    /// The ekko mechanism, its API/DLL names, its RC4 key and its diagnostics
    /// are rendered once by [`crate::engine::sleep_runtime`], so the technique
    /// and the `Sleep` API proxy share one implementation. `plan::validate`
    /// rejects non-`ekko` variants and region lists other than `[payload]`
    /// before this runs.
    pub fn render_fragment(&self, _strings: &StringsConfig) -> String {
        DEF.stub_fragment
            .replace("$SLEEP_MS$", &self.sleep_ms.to_string())
    }
}

#[cfg(test)]
mod tests;
