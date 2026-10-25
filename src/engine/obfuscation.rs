//! String obfuscation for stub literals.
//!
//! The packer embeds a handful of sensitive string literals into the generated
//! stub (the per-build marker, a technique's target path, ...). Left as-is they
//! would show up in `strings <binary>` and trip static scanners, so this module
//! turns each one into a fragment of Rust code that rebuilds the string at
//! runtime instead of storing it in cleartext.
//!
//! Two strategies, selected per build in `build.stub.strings`:
//!
//! - [`StringStrategy::Xor`]: the plaintext is XORed with a 32-byte key at pack
//!   time and decoded by a small runtime loop. Fast, good evasion ratio, and
//!   each string gets a fresh key (keys are never shared between strings).
//! - [`StringStrategy::Stack`]: the plaintext never lands in `.rdata`; it is
//!   rebuilt byte by byte on the stack at the moment of use. It needs no
//!   decoder and no key, but it emits one store per byte (more code, slightly
//!   slower). Ideal for short strings that must appear zero times in `.rdata`.

use serde::{Deserialize, Serialize};

use crate::engine::entropy::{BuildEntropy, Domain};
use crate::error::{PackerError, Result};

/// Length of the XOR key in bytes (256 bits).
pub const XOR_KEY_LEN: usize = 32;

/// Strategy used to obfuscate a stub string literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringStrategy {
    /// XOR with a repeating 32-byte key, decoded at runtime.
    Xor,
    /// Byte-by-byte reconstruction on the stack; no key, no `.rdata` copy.
    Stack,
}

impl StringStrategy {
    /// Lowercase label used in the build summary.
    pub fn label(self) -> &'static str {
        match self {
            StringStrategy::Xor => "xor",
            StringStrategy::Stack => "stack",
        }
    }
}

/// Raw `build.stub.strings` YAML block, before semantic validation.
///
/// `strategy` and `key` are kept as plain strings here so that
/// [`StringsConfig::from_yaml`] can report clear errors for invalid values
/// instead of a generic deserialization message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlStringsPlan {
    /// Obfuscation strategy (`xor` or `stack`).
    #[serde(default = "default_strategy")]
    pub strategy: String,

    /// XOR key spec: `random` or `literal:<hex>` (32 bytes).
    #[serde(default = "default_key")]
    pub key: String,
}

fn default_strategy() -> String {
    "xor".to_string()
}

fn default_key() -> String {
    "random".to_string()
}

/// Resolved string-obfuscation configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StringsConfig {
    /// Which strategy is applied to every stub literal.
    pub strategy: StringStrategy,
    /// XOR key. `Some` for [`StringStrategy::Xor`], `None` for `Stack`.
    pub key: Option<[u8; XOR_KEY_LEN]>,
}

impl std::fmt::Debug for StringsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StringsConfig")
            .field("strategy", &self.strategy)
            .field("key", &self.key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl StringsConfig {
    /// Resolves the obfuscation plan with a fresh random entropy seed.
    ///
    /// Kept as the convenient entry point for callers that only need a
    /// validated configuration (tests, validation). A build uses
    /// [`Self::from_yaml_with_entropy`] so the key can be reproduced.
    pub fn from_yaml(yaml: Option<&YamlStringsPlan>) -> Result<Self> {
        Self::from_yaml_with_entropy(yaml, &BuildEntropy::random())
    }

    /// Resolves the obfuscation plan from the (optional) YAML block.
    ///
    /// `None` means "defaults" (`xor` + a key derived from the build entropy).
    /// An invalid strategy or an ill-formed `literal:` key is a validation
    /// error. A literal key still wins, so a pinned plan keeps its bytes.
    pub fn from_yaml_with_entropy(
        yaml: Option<&YamlStringsPlan>,
        entropy: &BuildEntropy,
    ) -> Result<Self> {
        let Some(yaml) = yaml else {
            return Ok(Self::xor(
                entropy.derive_bytes::<XOR_KEY_LEN>(Domain::StringsKey),
            ));
        };

        match yaml.strategy.as_str() {
            "xor" => Ok(Self::xor(resolve_key(&yaml.key, entropy)?)),
            "stack" => {
                if yaml.key != "random" {
                    return Err(PackerError::Validation(format!(
                        "invalid strings.key '{}' with strategy 'stack': the stack strategy has no key, use 'random' or omit it",
                        yaml.key
                    )));
                }
                Ok(Self {
                    strategy: StringStrategy::Stack,
                    key: None,
                })
            }
            other => Err(PackerError::Validation(format!(
                "invalid strings.strategy '{other}': expected 'xor' or 'stack'"
            ))),
        }
    }

    fn xor(key: [u8; XOR_KEY_LEN]) -> Self {
        Self {
            strategy: StringStrategy::Xor,
            key: Some(key),
        }
    }

    /// Obfuscates `plaintext` according to this configuration.
    pub fn obfuscate(&self, plaintext: &str) -> ObfuscatedString {
        match self.strategy {
            StringStrategy::Xor => {
                // `from_yaml` always stores a key for xor; the fallback defends
                // against a hand-constructed plan missing its key. It derives
                // from a fixed seed rather than drawing a sixth RNG, so the
                // build's entropy stays the only source of per-build values.
                let key = match self.key {
                    Some(key) => key,
                    None => {
                        BuildEntropy::from_seed(0).derive_bytes::<XOR_KEY_LEN>(Domain::StringsKey)
                    }
                };
                let bytes = plaintext
                    .bytes()
                    .enumerate()
                    .map(|(i, b)| b ^ key[i % XOR_KEY_LEN])
                    .collect();
                ObfuscatedString::Xor { bytes, key }
            }
            StringStrategy::Stack => ObfuscatedString::Stack {
                bytes: plaintext.as_bytes().to_vec(),
            },
        }
    }
}

/// An obfuscated stub string, ready to render as runtime reconstruction code.
#[derive(Clone, PartialEq, Eq)]
pub enum ObfuscatedString {
    /// XOR-encoded bytes plus the key used to encode them.
    Xor {
        bytes: Vec<u8>,
        key: [u8; XOR_KEY_LEN],
    },
    /// Plaintext bytes, emitted as individual stack stores.
    Stack { bytes: Vec<u8> },
}

impl std::fmt::Debug for ObfuscatedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObfuscatedString::Xor { bytes, .. } => f
                .debug_struct("Xor")
                .field("bytes", bytes)
                .field("key", &"[REDACTED]")
                .finish(),
            ObfuscatedString::Stack { bytes } => {
                f.debug_struct("Stack").field("bytes", bytes).finish()
            }
        }
    }
}

impl ObfuscatedString {
    /// Returns the Rust code fragment that reconstructs the string at runtime.
    ///
    /// The fragment is an *expression* (it evaluates to a `String`), so the
    /// stub binds it as `let name = <fragment>;`. `var_name` names the
    /// temporary stack buffer for the stack strategy; the xor strategy ignores
    /// it.
    pub fn render_stub_expr(&self, var_name: &str) -> String {
        match self {
            ObfuscatedString::Xor { bytes, key } => format!(
                "String::from_utf8_lossy(&crate::dec_xor(&{}, &{})).into_owned()",
                byte_array_literal(bytes),
                byte_array_literal(key),
            ),
            ObfuscatedString::Stack { bytes } => render_stack_expr(var_name, bytes),
        }
    }
}

/// Parses a key spec (`random` or `literal:<hex>`) into 32 bytes.
fn resolve_key(spec: &str, entropy: &BuildEntropy) -> Result<[u8; XOR_KEY_LEN]> {
    match spec.strip_prefix("literal:") {
        Some(hex) => {
            let bytes = hex::decode(hex).map_err(|e| {
                PackerError::Validation(format!(
                    "invalid strings.key 'literal:{hex}': not valid hexadecimal ({e})"
                ))
            })?;
            if bytes.len() != XOR_KEY_LEN {
                return Err(PackerError::Validation(format!(
                    "invalid strings.key 'literal:{hex}': expected exactly {XOR_KEY_LEN} bytes ({} hex chars), got {}",
                    XOR_KEY_LEN * 2,
                    bytes.len()
                )));
            }
            let mut key = [0u8; XOR_KEY_LEN];
            key.copy_from_slice(&bytes);
            if key.iter().all(|&byte| byte == 0) {
                return Err(PackerError::Validation(format!(
                    "invalid strings.key 'literal:{hex}': the key must not be all zero bytes, which would leave every literal in cleartext"
                )));
            }
            Ok(key)
        }
        None if spec == "random" => Ok(entropy.derive_bytes::<XOR_KEY_LEN>(Domain::StringsKey)),
        None => Err(PackerError::Validation(format!(
            "invalid strings.key '{spec}': expected 'random' or 'literal:<hex>'"
        ))),
    }
}

/// Renders `bytes` as a Rust byte-array literal, e.g. `[0x53, 0x54, 0x55]`.
///
/// Used by the XOR string-obfuscation expression ([`ObfuscatedString`]) and by the
/// syscall layer's hash/SSN constants.
pub(crate) fn byte_array_literal(bytes: &[u8]) -> String {
    let mut out = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("0x{b:02x}"));
    }
    out.push(']');
    out
}

/// Renders the stack strategy: a block that fills a local `[u8; N]` with
/// individual byte stores and converts it to a `String`.
///
/// Each byte is wrapped in [`std::hint::black_box`] so the optimizer cannot
/// constant-fold the stores back into a single contiguous literal in `.rdata`
/// (which would defeat the strategy).
fn render_stack_expr(var_name: &str, bytes: &[u8]) -> String {
    let buf = format!("{var_name}_buf");
    let mut out = format!("{{\n    let mut {buf} = [0u8; {}];\n", bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        out.push_str(&format!(
            "    {buf}[{i}] = std::hint::black_box(0x{b:02x});\n"
        ));
    }
    out.push_str(&format!(
        "    String::from_utf8_lossy(&{buf}).into_owned()\n}}"
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_round_trips_with_known_key() {
        let key = [0x11u8; XOR_KEY_LEN];
        let plan = StringsConfig {
            strategy: StringStrategy::Xor,
            key: Some(key),
        };
        let plaintext = "STUB_MARKER_deadbeef";

        let obf = plan.obfuscate(plaintext);
        let ObfuscatedString::Xor { bytes, key } = obf else {
            panic!("expected an xor obfuscation");
        };

        let decoded: String = bytes
            .iter()
            .enumerate()
            .map(|(i, b)| (*b ^ key[i % XOR_KEY_LEN]) as char)
            .collect();
        assert_eq!(decoded, plaintext);
        assert_ne!(bytes, plaintext.as_bytes().to_vec());
    }

    #[test]
    fn xor_render_emits_dec_xor_with_byte_arrays() {
        let obf = ObfuscatedString::Xor {
            bytes: vec![0x01, 0x02, 0x03],
            key: [0xaau8; XOR_KEY_LEN],
        };
        let code = obf.render_stub_expr("stub_marker");

        let prefix = "String::from_utf8_lossy(&crate::dec_xor(&[0x01, 0x02, 0x03], &[0xaa, 0xaa";
        assert!(code.starts_with(prefix), "unexpected code: {code}");
        assert!(code.ends_with(").into_owned()"), "unexpected code: {code}");
    }

    #[test]
    fn stack_render_produces_expected_code() {
        let obf = ObfuscatedString::Stack {
            bytes: b"ABC".to_vec(),
        };
        let code = obf.render_stub_expr("stub_marker");

        let expected = concat!(
            "{\n",
            "    let mut stub_marker_buf = [0u8; 3];\n",
            "    stub_marker_buf[0] = std::hint::black_box(0x41);\n",
            "    stub_marker_buf[1] = std::hint::black_box(0x42);\n",
            "    stub_marker_buf[2] = std::hint::black_box(0x43);\n",
            "    String::from_utf8_lossy(&stub_marker_buf).into_owned()\n",
            "}",
        );
        assert_eq!(code, expected);
    }

    /// Test-only: undo the XOR and decode as UTF-8, the same way the generated
    /// stub does.
    fn decode_xor(bytes: &[u8], key: &[u8; XOR_KEY_LEN]) -> String {
        let decoded: Vec<u8> = bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % XOR_KEY_LEN])
            .collect();
        String::from_utf8(decoded).expect("the round trip must stay valid UTF-8")
    }

    #[test]
    fn non_ascii_plaintext_round_trips_as_utf8() {
        let config = StringsConfig {
            strategy: StringStrategy::Xor,
            key: Some([0x11u8; XOR_KEY_LEN]),
        };

        for plaintext in ["café", "Grüße"] {
            let ObfuscatedString::Xor { bytes, key } = config.obfuscate(plaintext) else {
                panic!("expected an xor obfuscation");
            };
            let decoded = decode_xor(&bytes, &key);
            assert_eq!(decoded, plaintext);
            assert_eq!(decoded.as_bytes(), plaintext.as_bytes());
        }
    }

    #[test]
    fn rendered_expressions_decode_as_utf8() {
        let xor = StringsConfig {
            strategy: StringStrategy::Xor,
            key: Some([0x11u8; XOR_KEY_LEN]),
        };
        let xor_code = xor.obfuscate("café").render_stub_expr("stub_marker");
        assert!(
            xor_code.contains("String::from_utf8_lossy(&crate::dec_xor("),
            "the xor expression must decode as UTF-8: {xor_code}"
        );
        assert!(
            xor_code.ends_with(").into_owned()"),
            "unexpected code: {xor_code}"
        );

        let stack = StringsConfig {
            strategy: StringStrategy::Stack,
            key: None,
        };
        let stack_code = stack.obfuscate("Grüße").render_stub_expr("stub_marker");
        assert!(
            stack_code.contains("String::from_utf8_lossy(&stub_marker_buf).into_owned()"),
            "the stack expression must decode as UTF-8: {stack_code}"
        );
    }

    #[test]
    fn different_entropy_seeds_produce_distinct_keys() {
        let a = StringsConfig::from_yaml_with_entropy(None, &BuildEntropy::from_seed(1))
            .expect("seed 1")
            .key;
        let b = StringsConfig::from_yaml_with_entropy(None, &BuildEntropy::from_seed(2))
            .expect("seed 2")
            .key;
        assert_ne!(a, b, "two build seeds should derive different keys");
    }

    #[test]
    fn deserializes_yaml_strings_block() {
        let yaml: YamlStringsPlan =
            serde_yml::from_str("strategy: stack\nkey: random\n").expect("should parse");
        assert_eq!(yaml.strategy, "stack");
        assert_eq!(yaml.key, "random");
    }

    #[test]
    fn from_yaml_defaults_to_xor_random() {
        let plan = StringsConfig::from_yaml(None).expect("defaults should be valid");
        assert_eq!(plan.strategy, StringStrategy::Xor);
        assert!(plan.key.is_some());
    }

    #[test]
    fn from_yaml_parses_xor_with_random_key() {
        let yaml = YamlStringsPlan {
            strategy: "xor".into(),
            key: "random".into(),
        };
        let plan = StringsConfig::from_yaml(Some(&yaml)).expect("xor+random should be valid");
        assert_eq!(plan.strategy, StringStrategy::Xor);
        assert!(plan.key.is_some());
    }

    #[test]
    fn from_yaml_parses_stack_without_key() {
        let yaml = YamlStringsPlan {
            strategy: "stack".into(),
            key: "random".into(),
        };
        let plan = StringsConfig::from_yaml(Some(&yaml)).expect("stack should be valid");
        assert_eq!(plan.strategy, StringStrategy::Stack);
        assert_eq!(plan.key, None);
    }

    #[test]
    fn from_yaml_rejects_invalid_strategy() {
        let yaml = YamlStringsPlan {
            strategy: "rot13".into(),
            key: "random".into(),
        };
        let err = StringsConfig::from_yaml(Some(&yaml)).expect_err("rot13 should fail");
        assert!(err.to_string().contains("rot13"), "unclear error: {err}");
    }

    #[test]
    fn from_yaml_parses_literal_key() {
        let yaml = YamlStringsPlan {
            strategy: "xor".into(),
            key: format!("literal:{}", "11".repeat(XOR_KEY_LEN)),
        };
        let plan = StringsConfig::from_yaml(Some(&yaml)).expect("literal key should be valid");
        assert_eq!(plan.key, Some([0x11u8; XOR_KEY_LEN]));
    }

    #[test]
    fn from_yaml_rejects_all_zero_literal_key() {
        let yaml = YamlStringsPlan {
            strategy: "xor".into(),
            key: format!("literal:{}", "00".repeat(XOR_KEY_LEN)),
        };
        let err = StringsConfig::from_yaml(Some(&yaml)).expect_err("an all-zero key should fail");
        assert!(err.to_string().contains("all zero"), "unclear error: {err}");
    }

    #[test]
    fn from_yaml_rejects_stack_with_explicit_key() {
        let yaml = YamlStringsPlan {
            strategy: "stack".into(),
            key: format!("literal:{}", "11".repeat(XOR_KEY_LEN)),
        };
        let err = StringsConfig::from_yaml(Some(&yaml)).expect_err("stack takes no key");
        assert!(err.to_string().contains("stack"), "unclear error: {err}");
    }

    #[test]
    fn from_yaml_rejects_non_hex_literal_key() {
        let yaml = YamlStringsPlan {
            strategy: "xor".into(),
            key: "literal:zzzz".into(),
        };
        let err = StringsConfig::from_yaml(Some(&yaml)).expect_err("non-hex key should fail");
        assert!(err.to_string().contains("literal"), "unclear error: {err}");
    }

    #[test]
    fn from_yaml_rejects_wrong_length_literal_key() {
        let yaml = YamlStringsPlan {
            strategy: "xor".into(),
            key: "literal:00".into(),
        };
        let err = StringsConfig::from_yaml(Some(&yaml)).expect_err("short key should fail");
        assert!(err.to_string().contains("32"), "unclear error: {err}");
    }
}
