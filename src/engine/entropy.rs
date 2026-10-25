//! One seeded source for every per-build random value.
//!
//! Before this module each phase drew its own randomness (`thread_rng` and
//! `rand::random`): the polymorphism seed, the strings key, the payload key and
//! nonce, the generated icon seed, the identity values and the scrub filler.
//! Those values decide the artifact's bytes, but only some of them were
//! recorded, so a build could not be reproduced.
//!
//! A build now has a single [`BuildEntropy`] seed. Every per-build value is a
//! **domain-separated derivation** of that seed, so recording one number is
//! enough to recompute all of them:
//!
//! ```text
//! value = splitmix64(seed ^ domain_constant)
//! ```
//!
//! The mixer is the one `engine::steps` already uses for the source-level
//! entropy. It is duplicated here on purpose: `steps` is about generated code,
//! this module is about build inputs, and changing one must not silently change
//! the other. The derivation is part of `manifest_schema`: the domain constants
//! and the mixer are fixed, and changing either is a schema bump.
//!
//! The default build is unchanged semantically: [`BuildEntropy::from_plan`]
//! falls back to a fresh random seed when the plan records none, so two normal
//! builds still differ. What changed is that the seed is now recorded.

use crate::plan::schema::Plan;

use super::mixer::splitmix64;

/// Domain separators for the per-build values.
///
/// The numeric values are part of the reproducibility contract: changing one
/// changes every artifact built from a given seed, so it is a `manifest_schema`
/// bump. The spellings are only documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// The polymorphism codegen profile and source-level immediates.
    Polymorphism,
    /// The generated icon seed.
    Icon,
    /// The randomized `VERSIONINFO` values.
    Identity,
    /// The filler used to scrub build-path literals.
    Scrub,
    /// The XOR key applied to stub string literals.
    StringsKey,
    /// The payload encryption key.
    PayloadKey,
    /// The payload encryption nonce.
    PayloadNonce,
}

impl Domain {
    /// The fixed 64-bit separator mixed into the master seed.
    fn constant(self) -> u64 {
        match self {
            // "POLYMORP"
            Domain::Polymorphism => 0x504F_4C59_4D4F_5250,
            // "ICON"
            Domain::Icon => 0x4943_4F4E_0000_0001,
            // "IDENTITY"
            Domain::Identity => 0x4944_454E_5449_5459,
            // "SCRUB"
            Domain::Scrub => 0x5343_5255_4200_0001,
            // "STRINGKY"
            Domain::StringsKey => 0x5354_5249_4E47_4B59,
            // "PAYLOADK"
            Domain::PayloadKey => 0x5041_594C_4F41_444B,
            // "PAYLOADN"
            Domain::PayloadNonce => 0x5041_594C_4F41_444E,
        }
    }
}

/// The single entropy input of a build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildEntropy {
    /// The recorded master seed. Everything else is derived from it.
    pub seed: u64,
}

impl BuildEntropy {
    /// A fresh random seed: the default for a build that records none.
    pub fn random() -> Self {
        Self {
            seed: rand::random::<u64>(),
        }
    }

    /// Entropy from a known seed (a replay, a test or `--seed`).
    pub fn from_seed(seed: u64) -> Self {
        Self { seed }
    }

    /// Resolves the master seed with the documented precedence:
    /// CLI `--seed` > `reproduce.seed` (shorthand) > `reproduce.entropy.seed` >
    /// a literal `build.polymorphism.seed` > random.
    ///
    /// The literal polymorphism seed is accepted last for backwards
    /// compatibility: before this module a literal seed pinned the codegen
    /// profile. [`crate::engine::polymorphism::PolymorphismConfig`] still uses
    /// that literal directly, so its historical output is preserved.
    pub fn from_plan(plan: &Plan, cli_seed: Option<u64>) -> Self {
        if let Some(seed) = cli_seed {
            return Self::from_seed(seed);
        }
        if let Some(reproduce) = &plan.reproduce {
            if let Some(seed) = reproduce.seed.as_deref().and_then(parse_seed) {
                return Self::from_seed(seed);
            }
            if let Some(seed) = parse_seed(&reproduce.entropy.seed) {
                return Self::from_seed(seed);
            }
            if let Some(seed) = reproduce
                .entropy
                .polymorphism
                .as_ref()
                .map(|record| record.seed)
            {
                return Self::from_seed(seed);
            }
        }
        if let Some(seed) = plan
            .build
            .polymorphism
            .as_ref()
            .and_then(|block| match block.seed {
                Some(crate::engine::polymorphism::SeedSource::Literal(value)) => Some(value),
                _ => None,
            })
        {
            return Self::from_seed(seed);
        }
        Self::random()
    }

    /// The first derived `u64` for `domain`.
    pub fn derive(&self, domain: Domain) -> u64 {
        self.stream(domain, "").next_u64()
    }

    /// A byte array derived for `domain`.
    pub fn derive_bytes<const N: usize>(&self, domain: Domain) -> [u8; N] {
        self.stream(domain, "").bytes()
    }

    /// A byte array derived for `domain` and a per-item `tag`.
    ///
    /// Used to give every payload its own key and nonce from the same domain:
    /// the tag (the payload name) is mixed into the stream state, so two
    /// payloads never share a key.
    pub fn derive_tagged_bytes<const N: usize>(&self, domain: Domain, tag: &str) -> [u8; N] {
        self.stream(domain, tag).bytes()
    }

    /// A deterministic byte stream for `domain` and `tag`.
    ///
    /// The scrub filler consumes one stream per byte so a long scrubbed region
    /// is varied text rather than a repeated byte.
    pub fn stream(&self, domain: Domain, tag: &str) -> EntropyStream {
        EntropyStream {
            state: self.seed ^ domain.constant() ^ tag_mix(tag),
        }
    }
}

/// A splitmix64 stream derived from one `(seed, domain, tag)` triple.
#[derive(Debug, Clone)]
pub struct EntropyStream {
    state: u64,
}

impl EntropyStream {
    /// The next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        splitmix64(&mut self.state)
    }

    /// The next `N` bytes, little-endian per 64-bit word.
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let mut written = 0;
        while written < N {
            let word = self.next_u64().to_le_bytes();
            let take = (N - written).min(8);
            out[written..written + take].copy_from_slice(&word[..take]);
            written += take;
        }
        out
    }

    /// The next byte, for a per-byte filler.
    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
}

/// Parses a recorded seed: decimal or `0x` hex; `random` (or empty) means none.
pub fn parse_seed(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("random") {
        return None;
    }
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => value.parse().ok(),
    }
}

/// FNV-1a over `tag`, or `0` for the untagged stream.
///
/// The empty tag must mix to zero so [`BuildEntropy::derive`] is exactly
/// `splitmix64(seed ^ domain)`, the formula the reproducibility contract pins.
fn tag_mix(tag: &str) -> u64 {
    if tag.is_empty() {
        return 0;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in tag.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = r#"
schema: 6
name: entropy-test
build:
  output:
    path: ./dist/out.exe
"#;

    fn plan_with_reproduce(yaml: &str) -> Plan {
        serde_yml::from_str(yaml).expect("valid plan")
    }

    #[test]
    fn the_mixer_is_pinned_per_domain() {
        // Computed independently from the documented formula. A failure here
        // means artifacts built from a recorded seed changed: bump the schema.
        let entropy = BuildEntropy::from_seed(0);
        assert_eq!(entropy.derive(Domain::Polymorphism), 0x6f1a_4a6d_706c_a5ab);
        assert_eq!(entropy.derive(Domain::Icon), 0x58de_23b1_68ce_aeaf);
        assert_eq!(entropy.derive(Domain::Identity), 0x821e_b16b_81d8_928a);
        assert_eq!(entropy.derive(Domain::Scrub), 0xc2b7_b0b4_0c2f_fbe8);
        assert_eq!(entropy.derive(Domain::StringsKey), 0x63a2_c806_4c04_f914);
        assert_eq!(entropy.derive(Domain::PayloadKey), 0x35aa_4247_6ada_b098);
        assert_eq!(entropy.derive(Domain::PayloadNonce), 0x31c4_3567_ffd6_d3cd);

        let entropy = BuildEntropy::from_seed(0x0123_4567_89ab_cdef);
        assert_eq!(entropy.derive(Domain::Polymorphism), 0xe2f9_3704_f0c5_726a);
        assert_eq!(entropy.derive(Domain::PayloadKey), 0x8495_90a8_d760_b942);
    }

    #[test]
    fn domains_do_not_collide() {
        let entropy = BuildEntropy::from_seed(0xdead_beef);
        let values = [
            entropy.derive(Domain::Polymorphism),
            entropy.derive(Domain::Icon),
            entropy.derive(Domain::Identity),
            entropy.derive(Domain::Scrub),
            entropy.derive(Domain::StringsKey),
            entropy.derive(Domain::PayloadKey),
            entropy.derive(Domain::PayloadNonce),
        ];
        for (i, a) in values.iter().enumerate() {
            for b in &values[i + 1..] {
                assert_ne!(a, b, "two domains derived the same value");
            }
        }
    }

    #[test]
    fn bytes_are_stable_and_extend_the_scalar() {
        let entropy = BuildEntropy::from_seed(7);
        let first: [u8; 32] = entropy.derive_bytes(Domain::StringsKey);
        let second: [u8; 32] = entropy.derive_bytes(Domain::StringsKey);
        assert_eq!(first, second);

        let scalar: [u8; 8] = entropy.derive_bytes(Domain::PayloadNonce);
        assert_eq!(
            u64::from_le_bytes(scalar),
            entropy.derive(Domain::PayloadNonce),
            "derive_bytes(8) must be the little-endian form of derive()"
        );
    }

    #[test]
    fn tags_separate_payloads() {
        let entropy = BuildEntropy::from_seed(7);
        let a: [u8; 32] = entropy.derive_tagged_bytes(Domain::PayloadKey, "implant");
        let b: [u8; 32] = entropy.derive_tagged_bytes(Domain::PayloadKey, "dropper");
        assert_ne!(a, b);
    }

    #[test]
    fn the_stream_is_deterministic() {
        let entropy = BuildEntropy::from_seed(42);
        let mut a = entropy.stream(Domain::Scrub, "");
        let mut b = entropy.stream(Domain::Scrub, "");
        let left: Vec<u8> = (0..64).map(|_| a.next_u8()).collect();
        let right: Vec<u8> = (0..64).map(|_| b.next_u8()).collect();
        assert_eq!(left, right);
    }

    #[test]
    fn cli_seed_wins_over_the_reproduce_block() {
        let yaml = r#"
schema: 6
name: precedence
build:
  output: { path: ./dist/out.exe }
reproduce:
  seed: 5
  entropy: { seed: "0x6" }
"#;
        let plan = plan_with_reproduce(yaml);
        assert_eq!(entropy_seed(&plan, Some(9)), 9);
        assert_eq!(entropy_seed(&plan, None), 5);
    }

    #[test]
    fn the_entropy_seed_is_used_when_the_shorthand_is_absent() {
        let yaml = r#"
schema: 6
name: precedence
build:
  output: { path: ./dist/out.exe }
reproduce:
  entropy: { seed: "0x2a" }
"#;
        let plan = plan_with_reproduce(yaml);
        assert_eq!(entropy_seed(&plan, None), 42);
    }

    #[test]
    fn a_literal_polymorphism_seed_is_the_last_plan_fallback() {
        let plan = plan_with_reproduce(
            r#"
schema: 6
name: literal
build:
  polymorphism: { seed: "literal:0x10" }
  output: { path: ./dist/out.exe }
"#,
        );
        assert_eq!(entropy_seed(&plan, None), 0x10);
    }

    #[test]
    fn a_plain_plan_gets_a_random_seed() {
        let plan = plan_with_reproduce(
            r#"
schema: 6
name: plain
build:
  output: { path: ./dist/out.exe }
"#,
        );
        let first = BuildEntropy::from_plan(&plan, None).seed;
        let second = BuildEntropy::from_plan(&plan, None).seed;
        assert_ne!(first, second);
    }

    #[test]
    fn seed_parsing_accepts_decimal_and_hex() {
        assert_eq!(parse_seed("0x10"), Some(16));
        assert_eq!(parse_seed("16"), Some(16));
        assert_eq!(parse_seed("random"), None);
        assert_eq!(parse_seed(""), None);
    }

    fn entropy_seed(plan: &Plan, cli_seed: Option<u64>) -> u64 {
        BuildEntropy::from_plan(plan, cli_seed).seed
    }

    #[test]
    fn the_fixture_is_a_valid_plan() {
        // `SEED` documents the baseline; parsing it here keeps it honest.
        let plan: Plan = serde_yml::from_str(SEED).expect("valid plan");
        assert_eq!(plan.schema, 6);
    }
}
