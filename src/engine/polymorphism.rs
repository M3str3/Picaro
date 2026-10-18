//! Build-time polymorphism: per-build diversity so two builds of one plan do
//! not share a byte-identical `.text`.
//!
//! **Phase 1 (this module): a seeded codegen profile.** The build seed picks
//! `-C codegen-units`, `-C opt-level`, `-C lto`, a `-C llvm-args=--inline-threshold`
//! value and a `-Z randomize-layout` + `-Z layout-seed` pair from small pools, so
//! `rustc` emits **different instructions** on every build even though the
//! generated source is identical. Source-level diversity and cosmetic PE mutation
//! are later phases (see `docs/design/polymorphism.md`).
//!
//! The measures here are behavior-preserving by construction (they only change
//! *how* the compiler lays out equivalent code), so they are **on by default**
//! (`mode: full`). A debug build forces `mode: none`: a debug artifact exists to
//! stay reproducible and debuggable, and codegen variation defeats that.
//!
//! Design, phases and decision log: `docs/design/polymorphism.md`.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use super::{BuildError, Result};

/// `build.polymorphism`: the per-build diversity block.
///
/// Applies to the whole build (the stub compile and, in later phases, the final
/// artifact), so it is a top-level loader block, not a `runtime:` technique.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlPolymorphismPlan {
    /// Master switch. `none` opts out (the build is byte-reproducible);
    /// `codegen`, `source` and `full` are cumulative. Defaults to `full`.
    #[serde(default)]
    pub mode: PolymorphismMode,

    /// Seed for every per-build choice: `random` (default) or `literal:<u64>`.
    /// Recorded in the build manifest so an artifact can be reproduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<SeedSource>,

    /// Pools the codegen profile is drawn from (phase 1).
    #[serde(default)]
    pub codegen: CodegenPlan,
}

impl YamlPolymorphismPlan {
    /// Checks the block before a build. Returns a human-readable message.
    ///
    /// The mode and seed are validated by `serde` on parse; this only catches
    /// pool values that would produce an invalid `rustc` invocation.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.codegen.codegen_units.contains(&0) {
            return Err(
                "codegen.codegen_units must contain values >= 1 (0 disables codegen units)"
                    .to_string(),
            );
        }
        if self.codegen.opt_level.is_empty() {
            return Err("codegen.opt_level must not be empty".to_string());
        }
        if self.codegen.lto.is_empty() {
            return Err("codegen.lto must not be empty".to_string());
        }
        if self.codegen.inline_threshold.iter().any(|t| *t < 0) {
            return Err("codegen.inline_threshold must contain values >= 0".to_string());
        }
        if self.codegen.mir_opt_level.iter().any(|l| *l > 4) {
            return Err("codegen.mir_opt_level must contain values in 0..=4".to_string());
        }
        Ok(())
    }
}

/// Cumulative polymorphism level (`build.polymorphism.mode`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolymorphismMode {
    /// Off: the build reproduces today's bytes exactly.
    None,
    /// Seeded codegen profile only.
    Codegen,
    /// Codegen profile plus source-level diversity (later phase).
    Source,
    /// Everything: codegen, source and cosmetic PE mutation (later phases). The
    /// default.
    #[default]
    Full,
}

impl PolymorphismMode {
    /// Lowercase label used in the build output and the manifest.
    pub fn label(self) -> &'static str {
        match self {
            PolymorphismMode::None => "none",
            PolymorphismMode::Codegen => "codegen",
            PolymorphismMode::Source => "source",
            PolymorphismMode::Full => "full",
        }
    }

    /// Whether the seeded codegen profile applies (every level but `none`).
    fn uses_codegen(self) -> bool {
        !matches!(self, PolymorphismMode::None)
    }
}

/// Seed source (`build.polymorphism.seed`): `random` or `literal:<u64>`.
///
/// A literal seed (decimal or `0x` hex) makes a build reproducible; a random
/// seed is what gives two builds different output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum SeedSource {
    /// A fresh random seed per build (the default).
    Random,
    /// A fixed seed.
    Literal(u64),
}

impl From<SeedSource> for String {
    fn from(source: SeedSource) -> Self {
        match source {
            SeedSource::Random => "random".to_string(),
            SeedSource::Literal(value) => format!("literal:{value:#x}"),
        }
    }
}

impl TryFrom<String> for SeedSource {
    type Error = String;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        value.parse()
    }
}

impl std::str::FromStr for SeedSource {
    type Err = String;

    /// Parses `random` or `literal:<u64>` (decimal or `0x`-prefixed hex).
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("random") {
            return Ok(SeedSource::Random);
        }
        if let Some(literal) = value.strip_prefix("literal:") {
            let literal = literal.trim();
            let parsed = match literal
                .strip_prefix("0x")
                .or_else(|| literal.strip_prefix("0X"))
            {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => literal.parse::<u64>(),
            };
            return parsed.map(SeedSource::Literal).map_err(|_| {
                format!("invalid seed literal '{literal}': expected a u64 (decimal or 0x hex)")
            });
        }
        Err(format!(
            "unknown seed '{value}'; expected 'random' or 'literal:<u64>'"
        ))
    }
}

/// A `-C opt-level` value for the loader stub.
///
/// `0` is selectable on purpose. It is absent from the default pool (the stub is
/// a small shim where size wins), but pinning it is the escape hatch for a build
/// where the optimizer exposes a miscompile: `hardening_flags` passes
/// `-C debug-assertions=off` explicitly, so `-C opt-level=0` does *not* switch
/// `cfg(debug_assertions)` on (the reason a bare `opt-level=0` is usually
/// avoided). The artifact stays a normal delivery build (stripped, no checks,
/// polymorphism still applies) — only its code is unoptimized.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptLevel {
    /// `-C opt-level=0` (no optimization).
    #[serde(rename = "0")]
    Zero,
    /// `-C opt-level=1`.
    #[serde(rename = "1")]
    One,
    /// `-C opt-level=2`.
    #[serde(rename = "2")]
    Two,
    /// `-C opt-level=3`.
    #[serde(rename = "3")]
    Three,
    /// `-C opt-level=s` (size).
    #[serde(rename = "s")]
    S,
    /// `-C opt-level=z` (size, aggressive). The loader default.
    #[serde(rename = "z")]
    #[default]
    Z,
}

impl OptLevel {
    /// The value for `-C opt-level=`.
    pub fn flag(self) -> &'static str {
        match self {
            OptLevel::Zero => "0",
            OptLevel::One => "1",
            OptLevel::Two => "2",
            OptLevel::Three => "3",
            OptLevel::S => "s",
            OptLevel::Z => "z",
        }
    }
}

/// A `-C lto` value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LtoMode {
    /// No LTO flag (the toolchain default). The loader default.
    #[default]
    Off,
    /// `-C lto=thin`.
    Thin,
    /// `-C lto=fat`.
    Fat,
}

impl LtoMode {
    /// The value for `-C lto=`, or `None` to emit no flag at all.
    pub fn flag(self) -> Option<&'static str> {
        match self {
            LtoMode::Off => None,
            LtoMode::Thin => Some("thin"),
            LtoMode::Fat => Some("fat"),
        }
    }
}

/// `build.polymorphism.codegen`: the pools the codegen profile is drawn from.
///
/// Every pool is behavior-preserving: `codegen-units` splits codegen without
/// changing semantics, `opt-level` trades speed for size, and `lto` changes
/// inlining. Empty pools fall back to the toolchain default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodegenPlan {
    /// `-C codegen-units` pool (default `[1, 2, 4, 8]`).
    #[serde(default = "default_codegen_units")]
    pub codegen_units: Vec<u32>,

    /// `-C opt-level` pool (default `[z, s, 2]`).
    #[serde(default = "default_opt_levels")]
    pub opt_level: Vec<OptLevel>,

    /// `-C lto` pool (default `[off]`: LTO is opt-in because it requires the
    /// dependency rlibs to carry LLVM bitcode).
    #[serde(default = "default_lto")]
    pub lto: Vec<LtoMode>,

    /// `-C llvm-args=--inline-threshold=N` pool (default `[25, 100, 300]`). This
    /// changes how aggressively LLVM inlines, which changes the emitted code.
    #[serde(default = "default_inline_thresholds")]
    pub inline_threshold: Vec<i32>,

    /// `-Z mir-opt-level` pool (default `[1, 2, 3]`). Changes the MIR optimization
    /// level, so the code that reaches LLVM differs. Needs `RUSTC_BOOTSTRAP=1`.
    #[serde(default = "default_mir_opt_levels")]
    pub mir_opt_level: Vec<u8>,

    /// Apply `-Z randomize-layout` (reorders the fields of `repr(Rust)` types) with
    /// a per-build `-Z layout-seed`. Needs `RUSTC_BOOTSTRAP=1`. **Off by default:**
    /// the canonical stub has almost no layout-sensitive `repr(Rust)` types (most
    /// data is `std`/`windows` types, which are not randomized), so it is a no-op
    /// for it and only earns its cost on a plan that keeps such types in memory.
    #[serde(default = "default_randomize_layout")]
    pub randomize_layout: bool,
}

impl Default for CodegenPlan {
    fn default() -> Self {
        Self {
            codegen_units: default_codegen_units(),
            opt_level: default_opt_levels(),
            lto: default_lto(),
            inline_threshold: default_inline_thresholds(),
            mir_opt_level: default_mir_opt_levels(),
            randomize_layout: default_randomize_layout(),
        }
    }
}

fn default_codegen_units() -> Vec<u32> {
    vec![1, 2, 4, 8]
}

fn default_opt_levels() -> Vec<OptLevel> {
    vec![OptLevel::Z, OptLevel::S, OptLevel::Two]
}

fn default_lto() -> Vec<LtoMode> {
    vec![LtoMode::Off]
}

fn default_inline_thresholds() -> Vec<i32> {
    vec![25, 100, 300]
}

fn default_mir_opt_levels() -> Vec<u8> {
    vec![1, 2, 3]
}

fn default_randomize_layout() -> bool {
    false
}

/// The resolved codegen profile for one build.
///
/// `Default` is exactly today's release flags, so `PolymorphismMode::None` and
/// the default value reproduce the current bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodegenProfile {
    /// `-C codegen-units`.
    pub codegen_units: u32,
    /// `-C opt-level`.
    pub opt_level: OptLevel,
    /// `-C lto` (or `Off` for no flag).
    pub lto: LtoMode,
    /// `-C llvm-args=--inline-threshold=N` (`None` = no flag).
    pub inline_threshold: Option<i32>,
    /// `-Z mir-opt-level=N` (`None` = no flag).
    pub mir_opt_level: Option<u8>,
    /// `-Z randomize-layout` (needs `RUSTC_BOOTSTRAP=1`).
    pub randomize_layout: bool,
    /// `-Z layout-seed=N` (only meaningful with `randomize_layout`).
    pub layout_seed: u64,
}

impl CodegenProfile {
    /// Whether the profile needs the unstable `-Z` flag surface, which requires
    /// `RUSTC_BOOTSTRAP=1` on the pinned stable toolchain.
    pub fn uses_unstable(self) -> bool {
        self.mir_opt_level.is_some() || self.randomize_layout
    }
}

impl Default for CodegenProfile {
    fn default() -> Self {
        Self {
            codegen_units: 1,
            opt_level: OptLevel::Z,
            lto: LtoMode::Off,
            inline_threshold: None,
            mir_opt_level: None,
            randomize_layout: false,
            layout_seed: 0,
        }
    }
}

/// The resolved polymorphism configuration for one build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolymorphismConfig {
    /// The active level (forced to `none` for a debug build).
    pub mode: PolymorphismMode,
    /// The seed driving every per-build choice.
    pub seed: u64,
    /// The codegen profile `rustc` is invoked with.
    pub codegen: CodegenProfile,
}

impl Default for PolymorphismConfig {
    fn default() -> Self {
        Self {
            mode: PolymorphismMode::Full,
            seed: 0,
            codegen: CodegenProfile::default(),
        }
    }
}

impl PolymorphismConfig {
    /// Resolves the block for a build.
    ///
    /// `debug` forces `mode: none` (a debug build keeps the toolchain's debug
    /// flags and must stay reproducible), regardless of the plan's `mode`. A
    /// missing block means the defaults — `mode: full`, a random seed.
    pub fn from_yaml(yaml: Option<&YamlPolymorphismPlan>, debug: bool) -> Result<Self> {
        let plan = yaml.cloned().unwrap_or_default();
        plan.validate().map_err(BuildError::InvalidPolymorphism)?;

        let mode = if debug {
            PolymorphismMode::None
        } else {
            plan.mode
        };
        let seed = match plan.seed {
            Some(SeedSource::Literal(value)) => value,
            _ => rand::random::<u64>(),
        };
        let codegen = if mode.uses_codegen() {
            resolve_codegen(&plan.codegen, seed)
        } else {
            CodegenProfile::default()
        };
        Ok(Self {
            mode,
            seed,
            codegen,
        })
    }

    /// Whether the source-level phase applies (mode `source` or `full`).
    pub fn uses_source(self) -> bool {
        matches!(self.mode, PolymorphismMode::Source | PolymorphismMode::Full)
    }

    /// The record written into the build manifest.
    pub fn record(self) -> PolymorphismRecord {
        PolymorphismRecord {
            mode: self.mode,
            seed: self.seed,
            codegen_units: self.codegen.codegen_units,
            opt_level: self.codegen.opt_level,
            lto: self.codegen.lto,
            inline_threshold: self.codegen.inline_threshold,
            mir_opt_level: self.codegen.mir_opt_level,
            randomize_layout: self.codegen.randomize_layout,
            layout_seed: self.codegen.layout_seed,
        }
    }
}

/// Manifest record of the resolved polymorphism (`<stem>.manifest.json`).
///
/// The seed reproduces the artifact: `resolve_codegen(pools, seed)` is
/// deterministic, so the same seed (with the same pools) yields the same
/// profile.
#[derive(Debug, Clone, Serialize)]
pub struct PolymorphismRecord {
    /// Active level.
    pub mode: PolymorphismMode,
    /// The seed the profile was drawn from.
    pub seed: u64,
    /// Chosen `-C codegen-units`.
    pub codegen_units: u32,
    /// Chosen `-C opt-level`.
    pub opt_level: OptLevel,
    /// Chosen `-C lto`.
    pub lto: LtoMode,
    /// Chosen `-C llvm-args=--inline-threshold` (`None` = none).
    pub inline_threshold: Option<i32>,
    /// Chosen `-Z mir-opt-level` (`None` = none).
    pub mir_opt_level: Option<u8>,
    /// Whether `-Z randomize-layout` was applied.
    pub randomize_layout: bool,
    /// The `-Z layout-seed` used with `randomize_layout`.
    pub layout_seed: u64,
}

/// Draws a codegen profile from `plan`'s pools with `seed`.
///
/// One `StdRng` seeded with `seed`, so the same seed always yields the same
/// profile (the reproducibility guarantee the manifest relies on).
fn resolve_codegen(plan: &CodegenPlan, seed: u64) -> CodegenProfile {
    let mut rng = StdRng::seed_from_u64(seed);
    let codegen_units = choose(&mut rng, &plan.codegen_units, 1).max(1);
    let opt_level = choose(&mut rng, &plan.opt_level, OptLevel::Z);
    let lto = choose(&mut rng, &plan.lto, LtoMode::Off);
    let inline_threshold = if plan.inline_threshold.is_empty() {
        None
    } else {
        Some(choose(&mut rng, &plan.inline_threshold, 100))
    };
    let mir_opt_level = if plan.mir_opt_level.is_empty() {
        None
    } else {
        Some(choose(&mut rng, &plan.mir_opt_level, 2))
    };
    let layout_seed = rng.gen::<u64>();
    CodegenProfile {
        codegen_units,
        opt_level,
        lto,
        inline_threshold,
        mir_opt_level,
        randomize_layout: plan.randomize_layout,
        layout_seed,
    }
}

/// Picks one entry from `pool`, or `fallback` when the pool is empty.
fn choose<T: Copy>(rng: &mut StdRng, pool: &[T], fallback: T) -> T {
    if pool.is_empty() {
        return fallback;
    }
    pool[rng.gen_range(0..pool.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_mode_is_full() {
        assert_eq!(YamlPolymorphismPlan::default().mode, PolymorphismMode::Full);
    }

    #[test]
    fn none_keeps_the_baseline_profile() {
        let yaml = YamlPolymorphismPlan {
            mode: PolymorphismMode::None,
            ..YamlPolymorphismPlan::default()
        };
        let config = PolymorphismConfig::from_yaml(Some(&yaml), false).unwrap();
        assert_eq!(config.mode, PolymorphismMode::None);
        assert_eq!(config.codegen, CodegenProfile::default());
    }

    #[test]
    fn debug_forces_none_over_the_plan() {
        let yaml = YamlPolymorphismPlan {
            mode: PolymorphismMode::Full,
            ..YamlPolymorphismPlan::default()
        };
        let config = PolymorphismConfig::from_yaml(Some(&yaml), true).unwrap();
        assert_eq!(config.mode, PolymorphismMode::None);
        assert_eq!(config.codegen, CodegenProfile::default());
    }

    #[test]
    fn the_same_seed_yields_the_same_profile() {
        let yaml = YamlPolymorphismPlan {
            mode: PolymorphismMode::Full,
            seed: Some(SeedSource::Literal(0x1234_5678)),
            ..YamlPolymorphismPlan::default()
        };
        let first = PolymorphismConfig::from_yaml(Some(&yaml), false).unwrap();
        let second = PolymorphismConfig::from_yaml(Some(&yaml), false).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.seed, 0x1234_5678);
    }

    #[test]
    fn a_random_seed_is_drawn_without_a_literal() {
        let yaml = YamlPolymorphismPlan::default();
        let config = PolymorphismConfig::from_yaml(Some(&yaml), false).unwrap();
        assert_eq!(config.mode, PolymorphismMode::Full);
    }

    #[test]
    fn opt_level_zero_is_selectable() {
        // `0` is not in the default pool, but a plan can pin it: it is the escape
        // hatch for a build where the optimizer exposes a miscompile. The explicit
        // `debug-assertions=off` in `hardening_flags` keeps `cfg(debug_assertions)`
        // off, so it does not change behavior beyond not optimizing.
        let yaml: YamlPolymorphismPlan =
            serde_yml::from_str("mode: codegen\ncodegen:\n  opt_level: [\"0\"]\n")
                .expect("opt-level 0 should parse");
        yaml.validate().expect("opt-level 0 is a valid pool value");
        assert_eq!(yaml.codegen.opt_level, vec![OptLevel::Zero]);
        assert_eq!(OptLevel::Zero.flag(), "0");
        assert_eq!(resolve_codegen(&yaml.codegen, 0).opt_level, OptLevel::Zero);
        assert!(!CodegenPlan::default().opt_level.contains(&OptLevel::Zero));
    }

    #[test]
    fn a_wider_pool_is_actually_drawn_from() {
        // With a single-entry pool the choice is forced; that is what makes the
        // default `mode: none` byte-identical to the previous build.
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..64u64 {
            let profile = resolve_codegen(&CodegenPlan::default(), seed);
            assert!([1, 2, 4, 8].contains(&profile.codegen_units));
            seen.insert(profile.codegen_units);
        }
        assert!(seen.len() > 1, "codegen-units pool never varied: {seen:?}");
    }

    #[test]
    fn seed_literals_parse_decimal_and_hex() {
        assert_eq!(
            "literal:255".parse::<SeedSource>().unwrap(),
            SeedSource::Literal(255)
        );
        assert_eq!(
            "literal:0xff".parse::<SeedSource>().unwrap(),
            SeedSource::Literal(255)
        );
        assert_eq!("random".parse::<SeedSource>().unwrap(), SeedSource::Random);
        assert!("nope".parse::<SeedSource>().is_err());
        assert!("literal:xyz".parse::<SeedSource>().is_err());
    }

    #[test]
    fn a_zero_codegen_units_pool_entry_is_rejected() {
        let yaml = YamlPolymorphismPlan {
            codegen: CodegenPlan {
                codegen_units: vec![1, 0],
                ..CodegenPlan::default()
            },
            ..YamlPolymorphismPlan::default()
        };
        assert!(yaml.validate().is_err());
    }

    #[test]
    fn an_empty_codegen_units_pool_is_allowed() {
        // `codegen-units` is the one pool that may be empty: it falls back to
        // 1. `opt-level` and `lto` may not, because they always need a value.
        let yaml = YamlPolymorphismPlan {
            codegen: CodegenPlan {
                codegen_units: Vec::new(),
                ..CodegenPlan::default()
            },
            ..YamlPolymorphismPlan::default()
        };
        assert!(yaml.validate().is_ok());
        assert_eq!(resolve_codegen(&yaml.codegen, 7).codegen_units, 1);
    }

    #[test]
    fn the_new_knobs_are_drawn_from_the_seed() {
        let mut thresholds = std::collections::BTreeSet::new();
        let mut mir_levels = std::collections::BTreeSet::new();
        let mut layout_seeds = std::collections::BTreeSet::new();
        for seed in 0..64u64 {
            let profile = resolve_codegen(&CodegenPlan::default(), seed);
            thresholds.insert(profile.inline_threshold);
            mir_levels.insert(profile.mir_opt_level);
            layout_seeds.insert(profile.layout_seed);
            assert!(profile.uses_unstable());
        }
        assert!(
            thresholds.len() > 1,
            "inline thresholds never varied: {thresholds:?}"
        );
        assert!(mir_levels.len() > 1, "mir-opt levels never varied");
        assert!(layout_seeds.len() > 1, "layout seeds never varied");
    }

    #[test]
    fn a_negative_inline_threshold_is_rejected() {
        let yaml = YamlPolymorphismPlan {
            codegen: CodegenPlan {
                inline_threshold: vec![-1],
                ..CodegenPlan::default()
            },
            ..YamlPolymorphismPlan::default()
        };
        assert!(yaml.validate().is_err());
    }

    #[test]
    fn an_out_of_range_mir_opt_level_is_rejected() {
        let yaml = YamlPolymorphismPlan {
            codegen: CodegenPlan {
                mir_opt_level: vec![9],
                ..CodegenPlan::default()
            },
            ..YamlPolymorphismPlan::default()
        };
        assert!(yaml.validate().is_err());
    }
}
