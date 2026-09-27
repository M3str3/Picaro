//! Plausible, randomized identity for the packed artifact.
//!
//! A generated `VERSIONINFO` and certificate subject that look like a real
//! product keep the artifact from carrying obviously synthetic metadata
//! ("test", "admin", empty strings). `randomize` in `output.resources.version_info`
//! turns it on; explicit fields in the plan always win.

use rand::Rng;
use serde::Serialize;

use crate::plan::schema::VersionInfoPlan;

/// Company-name parts: `"<adjective> <noun> <suffix>"`, e.g. `Blue Ridge Systems`.
const ADJECTIVES: &[&str] = &[
    "Blue", "Iron", "Cedar", "North", "Silver", "Bright", "Rapid", "Quiet", "Golden", "Granite",
    "Aurora", "Vector", "Lumen", "Harbor", "Summit", "Cobalt", "Amber", "Willow", "Onyx", "Zephyr",
];
const NOUNS: &[&str] = &[
    "Ridge", "Harbor", "Peak", "Stream", "Bridge", "Works", "Point", "Bay", "Field", "Forge",
    "Gate", "Springs", "Vale", "Circuit", "Nexus", "Foundry", "Axis", "Orbit", "Trail", "Meadow",
];
const SUFFIXES: &[&str] = &[
    "Technologies",
    "Systems",
    "Labs",
    "Software",
    "Solutions",
    "Industries",
    "Group",
    "Dynamics",
    "Digital",
    "Networks",
];
/// Product kinds, appended to the company's noun: `"<noun> <kind>"`.
const KINDS: &[&str] = &[
    "Suite", "Manager", "Client", "Hub", "Toolkit", "Station", "Console", "Agent", "Studio",
    "Center",
];
/// Short purposes appended to the product for the file description.
const PURPOSES: &[&str] = &[
    "desktop application",
    "background service",
    "system utility",
    "configuration tool",
    "device helper",
];

/// A coherent set of generated metadata values.
#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    pub company: String,
    pub product: String,
    pub description: String,
    pub internal_name: String,
    pub copyright: String,
    pub file_version: String,
    pub product_version: String,
}

/// Generates a fresh identity.
///
/// `original_filename` is not generated: it must match the real artifact name,
/// so it is passed in by the caller.
pub fn generate() -> Identity {
    let mut rng = rand::thread_rng();
    let mut pick = |list: &[&'static str]| list[rng.gen_range(0..list.len())].to_string();

    let adjective = pick(ADJECTIVES);
    let noun = pick(NOUNS);
    let suffix = pick(SUFFIXES);
    let kind = pick(KINDS);
    let purpose = pick(PURPOSES);

    let company = format!("{adjective} {noun} {suffix}");
    let product = format!("{noun} {kind}");
    let description = format!("{product} - {purpose}");
    let internal_name = product.to_lowercase().replace(' ', "");

    let file_version = version_string(random_version(&mut rng));
    let product_version = version_string(random_version(&mut rng));

    Identity {
        copyright: format!(
            "Copyright (C) {} {company}. All rights reserved.",
            current_year()
        ),
        company,
        product,
        description,
        internal_name,
        file_version,
        product_version,
    }
}

/// Fills the unset fields of `plan` with generated values when
/// `plan.randomize` is set.
///
/// The returned plan has `randomize` cleared, so it can be used as a plain,
/// fully-resolved `VERSIONINFO` spec.
pub fn apply(plan: &VersionInfoPlan) -> VersionInfoPlan {
    if !plan.randomize {
        return plan.clone();
    }
    let identity = generate();
    VersionInfoPlan {
        company: plan.company.clone().or(Some(identity.company)),
        product: plan.product.clone().or(Some(identity.product)),
        description: plan.description.clone().or(Some(identity.description)),
        original_filename: plan.original_filename.clone(),
        internal_name: plan.internal_name.clone().or(Some(identity.internal_name)),
        copyright: plan.copyright.clone().or(Some(identity.copyright)),
        file_version: plan.file_version.clone().or(Some(identity.file_version)),
        product_version: plan
            .product_version
            .clone()
            .or(Some(identity.product_version)),
        randomize: false,
    }
}

/// A random `(major, minor, patch, build)` version.
fn random_version(rng: &mut impl Rng) -> (u16, u16, u16, u16) {
    (
        rng.gen_range(1..=10),
        rng.gen_range(0..=30),
        rng.gen_range(0..=99),
        rng.gen_range(0..=9999),
    )
}

/// `1.2.3.4` for a version tuple.
fn version_string(version: (u16, u16, u16, u16)) -> String {
    format!("{}.{}.{}.{}", version.0, version.1, version.2, version.3)
}

/// Current year, from the system clock (1970 + whole years since the epoch).
fn current_year() -> u64 {
    1970 + std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 31_557_600)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_non_empty_coherent_values() {
        let identity = generate();
        assert!(identity.company.split(' ').count() >= 3, "{identity:?}");
        assert!(!identity.product.is_empty());
        assert!(identity.description.starts_with(&identity.product));
        assert_eq!(
            identity.internal_name,
            identity.product.to_lowercase().replace(' ', "")
        );
        assert!(identity.copyright.contains(&identity.company));
        assert_eq!(identity.file_version.split('.').count(), 4);
        assert_eq!(identity.product_version.split('.').count(), 4);
    }

    #[test]
    fn randomizes_unset_fields_and_clears_the_flag() {
        let plan = VersionInfoPlan {
            randomize: true,
            ..VersionInfoPlan::default()
        };
        let resolved = apply(&plan);
        assert!(!resolved.randomize);
        assert!(resolved.company.is_some());
        assert!(resolved.file_version.is_some());
    }

    #[test]
    fn explicit_fields_win_over_generated_ones() {
        let plan = VersionInfoPlan {
            randomize: true,
            company: Some("Explicit Ltd".to_string()),
            ..VersionInfoPlan::default()
        };
        let resolved = apply(&plan);
        assert_eq!(resolved.company.as_deref(), Some("Explicit Ltd"));
        assert!(
            resolved.product.is_some(),
            "the other fields are still filled"
        );
    }

    #[test]
    fn apply_is_a_no_op_without_randomize() {
        let plan = VersionInfoPlan {
            company: Some("Only This".to_string()),
            ..VersionInfoPlan::default()
        };
        assert_eq!(apply(&plan), plan);
    }
}
