//! Stable splitmix64 mixer.
//!
//! Both the generated source constants (`engine::steps`) and the recorded build
//! entropy (`engine::entropy`) derive per-build values from a seed. The
//! derivation is part of the reproduction contract, so there is one
//! implementation instead of two copies that could drift.

const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

/// Advances `state` and returns the next splitmix64 value.
pub(crate) fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(GOLDEN);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the first three values for seed 0. The sequence is fixed by the
    /// reproduction contract; changing it is a manifest schema bump.
    #[test]
    fn the_sequence_is_stable() {
        let mut state = 0;
        assert_eq!(splitmix64(&mut state), 0xE220_A839_7B1D_CDAF);
        assert_eq!(splitmix64(&mut state), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(splitmix64(&mut state), 0x06C4_5D18_8009_454F);
    }
}
