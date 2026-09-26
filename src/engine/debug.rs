//! Debug instrumentation for the generated stub.
//!
//! `build.stub.debug: true` turns the packed binary into a debug artifact: the
//! technique fragments call `crate::tech_dbg!` at every step they take, and this
//! module renders the macro so those calls print one
//! `[+] [<technique>] <message>` line on stderr.
//!
//! The fragments are the same in both modes, so a trace point is written once.
//! With the flag off the macro expands to nothing without evaluating its
//! arguments, which removes every debug literal at compile time: a release
//! artifact stays byte-for-byte as evasive as before this feature existed. That
//! is also why the trace literals do not go through
//! [`super::obfuscation::StringsConfig`]: they exist only in a debug build, a
//! deliberate laboratory trade of evasion for observability.
//!
//! The prelude is *appended* to the rendered stub (builtin or custom) by the
//! stub renderer, so a custom loader stub declares nothing for it.

/// The macro every technique fragment calls for a trace line. It is exported
/// from the crate root, so fragments call it as `crate::tech_dbg!` from any
/// module.
#[cfg(test)]
pub const TECH_DBG: &str = "tech_dbg";

/// Marks the start of the appended prelude. It is present in every variant, so
/// a caller that needs to reason about the template's own output (the tests that
/// assert no `$PLACEHOLDER$` survived) can cut it off first.
#[cfg(test)]
pub const PRELUDE_MARKER: &str = "// --- Debug instrumentation";

/// Returns `source` up to the appended debug prelude.
///
/// The prelude contains `$` as Rust macro syntax, so it would defeat a
/// "no left-over placeholder" check over the whole rendered stub. Test-only.
#[cfg(test)]
pub fn strip_prelude(source: &str) -> &str {
    match source.find(PRELUDE_MARKER) {
        Some(index) => source[..index].trim_end(),
        None => source,
    }
}

/// Renders the prelude appended to every generated stub.
///
/// `windows_subsystem` picks the variant that allocates a console before the
/// first line: a `windows`-subsystem process has no console attached, so its
/// stderr would otherwise go nowhere.
pub fn render_prelude(debug: bool, windows_subsystem: bool) -> &'static str {
    match (debug, windows_subsystem) {
        (false, _) => DISABLED,
        (true, false) => ENABLED,
        (true, true) => ENABLED_WITH_CONSOLE,
    }
}

/// The no-op prelude (`build.stub.debug: false`). Its macro discards its tokens
/// without evaluating them, so neither the trace literals nor the logged values
/// survive into the binary.
const DISABLED: &str = r#"
// --- Debug instrumentation (build.stub.debug = false) ---
// The technique fragments call `crate::tech_dbg!` unconditionally; with the
// flag off the macro expands to nothing and none of its arguments are
// evaluated, so no debug literal reaches the binary.
#[allow(unused_macros)]
#[macro_export]
macro_rules! tech_dbg {
    ($($tt:tt)*) => {};
}
"#;

/// The enabled prelude (`build.stub.debug: true`, console subsystem).
const ENABLED: &str = r#"
// --- Debug instrumentation (build.stub.debug = true) ---
// Prints one `[+] [<technique>] <message>` line per step on stderr, so it never
// mixes with the payload's stdout.
#[allow(unused_macros)]
#[macro_export]
macro_rules! tech_dbg {
    ($tech:literal, $($arg:tt)*) => {
        eprintln!("[+] [{}] {}", $tech, format_args!($($arg)*));
    };
}
"#;

/// The enabled prelude for a `windows`-subsystem artifact, which has no console
/// to write stderr to until one is allocated.
const ENABLED_WITH_CONSOLE: &str = r#"
// --- Debug instrumentation (build.stub.debug = true) ---
// Prints one `[+] [<technique>] <message>` line per step on stderr. The artifact
// uses the `windows` subsystem, so a console is allocated on the first line.
#[allow(unused_macros)]
#[macro_export]
macro_rules! tech_dbg {
    ($tech:literal, $($arg:tt)*) => {{
        crate::__batesian_debug_console();
        eprintln!("[+] [{}] {}", $tech, format_args!($($arg)*));
    }};
}

/// Allocates a console the first time a trace line is printed. A `windows`
/// subsystem process runs without one, so stderr would otherwise be discarded.
#[allow(dead_code)]
fn __batesian_debug_console() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = unsafe { windows::Win32::System::Console::AllocConsole() };
    });
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_prelude_strips_everything() {
        let prelude = render_prelude(false, false);
        assert!(prelude.contains("macro_rules! tech_dbg"));
        // The discarded-token arm must not reference the format machinery.
        assert!(!prelude.contains("eprintln!"));
        assert!(!prelude.contains("format_args"));
        // A windows subsystem must not add the console allocation either.
        assert!(!render_prelude(false, true).contains("AllocConsole"));
    }

    #[test]
    fn enabled_prelude_prints_on_stderr() {
        let prelude = render_prelude(true, false);
        assert!(prelude.contains("eprintln!"));
        assert!(prelude.contains("[+] [{}] {}"));
        assert!(!prelude.contains("AllocConsole"));
    }

    #[test]
    fn enabled_windows_prelude_allocates_a_console() {
        let prelude = render_prelude(true, true);
        assert!(prelude.contains("AllocConsole"));
        assert!(prelude.contains("__batesian_debug_console"));
        assert!(prelude.contains("eprintln!"));
    }

    #[test]
    fn every_variant_exports_the_macro_at_the_crate_root() {
        for debug in [false, true] {
            for windows in [false, true] {
                let prelude = render_prelude(debug, windows);
                assert!(
                    prelude.contains("#[macro_export]"),
                    "debug={debug} windows={windows}: {prelude}"
                );
                assert!(prelude.contains(&format!("macro_rules! {TECH_DBG}")));
            }
        }
    }

    #[test]
    fn strip_prelude_cuts_the_appended_block() {
        let stub = format!("fn main() {{}}\n{}", render_prelude(true, false));
        assert_eq!(strip_prelude(&stub), "fn main() {}");
        // A source without a prelude is returned unchanged.
        assert_eq!(strip_prelude("fn main() {}"), "fn main() {}");
    }
}
