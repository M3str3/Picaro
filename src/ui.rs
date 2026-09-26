//! Terminal UX: banner, color palette and small formatting primitives.
//!
//! Color is opt-in. A [`Palette`] either emits ANSI escapes or plain text, and
//! [`Palette::auto`] only enables color when stdout is an interactive terminal
//! and the environment allows it (`NO_COLOR`, `CLICOLOR=0` and `TERM=dumb` are
//! all honored). That keeps redirecting the output into a file or a log clean,
//! which matters because the audit report is meant to be copy-pasted into
//! notes.
//!
//! The palette is truecolor (24-bit) and chosen for legibility first: a soft
//! violet accent for the brand and headings, clear greens, yellows and reds for
//! status, and a steel blue for targets. Primary text is left in the terminal's
//! own foreground so it keeps full contrast on any theme; only accents carry
//! color, and the secondary tone stays bright enough to read on a dark
//! background.
//!
//! Wiring the streams through `anstream` (the same crate `clap` uses) means the
//! escapes are stripped when they would not be understood, and virtual-terminal
//! processing is enabled on Windows consoles where it is not on by default.

use std::fmt::Display;

use anstream::{AutoStream, ColorChoice};
use anstyle::{Color, Reset, RgbColor, Style};

/// Application name, used in the banner subtitle and the CLI help.
pub const NAME: &str = "batesian";

/// One-line description, reused by the CLI help and the banner subtitle.
pub const TAGLINE: &str = "mimicry-based packer";

/// The banner. `banner.txt` at the repo root is the single source of truth, so
/// the art is edited (only) there.
pub const BANNER: &str = include_str!("../banner.txt");

/// Glyphs used across the CLI.
///
/// Deliberately few, and all of them render in the common Windows terminals
/// (`wt`, `conhost`, `mintty`).
pub mod glyph {
    /// A completed step.
    pub const OK: &str = "✓";
    /// A failed step.
    pub const FAIL: &str = "✗";
    /// A warning marker.
    pub const WARN: &str = "!";
    /// A step bullet, and the prompt of the command echo line.
    pub const BULLET: &str = "▸";
    /// The marker of an interactive question.
    pub const ASK: &str = "?";
    /// Separator between pipeline steps.
    pub const ARROW: &str = "→";
    /// An inline separator between related values.
    pub const DOT: &str = "·";
    /// Filled cell of the entropy gauge.
    pub const BLOCK: &str = "█";
    /// Empty cell of the entropy gauge.
    pub const SHADE: &str = "░";
    /// Horizontal rule.
    pub const RULE: &str = "─";
}

/// Brand accent (banner, app name, headings): a soft violet.
const VIOLET: Color = Color::Rgb(RgbColor(167, 139, 250));
/// Success.
const GREEN: Color = Color::Rgb(RgbColor(126, 198, 153));
/// Muted success (entropy gauges, secondary confirmations).
const GREEN_DIM: Color = Color::Rgb(RgbColor(95, 158, 119));
/// Warning: a clean yellow, deliberately not orange.
const YELLOW: Color = Color::Rgb(RgbColor(224, 192, 96));
/// Danger.
const RED: Color = Color::Rgb(RgbColor(229, 118, 118));
/// Targets (binary paths, filenames): steel blue.
const BLUE: Color = Color::Rgb(RgbColor(122, 167, 224));
/// Secondary text (labels, function lists). Bright enough to read on a dark
/// background — never a near-invisible gray.
const SLATE: Color = Color::Rgb(RgbColor(154, 164, 178));
/// Structural punctuation (rules, separators, empty gauge cells).
const SLATE_DIM: Color = Color::Rgb(RgbColor(120, 130, 146));

/// Column labels are padded to this width in [`Palette::field`].
const LABEL_WIDTH: usize = 12;
/// Step labels are padded to this width in [`Palette::step`]/[`Palette::done`].
const STEP_WIDTH: usize = 8;
/// Gap between columns of the metadata bar.
const META_GAP: usize = 2;
/// Label width of a verbose detail line ([`Palette::detail`]).
const DETAIL_WIDTH: usize = 9;

/// Semantic color roles.
///
/// Renderers pick a role instead of a color so the palette stays in one place
/// and a report still reads correctly when the palette is disabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Brand accent (violet, bold): the tool name, section headings.
    Brand,
    /// Primary value text. Emitted in the terminal's default foreground, so it
    /// keeps full contrast on any theme.
    Value,
    /// Secondary text: labels, function lists.
    Dim,
    /// Structural punctuation: rules, separators, gauge track.
    Faint,
    /// Success.
    Ok,
    /// Muted success.
    OkDim,
    /// Warning.
    Warn,
    /// Danger.
    Bad,
    /// A target: binary paths and filenames.
    Target,
    /// Emphasis with no color.
    Bold,
}

/// The style backing each [`Tone`].
fn style_of(tone: Tone) -> Style {
    match tone {
        Tone::Brand => Style::new().fg_color(Some(VIOLET)).bold(),
        // `Value` is short-circuited in `Palette::tone`; the match must still be
        // exhaustive, so give it an empty style.
        Tone::Value => Style::new(),
        Tone::Dim => Style::new().fg_color(Some(SLATE)),
        Tone::Faint => Style::new().fg_color(Some(SLATE_DIM)),
        Tone::Ok => Style::new().fg_color(Some(GREEN)),
        Tone::OkDim => Style::new().fg_color(Some(GREEN_DIM)),
        Tone::Warn => Style::new().fg_color(Some(YELLOW)),
        Tone::Bad => Style::new().fg_color(Some(RED)).bold(),
        Tone::Target => Style::new().fg_color(Some(BLUE)),
        Tone::Bold => Style::new().bold(),
    }
}

/// One cell of the metadata bar: a short uppercase `key` and the `value` shown
/// underneath it, colored by `tone`.
pub struct Meta {
    pub key: &'static str,
    pub value: String,
    pub tone: Tone,
}

/// Renders styled text, or the plain text when coloring is disabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    color: bool,
}

impl Palette {
    /// Color only when stdout is an interactive terminal and the environment
    /// allows it.
    pub fn auto() -> Self {
        let choice = AutoStream::choice(&std::io::stdout());
        Self {
            color: !matches!(choice, ColorChoice::Never),
        }
    }

    /// Never emit escape codes (tests, redirected output, `--no-color`).
    pub fn plain() -> Self {
        Self { color: false }
    }

    /// Applies `style` to `text`, wrapping it in a reset when coloring is on.
    fn paint(self, style: Style, text: impl Display) -> String {
        if self.color {
            format!("{style}{text}{Reset}")
        } else {
            text.to_string()
        }
    }

    /// Paints `text` with the color role `tone`.
    pub fn tone(self, tone: Tone, text: impl Display) -> String {
        // Primary values carry no color: the terminal's own foreground is the
        // only choice that stays legible on every theme, since a fixed light
        // gray disappears on a light background (and vice versa).
        if tone == Tone::Value {
            return text.to_string();
        }
        self.paint(style_of(tone), text)
    }

    /// Brand color, for the banner and the app name.
    pub fn brand(self, text: impl Display) -> String {
        self.tone(Tone::Brand, text)
    }

    /// Section heading (same accent as the brand).
    pub fn heading(self, text: impl Display) -> String {
        self.tone(Tone::Brand, text)
    }

    /// Emphasis.
    pub fn bold(self, text: impl Display) -> String {
        self.tone(Tone::Bold, text)
    }

    /// Primary value text (the terminal's default foreground).
    pub fn value(self, text: impl Display) -> String {
        self.tone(Tone::Value, text)
    }

    /// Secondary text: labels and function lists.
    pub fn dim(self, text: impl Display) -> String {
        self.tone(Tone::Dim, text)
    }

    /// Structural punctuation: rules, separators, gauge track.
    pub fn faint(self, text: impl Display) -> String {
        self.tone(Tone::Faint, text)
    }

    /// Success text.
    pub fn ok(self, text: impl Display) -> String {
        self.tone(Tone::Ok, text)
    }

    /// Warning text.
    pub fn warn(self, text: impl Display) -> String {
        self.tone(Tone::Warn, text)
    }

    /// Error text.
    pub fn error(self, text: impl Display) -> String {
        self.tone(Tone::Bad, text)
    }

    /// A target: binary paths and filenames.
    pub fn target(self, text: impl Display) -> String {
        self.tone(Tone::Target, text)
    }

    /// A green check mark.
    pub fn check(self) -> String {
        self.ok(glyph::OK)
    }

    /// A yellow warning mark.
    pub fn bang(self) -> String {
        self.warn(glyph::WARN)
    }

    /// A red cross.
    pub fn cross(self) -> String {
        self.error(glyph::FAIL)
    }

    /// The faint prompt of the command echo line.
    pub fn prompt(self) -> String {
        self.faint(glyph::BULLET)
    }

    /// An interactive question: `  ? label` (no trailing colon/newline).
    ///
    /// The wizard appends the accepted values and reads the answer, so the
    /// question itself stays a pure formatting concern here.
    pub fn question(self, label: impl Display) -> String {
        format!("  {} {}", self.brand(glyph::ASK), label)
    }

    /// A numbered menu entry: `      1. name  description`.
    ///
    /// `description` is dimmed and omitted when empty; the name stays bold so
    /// the choices stand out from the question printed above them.
    pub fn menu(self, index: usize, name: &str, description: &str) -> String {
        if description.is_empty() {
            format!(
                "      {} {}",
                self.dim(format!("{index}.")),
                self.bold(name)
            )
        } else {
            format!(
                "      {} {}  {}",
                self.dim(format!("{index}.")),
                self.bold(name),
                self.dim(description)
            )
        }
    }

    /// A horizontal rule of `width` cells.
    ///
    /// Drawn with box-drawing characters rather than `-` so it visually matches
    /// the rest of the frame.
    pub fn rule(self, width: usize) -> String {
        self.faint(glyph::RULE.repeat(width))
    }

    /// The banner, brand-colored and without a trailing newline.
    pub fn banner(self) -> String {
        self.paint(style_of(Tone::Brand), BANNER.trim_end())
    }

    /// The `▸ app subcommand · target` echo printed at the top of a command's
    /// output.
    ///
    /// Showing the invocation makes pasted reports self-documenting: the reader
    /// sees exactly what was run without scrolling back through their shell.
    pub fn command_line(self, subcommand: &str, target: impl Display) -> String {
        format!(
            "{} {} {} {} {}",
            self.prompt(),
            self.brand(NAME),
            self.value(subcommand),
            self.faint(glyph::DOT),
            self.target(target),
        )
    }

    /// A horizontal metadata bar: a row of uppercase keys with their values
    /// column-aligned directly underneath.
    ///
    /// Each column is as wide as its widest cell, so values never drift under
    /// the wrong key. When the row would exceed the detected terminal width the
    /// bar stacks one `KEY  value` line per item instead, which keeps a narrow
    /// window readable rather than wrapping the two rows out of alignment.
    pub fn meta_bar(self, items: &[Meta]) -> String {
        if items.is_empty() {
            return String::new();
        }

        let widths: Vec<usize> = items
            .iter()
            .map(|item| item.key.chars().count().max(item.value.chars().count()))
            .collect();
        let total: usize = widths.iter().sum::<usize>() + META_GAP * (items.len() - 1);

        if total > term_width() {
            let key_width = items
                .iter()
                .map(|i| i.key.chars().count())
                .max()
                .unwrap_or(0);
            return items
                .iter()
                .map(|item| {
                    format!(
                        "{} {}\n",
                        self.dim(format!("{:<width$}", item.key, width = key_width)),
                        self.tone(item.tone, &item.value)
                    )
                })
                .collect();
        }

        let gap = " ".repeat(META_GAP);
        let last = items.len() - 1;
        let keys = items
            .iter()
            .zip(&widths)
            .enumerate()
            .map(|(i, (item, width))| {
                // The last column needs no padding, which keeps trailing
                // whitespace out of a report meant to be copy-pasted.
                if i == last {
                    self.dim(item.key)
                } else {
                    self.dim(format!("{:<width$}", item.key, width = *width))
                }
            })
            .collect::<Vec<_>>()
            .join(&gap);
        let values = items
            .iter()
            .zip(&widths)
            .enumerate()
            .map(|(i, (item, width))| {
                if i == last {
                    self.tone(item.tone, &item.value)
                } else {
                    self.tone(item.tone, format!("{:<width$}", item.value, width = *width))
                }
            })
            .collect::<Vec<_>>()
            .join(&gap);
        format!("{keys}\n{values}\n")
    }

    /// An aligned `label  value` line (no trailing newline).
    pub fn field(self, label: &str, value: impl Display) -> String {
        format!(
            "  {} {}",
            self.dim(format!("{label:<width$}", width = LABEL_WIDTH)),
            value
        )
    }

    /// A completed step: `  ✓ label  detail`.
    ///
    /// `detail` is used verbatim so the caller can color each fragment; this
    /// never dims it, because SGR faint persists until reset and would wash out
    /// a path or value nested inside.
    pub fn done(self, label: &str, detail: impl Display) -> String {
        format!(
            "  {} {} {}",
            self.check(),
            self.bold(format!("{label:<width$}", width = STEP_WIDTH)),
            detail
        )
    }

    /// An indented `label  value` line for verbose step detail.
    pub fn detail(self, label: &str, value: impl Display) -> String {
        format!(
            "      {} {}",
            self.dim(format!("{label:<width$}", width = DETAIL_WIDTH)),
            value
        )
    }

    /// The closing result line: `  ✓ label  detail`, label in the success color.
    ///
    /// Distinct from [`Palette::done`] so the final artifact stands out from the
    /// per-step lines around it.
    pub fn result(self, label: &str, detail: impl Display) -> String {
        format!(
            "  {} {} {}",
            self.check(),
            self.ok(self.bold(format!("{label:<width$}", width = STEP_WIDTH))),
            detail
        )
    }
}

/// The terminal width in columns, from `COLUMNS` when set (default 80).
///
/// Layout helpers use this to decide between a wide and a stacked rendering;
/// reading the environment keeps us dependency-free, and a wrong guess only
/// costs a fallback that is always readable.
fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .filter(|width| *width > 0)
        .unwrap_or(80)
}

/// Formats a byte count as a compact human size (`512 B`, `121 KB`, `3 MB`).
pub fn human_size(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

/// Formats a duration as `42 ms` or `1.50 s`.
pub fn format_elapsed(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms == 0 {
        "<1 ms".to_string()
    } else if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.2} s", d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain palette must not leak escape codes into the output.
    #[test]
    fn plain_palette_emits_no_escapes() {
        let ui = Palette::plain();
        assert_eq!(ui.ok("done"), "done");
        assert_eq!(ui.bang(), glyph::WARN);
        assert_eq!(
            ui.field("size", "1 bytes"),
            format!("  {:<12} {}", "size", "1 bytes")
        );
    }

    /// The colored palette wraps the text and resets it afterwards.
    #[test]
    fn colored_palette_wraps_style_and_reset() {
        let ui = Palette { color: true };
        let styled = ui.ok("done");
        assert!(styled.starts_with("\u{1b}["), "no escape: {styled:?}");
        assert!(styled.ends_with("\u{1b}[0m"), "no reset: {styled:?}");
        assert!(styled.contains("done"));
    }

    /// Primary values stay in the terminal's default foreground even when color
    /// is on, so they never lose contrast on a light (or dark) theme.
    #[test]
    fn value_tone_emits_no_color_even_when_enabled() {
        let ui = Palette { color: true };
        assert_eq!(ui.value("x64"), "x64");
    }

    /// Step lines keep the label column aligned regardless of label length.
    #[test]
    fn done_lines_align_labels() {
        let ui = Palette::plain();
        assert_eq!(
            ui.done("read", "a.exe"),
            format!("  {} {:<8} {}", glyph::OK, "read", "a.exe")
        );
        // Same column even though the labels differ in length.
        let short = ui.done("read", "v");
        let long = ui.done("encrypt", "v");
        assert_eq!(short.len(), long.len());
        // The closing result line shares the same column layout.
        assert_eq!(
            ui.result("packed", "out.exe"),
            format!("  {} {:<8} {}", glyph::OK, "packed", "out.exe")
        );
    }

    /// Detail lines align their labels under a deeper indent.
    #[test]
    fn detail_lines_align_labels() {
        let ui = Palette::plain();
        assert_eq!(
            ui.detail("time", "12 ms"),
            format!("      {:<9} {}", "time", "12 ms")
        );
    }

    /// Human sizes pick a sensible unit.
    #[test]
    fn human_size_picks_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1 KB");
        assert_eq!(human_size(123904), "121 KB");
        assert_eq!(human_size(3 * 1024 * 1024), "3 MB");
    }

    /// Durations switch from milliseconds to seconds.
    #[test]
    fn format_elapsed_switches_units() {
        use std::time::Duration;
        assert_eq!(format_elapsed(Duration::from_millis(0)), "<1 ms");
        assert_eq!(format_elapsed(Duration::from_millis(42)), "42 ms");
        assert_eq!(format_elapsed(Duration::from_millis(1500)), "1.50 s");
    }

    /// The banner comes from `banner.txt` and is embedded at compile time.
    #[test]
    fn banner_is_embedded() {
        assert!(
            BANNER.contains(glyph::BLOCK),
            "banner looks empty: {BANNER:?}"
        );
        assert_eq!(Palette::plain().banner(), BANNER.trim_end());
    }

    /// The command echo carries the tool name, the subcommand and the target.
    #[test]
    fn command_line_names_tool_subcommand_and_target() {
        let line = Palette::plain().command_line("audit", "a.exe");
        assert_eq!(
            line,
            format!("{} {NAME} audit {} a.exe", glyph::BULLET, glyph::DOT)
        );
    }

    /// The metadata bar lays the keys above their values.
    #[test]
    fn meta_bar_keeps_keys_and_values() {
        let bar = Palette::plain().meta_bar(&[
            Meta {
                key: "SIZE",
                value: "12 bytes".to_string(),
                tone: Tone::Value,
            },
            Meta {
                key: "ARCH",
                value: "x64".to_string(),
                tone: Tone::Value,
            },
        ]);
        assert!(bar.contains("SIZE"), "keys missing: {bar:?}");
        assert!(bar.contains("ARCH"), "keys missing: {bar:?}");
        assert!(bar.contains("12 bytes"), "values missing: {bar:?}");
        assert!(bar.contains("x64"), "values missing: {bar:?}");
        assert!(!bar.contains('\u{1b}'), "escapes leaked: {bar:?}");
    }

    /// A question carries its mark and label and nothing else.
    #[test]
    fn question_marks_the_label() {
        assert_eq!(
            Palette::plain().question("name"),
            format!("  {} name", glyph::ASK)
        );
    }

    /// Menu entries indent, number and separate the name from its description.
    #[test]
    fn menu_numbers_name_and_description() {
        let ui = Palette::plain();
        assert_eq!(
            ui.menu(2, "stack", "decoder-free"),
            "      2. stack  decoder-free"
        );
        assert_eq!(ui.menu(1, "xor", ""), "      1. xor");
    }
}
