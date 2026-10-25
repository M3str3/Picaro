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
use std::io::IsTerminal;

use anstream::{AutoStream, ColorChoice};
use anstyle::{Color, Reset, RgbColor, Style};

pub mod markdown;
pub mod pager;

/// Application name, used in the banner subtitle and the CLI help.
pub const NAME: &str = "picaro";

/// One-line description, reused by the CLI help and the banner subtitle.
pub const TAGLINE: &str = "Declarative evasion for Windows payloads";

// pub const BANNER: &str = "
//   ██████╗  █████╗ ████████╗███████╗███████╗██╗ █████╗ ███╗  ██╗
//   ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██║██╔══██╗████╗ ██║
//   ██████╦╝███████║   ██║   █████╗  ███████╗██║███████║██╔██╗██║
//   ██╔══██╗██╔══██║   ██║   ██╔══╝  ╚════██║██║██╔══██║██║╚████║
//   ██████╦╝██║  ██║   ██║   ███████╗███████║██║██║  ██║██║ ╚███║
//   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
// ";
// //
// pub const BANNER: &str = "
// █████▄ ▄▄  ▄▄▄▄  ▄▄▄  ▄▄▄▄   ▄▄▄
// ██▄▄█▀ ██ ██▀▀▀ ██▀██ ██▄█▄ ██▀██
// ██     ██ ▀████ ██▀██ ██ ██ ▀███▀
// ";

// pub const BANNER: &str = "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣾⣿⣿⣶⣿⣿⡿⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣻⢽⡳⣏⠞⣜⣹⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⡟⣧⠳⡍⢖⢣⡙⡚⠴⡸⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⡿⠘⠤⠓⡨⠌⢂⠔⡁⠆⠡⢀⢊⡽⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⠛⠒⠙⠒⠲⢤⡈⠄⢂⠐⢈⠐⢤⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⢆⠀⠀⠀⠀⠀⠈⠫⣆⡈⠄⠠⢌⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⠫⢦⡀⠀⠀⠀⠀⠀⢱⡇⢌⠘⣯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣧⠇⡌⠙⣦⣄⡀⠀⠀⢸⣏⠴⡘⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⡗⡸⣀⢣⠰⣨⢙⡷⣶⣿⣿⣞⡱⢺⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⡰⡑⠦⣌⠳⡄⣿⣾⣿⣿⣿⣿⡭⡙⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡧⢉⠤⡈⢡⢸⣿⣿⣿⣿⣿⡿⣤⢡⢸⡀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⠜⡡⠒⢡⠃⣿⣿⣿⣿⣿⣿⣿⣽⢷⡆⣇⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⡟⢤⡉⢆⡸⢟⢋⣍⣽⣷⣿⣿⣿⣿⣷⠺⣄⠀⣠⣴⡿⣧⣠⡿
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣽⣿⣿⣿⣿⣿⣿⣿⣟⠦⡑⡎⡴⣋⠴⣸⣿⣿⣿⡿⣿⣿⣿⠇⣾⣿⣿⣯⣿⣿⣯⠃
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣇⠳⣙⠶⣩⣿⣿⣿⣯⣿⣇⠀⠀⢀⡀⣻⠿⣿⣿⣿⣿⠃⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⡎⣝⣾⢿⣿⣿⣿⣿⣿⣿⣿⣿⢠⣾⣿⣷⣼⣿⢿⡿⠁⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣭⣟⣛⡻⠿⣿⠧⣼⣿⣿⣿⣿⡿⠟⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣯⣿⣿⣿⣿⠿⢿⣿⣻⣿⣶⣶⣿⢿⣿⣿⡟⠁⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⡇⠠⣄⣻⡿⣿⡿⣳⣯⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⡿⢧⣡⣽⣿⣿⣿⣰⣿⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⠿⣀⣦⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠒⠻⠿⠟⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀";

/// The wordmark shown at the left of the header.
///
/// Kept as a literal rather than a data file: the art lives with the code that
/// prints it, so there is no second copy to keep in sync. The frame around it
/// (and the art beside it) is drawn by [`frame`] when the banner is rendered.
pub const BANNER: &str = "   ███████████   ███
  ░░███░░░░░███ ░░░
   ░███    ░███ ████   ██████   ██████   ████████   ██████
   ░██████████ ░░███  ███░░███ ░░░░░███ ░░███░░███ ███░░███
   ░███░░░░░░   ░███ ░███ ░░░   ███████  ░███ ░░░ ░███ ░███
   ░███         ░███ ░███  ███ ███░░███  ░███     ░███ ░███
   █████        █████░░██████ ░░████████ █████    ░░██████
  ░░░░░        ░░░░░  ░░░░░░   ░░░░░░░░ ░░░░░      ░░░░░░";

/// The mascot art shown at the right of the header.
///
/// Its trailing braille blank cells (`U+2800`) are padding, not drawing; the
/// layout ignores them so the gap to the banner stays exact (see
/// [`banner_side_by_side`]).
// pub const ASCII_ART: &str = "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⡿⠿⠿⠆⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⠋⢀⡔⠁⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⠿⣿⢠⡞⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⠀⠀⠀⢀⣀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣾⣿⣿⣿⣿⣿⣿⠀⣀⣤⣾⠿⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣘⣯⣿⣿⣿⣿⣿⣿⣿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠙⠛⠻⠿⣿⣿⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⢀⣶⣾⣿⠟⠛⠻⠿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣿⡟⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⡾⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠸⢿⣧⣄⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀";
pub const ASCII_ART: &str = "";

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
    /// List item marker (Markdown renderer).
    pub const LIST: &str = "•";
    /// Vertical gutter of a quote or code block (Markdown renderer).
    pub const BAR: &str = "│";
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
/// Warning bar: orange-yellow behind black text.
const WARN_BAR_BG: Color = Color::Rgb(RgbColor(235, 166, 52));
const WARN_BAR_FG: Color = Color::Rgb(RgbColor(18, 14, 6));
/// Targets (binary paths, filenames): steel blue.
const BLUE: Color = Color::Rgb(RgbColor(122, 167, 224));
/// Secondary text (labels, function lists). Bright enough to read on a dark
/// background — never a near-invisible gray.
const SLATE: Color = Color::Rgb(RgbColor(154, 164, 178));
/// Structural punctuation (rules, separators, empty gauge cells).
const SLATE_DIM: Color = Color::Rgb(RgbColor(120, 130, 146));
/// Inline code (Markdown renderer): a soft cyan, distinct from the brand violet.
const CYAN: Color = Color::Rgb(RgbColor(126, 200, 208));

/// Column labels are padded to this width in [`Palette::field`].
const LABEL_WIDTH: usize = 12;
/// Indent of a wrapped field value: the two leading spaces, the label column and
/// its trailing space (see [`Palette::field_wrapped`]).
const VALUE_INDENT: usize = 2 + LABEL_WIDTH + 1;
/// Step labels are padded to this width in [`Palette::step`]/[`Palette::done`].
const STEP_WIDTH: usize = 8;
/// Gap between columns of the metadata bar.
const META_GAP: usize = 2;
/// Label width of a verbose detail line ([`Palette::detail`]).
const DETAIL_WIDTH: usize = 9;
/// Empty columns between the banner and the art in [`banner_side_by_side`].
const ART_GAP: usize = 4;
/// Blank cells [`frame`] leaves between the banner and its border.
const BANNER_PADDING: usize = 1;

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
    /// Italic emphasis with no color.
    Italic,
    /// An inline code span.
    Code,
    /// A hyperlink's label.
    Link,
}

/// The style of a warning bar: black text on the warning background.
fn warn_bar_style() -> Style {
    Style::new()
        .fg_color(Some(WARN_BAR_FG))
        .bg_color(Some(WARN_BAR_BG))
        .bold()
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
        Tone::Italic => Style::new().italic(),
        Tone::Code => Style::new().fg_color(Some(CYAN)),
        Tone::Link => Style::new().underline(),
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

    /// Italic emphasis.
    pub fn italic(self, text: impl Display) -> String {
        self.tone(Tone::Italic, text)
    }

    /// An inline code span.
    pub fn code(self, text: impl Display) -> String {
        self.tone(Tone::Code, text)
    }

    /// A hyperlink's label.
    pub fn link(self, text: impl Display) -> String {
        self.tone(Tone::Link, text)
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

    /// A warning as black text on the warning background, wrapped to `width`.
    ///
    /// The first line carries the `!`; continuations are indented so the block
    /// stays aligned. Without color it degrades to `! message`, which keeps
    /// redirected output readable.
    pub fn warn_lines(self, message: impl Display, width: usize) -> Vec<String> {
        let message = message.to_string();
        let available = width.saturating_sub(4).max(20);
        let mut wrapped = wrap_text(&message, available).into_iter();
        let mut out = Vec::new();
        if let Some(first) = wrapped.next() {
            out.push(self.warn_line(format!("! {first}")));
        }
        for line in wrapped {
            out.push(self.warn_line(format!("  {line}")));
        }
        out
    }

    fn warn_line(self, text: String) -> String {
        let text = text.trim_end();
        if !self.color {
            return text.to_string();
        }
        format!("{} {text} {Reset}", warn_bar_style())
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

    /// The banner and the mascot art side by side, boxed, brand-colored and
    /// without a trailing newline.
    pub fn banner(self) -> String {
        self.paint(
            style_of(Tone::Brand),
            frame(&banner_side_by_side(), BANNER_PADDING),
        )
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

    /// An aligned `label  value` line whose value wraps onto continuation lines
    /// indented under it (no trailing newline).
    ///
    /// The `techniques show` header carries long comma-joined lists that must
    /// not overflow a narrow terminal even when the page is printed inline
    /// (without the pager), so they are wrapped here instead of at draw time.
    pub fn field_wrapped(self, label: &str, value: impl Display, width: usize) -> String {
        let text = value.to_string();
        let available = width.saturating_sub(VALUE_INDENT).max(1);
        let mut lines = wrap_text(&text, available).into_iter();
        let mut out = self.field(label, lines.next().unwrap_or_default());
        for line in lines {
            out.push('\n');
            out.push_str(&" ".repeat(VALUE_INDENT));
            out.push_str(&line);
        }
        out
    }

    /// A completed step: `  ✓ label  detail`.
    ///
    /// `detail` is used verbatim so the caller can color each fragment; this
    /// never dims it, because SGR faint persists until reset and would wash out
    /// a path or value nested inside.
    pub fn done(self, label: &str, detail: impl Display) -> String {
        let label = capitalize(label);
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
        let label = capitalize(label);
        format!(
            "  {} {} {}",
            self.check(),
            self.ok(self.bold(format!("{label:<width$}", width = STEP_WIDTH))),
            detail
        )
    }
}

/// Uppercases the first letter of a label, leaving the rest untouched.
fn capitalize(label: &str) -> String {
    let mut chars = label.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// A token produced by [`wrap_text_pieces`]: `continuation` marks a chunk that
/// continues the previous one (a hard-broken long token), so no space is added.
struct Piece {
    text: String,
    continuation: bool,
}

/// Wraps plain `text` to `width` visible columns.
///
/// It breaks on whitespace; a single token wider than `width` is first split at
/// its `,` boundaries (so a joined list breaks readably), then hard-broken.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    let mut line_width = 0usize;

    for piece in wrap_text_pieces(text, width) {
        let piece_width = piece.text.chars().count();
        let mut gap = if line_width > 0 && !piece.continuation {
            1
        } else {
            0
        };
        if line_width > 0 && line_width + gap + piece_width > width {
            lines.push(std::mem::take(&mut line));
            line_width = 0;
            gap = 0;
        }
        if gap == 1 {
            line.push(' ');
        }
        line.push_str(&piece.text);
        line_width += gap + piece_width;
    }

    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Splits `text` into wrappable pieces of at most `width` visible columns.
fn wrap_text_pieces(text: &str, width: usize) -> Vec<Piece> {
    let mut pieces = Vec::new();
    for token in text.split_whitespace() {
        if token.chars().count() <= width {
            pieces.push(Piece {
                text: token.to_string(),
                continuation: false,
            });
            continue;
        }
        for part in split_at_commas(token) {
            if part.chars().count() <= width {
                pieces.push(Piece {
                    text: part,
                    continuation: false,
                });
            } else {
                for (index, chunk) in hard_chunks(&part, width).into_iter().enumerate() {
                    pieces.push(Piece {
                        text: chunk,
                        continuation: index > 0,
                    });
                }
            }
        }
    }
    pieces
}

/// Splits a token at its commas, keeping each comma with the piece before it.
fn split_at_commas(token: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    for ch in token.chars() {
        current.push(ch);
        if ch == ',' {
            parts.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    if parts.is_empty() {
        parts.push(token.to_string());
    }
    parts
}

/// Hard-splits `text` into chunks of exactly `width` characters.
fn hard_chunks(text: &str, width: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut count = 0usize;
    for ch in text.chars() {
        if count == width {
            chunks.push(std::mem::take(&mut current));
            count = 0;
        }
        current.push(ch);
        count += 1;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// The banner and the mascot art, printed side by side as a single block.
///
/// `BANNER` stays on the left, padded to its own widest line so `ASCII_ART`
/// always starts at the same column, and the shorter drawing is centered
/// vertically against the taller one. Both widths are measured ignoring trailing
/// blank cells — ASCII whitespace and the braille blank (`U+2800`) the art pads
/// with — so the gap is exactly [`ART_GAP`] columns instead of `ART_GAP` plus
/// invisible filler.
pub fn banner_side_by_side() -> String {
    join_blocks(&split_lines(BANNER), &split_lines(ASCII_ART), ART_GAP)
}

/// Whether `cell` is invisible padding rather than drawing.
fn is_blank(cell: char) -> bool {
    cell.is_whitespace() || cell == '\u{2800}'
}

/// Splits `art` into lines, dropping each line's trailing blank cells.
///
/// Leading blanks are kept: they are part of the drawing's shape.
fn split_lines(art: &str) -> Vec<&str> {
    art.trim_end_matches(is_blank)
        .lines()
        .map(|line| line.trim_end_matches(is_blank))
        .collect()
}

/// The width of the widest line (its trailing blanks are already trimmed).
fn block_width(lines: &[&str]) -> usize {
    lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0)
}

/// Lays `left` and `right` out as two columns of one canvas, centering the
/// shorter drawing vertically against the taller one.
fn join_blocks(left: &[&str], right: &[&str], gap: usize) -> String {
    let left_width = block_width(left);
    let height = left.len().max(right.len());
    let left_top = (height - left.len()) / 2;
    let right_top = (height - right.len()) / 2;
    let separator = " ".repeat(gap);

    (0..height)
        .map(|row| {
            let left_line = row
                .checked_sub(left_top)
                .and_then(|i| left.get(i))
                .copied()
                .unwrap_or("");
            let right_line = row
                .checked_sub(right_top)
                .and_then(|i| right.get(i))
                .copied()
                .unwrap_or("");

            let mut line = String::from(left_line);
            for _ in left_line.chars().count()..left_width {
                line.push(' ');
            }
            line.push_str(&separator);
            line.push_str(right_line);
            // The right column can be shorter than the canvas, so a row may end
            // with nothing; keep trailing whitespace out of the block.
            line.trim_end().to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Draws `content` inside a box with `padding` blank cells on every side.
///
/// The border is generated rather than stored, so any block — the joined banner
/// and art, in particular — is framed by calling this. Widths are measured with
/// [`split_lines`], so trailing blank cells never widen the box.
pub fn frame(content: &str, padding: usize) -> String {
    let lines = split_lines(content);
    let width = block_width(&lines);
    let inner = width + padding * 2;
    let rule = "─".repeat(inner);
    let blank = format!("│{}│", " ".repeat(inner));

    let mut out = Vec::with_capacity(lines.len() + padding * 2 + 2);
    out.push(format!("┌{rule}┐"));
    for _ in 0..padding {
        out.push(blank.clone());
    }
    for line in &lines {
        out.push(format!(
            "│{}{line}{}│",
            " ".repeat(padding),
            " ".repeat(width - line.chars().count() + padding)
        ));
    }
    for _ in 0..padding {
        out.push(blank.clone());
    }
    out.push(format!("└{rule}┘"));
    out.join("\n")
}

/// The terminal width in columns.
///
/// Prefers the real terminal size when stdout is a TTY, then `COLUMNS` (set by
/// some shells), then a safe default of 80. Layout helpers use this to decide
/// between a wide and a stacked rendering and to wrap the Markdown page; a wrong
/// guess only costs a fallback that is always readable, and keeping `COLUMNS`
/// and the 80 default as fallbacks keeps non-interactive output deterministic.
pub(crate) fn term_width() -> usize {
    if std::io::stdout().is_terminal() {
        if let Ok((cols, _)) = crossterm::terminal::size() {
            let cols = cols as usize;
            if cols > 0 {
                return cols;
            }
        }
    }
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
            format!("  {} {:<8} {}", glyph::OK, "Read", "a.exe")
        );
        // Same column even though the labels differ in length.
        let short = ui.done("read", "v");
        let long = ui.done("encrypt", "v");
        assert_eq!(short.len(), long.len());
        // The closing result line shares the same column layout.
        assert_eq!(
            ui.result("packed", "out.exe"),
            format!("  {} {:<8} {}", glyph::OK, "Packed", "out.exe")
        );
    }

    /// Warning bars wrap and degrade to `! message` without color.
    #[test]
    fn warnings_use_a_black_on_amber_bar() {
        let plain = Palette::plain();
        assert_eq!(plain.warn_lines("short", 40), vec!["! short"]);

        let colored = Palette { color: true };
        let lines = colored.warn_lines("a warning that wraps onto a second line", 24);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| line.contains("48;2;235;166;52")));
        assert!(lines[0].starts_with('\x1b'));
        assert!(lines[0].contains("!"));
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

    /// The banner literal is embedded (not read from disk) and non-empty.
    #[test]
    fn banner_is_embedded() {
        assert!(
            BANNER.contains(glyph::BLOCK),
            "banner looks empty: {BANNER:?}"
        );
        assert_eq!(
            Palette::plain().banner(),
            frame(&banner_side_by_side(), BANNER_PADDING)
        );
    }

    /// `frame` boxes its content with the requested padding on every side.
    #[test]
    fn frame_boxes_content_with_padding() {
        assert_eq!(
            frame("ab\nc\n", 1),
            "┌────┐\n│    │\n│ ab │\n│ c  │\n│    │\n└────┘"
        );
    }

    /// The layout pads the left column to its widest line, inserts the gap and
    /// centers the shorter drawing; trailing blank cells — ASCII spaces or the
    /// braille blank the art pads with — never count toward a width.
    #[test]
    fn side_by_side_pads_gaps_and_centers_the_drawings() {
        let left = split_lines("aa \nuuub\n"); // 4 wide, 2 tall
        let right = split_lines("R\nRR\nR\n"); // 2 wide, 3 tall
        assert_eq!(join_blocks(&left, &right, 1), "aa   R\nuuub RR\n     R");

        let left = split_lines("X\n");
        let right = split_lines("1\n2\n3\n4\n");
        assert_eq!(join_blocks(&left, &right, 1), "  1\nX 2\n  3\n  4");

        assert_eq!(split_lines("ab\u{2800}\u{2800}\ncd  \n"), vec!["ab", "cd"]);
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

    /// A wrapped field value stays aligned and never exceeds the width.
    #[test]
    fn field_wrapped_indents_and_fits_continuations() {
        let value = (1..=12)
            .map(|i| format!("NtSomething{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let rendered = Palette::plain().field_wrapped("syscalls", value, 40);
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines.len() > 1, "should have wrapped: {rendered}");
        assert!(lines[0].starts_with("  syscalls"), "{rendered}");
        for line in &lines[1..] {
            assert!(
                line.starts_with(&" ".repeat(VALUE_INDENT)),
                "continuation not indented under the value: {line:?}"
            );
        }
        for line in &lines {
            assert!(line.chars().count() <= 40, "overflow: {line:?}");
        }
    }

    /// A short field value stays exactly on the single `field` line.
    #[test]
    fn field_wrapped_keeps_short_values_on_one_line() {
        let ui = Palette::plain();
        assert_eq!(
            ui.field_wrapped("requires", "windows-x64, windows-x86", 80),
            ui.field("requires", "windows-x64, windows-x86")
        );
    }

    /// A single long comma-joined token breaks at its commas, not mid-word.
    #[test]
    fn field_wrapped_breaks_long_joined_tokens() {
        let value =
            "NtAllocateVirtualMemory,NtWriteVirtualMemory,NtReadVirtualMemory,NtResumeThread";
        let rendered = Palette::plain().field_wrapped("syscalls", value, 40);
        assert!(rendered.contains("NtAllocateVirtualMemory,"), "{rendered}");
        for line in rendered.lines() {
            assert!(line.chars().count() <= 40, "overflow: {line:?}");
        }
    }
}
