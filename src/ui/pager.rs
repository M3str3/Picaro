//! Built-in alternate-screen pager.
//!
//! `picaro techniques show` hands its rendered page here. When the content is
//! taller than the terminal and stdout is a TTY, the pager draws it full screen
//! in the alternate screen and reads keys until the user quits, then restores
//! the terminal exactly where it was (a read-only `less`). Every failure path
//! falls back to plain printing, so a pager that cannot start never breaks the
//! command.

use std::io::{self, IsTerminal, Write};
use std::ops::Range;

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::style::Print;
use crossterm::terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, queue};

use crate::ui::{glyph, Palette};

/// Displays `content` (already ANSI-rendered) full-screen when it is taller
/// than the terminal, in the alternate screen so the terminal is restored on
/// quit. Returns `true` when it displayed the content itself; `false` when the
/// caller should just print it (not a TTY, content fits, or the pager could not
/// start). Never fails the caller: errors after the decision are swallowed
/// after restoring the terminal.
pub fn page(content: &str, ui: &Palette) -> bool {
    if !io::stdout().is_terminal() {
        return false;
    }
    let Ok((_, rows)) = terminal::size() else {
        return false;
    };

    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    // The last row is reserved for the status bar.
    let height = rows.saturating_sub(1) as usize;
    if height == 0 || total <= height {
        return false;
    }

    if terminal::enable_raw_mode().is_err() {
        return false;
    }
    // `screen` disables raw mode on drop, whether or not the alternate screen
    // was entered.
    let mut screen = Screen { alternate: false };
    let mut out = io::stdout();
    if execute!(out, EnterAlternateScreen, Hide).is_err() {
        return false;
    }
    screen.alternate = true;

    // The pager owns the screen from here: whatever happens during key reading,
    // `screen` restores the terminal when it drops, and we report success
    // because the content was shown.
    let _ = run(&mut out, &lines, ui, height);
    drop(screen);
    true
}

/// Restores the terminal on every exit path (including a mid-run error).
struct Screen {
    alternate: bool,
}

impl Drop for Screen {
    fn drop(&mut self) {
        if self.alternate {
            let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        }
        let _ = terminal::disable_raw_mode();
    }
}

/// The scroll/quit loop. `height` is the content height (status bar excluded).
fn run(out: &mut impl Write, lines: &[&str], ui: &Palette, mut height: usize) -> io::Result<()> {
    let total = lines.len();
    let mut offset = 0usize;

    loop {
        draw(out, lines, ui, offset, height)?;
        match event::read()? {
            // Windows reports release and repeat events too; only a press is a
            // scroll command, or every line would move twice.
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(());
                }
                KeyCode::Up | KeyCode::Char('k') => offset = offset.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => {
                    offset = (offset + 1).min(max_offset(total, height));
                }
                KeyCode::PageUp => offset = offset.saturating_sub(height),
                KeyCode::PageDown | KeyCode::Char(' ') => {
                    offset = (offset + height).min(max_offset(total, height));
                }
                KeyCode::Home | KeyCode::Char('g') => offset = 0,
                KeyCode::End | KeyCode::Char('G') => offset = max_offset(total, height),
                _ => {}
            },
            Event::Resize(_, rows) => {
                height = (rows.saturating_sub(1) as usize).max(1);
                offset = offset.min(max_offset(total, height));
            }
            _ => {}
        }
    }
}

/// Redraws the visible window and the status bar in one buffered write.
fn draw(
    out: &mut impl Write,
    lines: &[&str],
    ui: &Palette,
    offset: usize,
    height: usize,
) -> io::Result<()> {
    let total = lines.len();
    let range = visible_range(total, offset, height);
    let count = range.len();
    let mut buffer: Vec<u8> = Vec::new();

    for (row, index) in range.clone().enumerate() {
        queue!(
            buffer,
            MoveTo(0, row as u16),
            Clear(ClearType::CurrentLine),
            Print(lines[index])
        )?;
    }
    // Clear the rows a previous, taller window left behind.
    for row in count..height {
        queue!(buffer, MoveTo(0, row as u16), Clear(ClearType::CurrentLine))?;
    }

    queue!(
        buffer,
        MoveTo(0, height as u16),
        Clear(ClearType::CurrentLine),
        Print(status_line(ui, range.start, range.end, total))
    )?;

    out.write_all(&buffer)?;
    out.flush()
}

/// The window of line indices shown at `offset`, clamped so it never runs past
/// the end of the document (`total - height`, or `0` when everything fits).
fn visible_range(total: usize, offset: usize, height: usize) -> Range<usize> {
    if total == 0 || height == 0 {
        return 0..0;
    }
    let start = offset.min(max_offset(total, height));
    let end = (start + height).min(total);
    start..end
}

/// The largest scroll offset that still shows content.
fn max_offset(total: usize, height: usize) -> usize {
    total.saturating_sub(height)
}

/// The bottom status bar: `lines a–b/total · q quit`.
fn status_line(ui: &Palette, start: usize, end: usize, total: usize) -> String {
    let (first, last) = if total == 0 { (0, 0) } else { (start + 1, end) };
    format!(
        "{} {}",
        ui.faint(glyph::RULE.repeat(3)),
        ui.dim(format!(
            "lines {first}–{last}/{total} {} q quit",
            glyph::DOT
        ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_range_shows_a_full_window_at_the_top() {
        assert_eq!(visible_range(100, 0, 20), 0..20);
    }

    #[test]
    fn visible_range_clamps_the_offset_at_the_end() {
        assert_eq!(visible_range(100, 90, 20), 80..100);
    }

    #[test]
    fn visible_range_covers_documents_shorter_than_the_window() {
        assert_eq!(visible_range(5, 0, 20), 0..5);
        assert_eq!(visible_range(5, 40, 20), 0..5);
    }

    #[test]
    fn visible_range_is_empty_without_content_or_height() {
        assert_eq!(visible_range(0, 0, 20), 0..0);
        assert_eq!(visible_range(10, 0, 0), 0..0);
    }

    #[test]
    fn max_offset_never_underflows() {
        assert_eq!(max_offset(100, 20), 80);
        assert_eq!(max_offset(5, 20), 0);
    }

    #[test]
    fn status_line_reports_the_window_and_no_escapes_when_plain() {
        let status = status_line(&Palette::plain(), 19, 40, 100);
        assert!(status.contains("20–40/100"), "{status}");
        assert!(status.contains("q quit"), "{status}");
        assert!(!status.contains('\u{1b}'), "{status:?}");
    }
}
