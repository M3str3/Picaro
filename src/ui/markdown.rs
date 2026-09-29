//! Minimal Markdown → styled terminal renderer.
//!
//! `picaro techniques show` renders each technique README through this module.
//! It understands the subset the READMEs actually use — headings, paragraphs,
//! ordered/unordered lists, GFM pipe tables, fenced code blocks, blockquotes
//! and horizontal rules — plus inline `**bold**`, `*italic*`, `_italic_`,
//! `` `code` `` and `[text](url)`.
//!
//! Every line is wrapped by its *visible* length (inline markers stripped), so
//! styled output never overflows the terminal. All styling goes through
//! [`Palette`], which means a plain palette renders plain text with no escapes.

use crate::ui::{glyph, Palette, Tone};

/// Narrowest layout the renderer will attempt. Keeps wrapping finite when the
/// caller hands over a nonsensical width.
const MIN_WIDTH: usize = 20;

/// Bound on nested inline emphasis, so a crafted document cannot recurse
/// without limit.
const MAX_INLINE_DEPTH: usize = 4;

// Box-drawing frame of a Markdown table (structural, never colored).
const TABLE_TOP_LEFT: char = '┌';
const TABLE_TOP_MID: char = '┬';
const TABLE_TOP_RIGHT: char = '┐';
const TABLE_MID_LEFT: char = '├';
const TABLE_MID_MID: char = '┼';
const TABLE_MID_RIGHT: char = '┤';
const TABLE_BOTTOM_LEFT: char = '└';
const TABLE_BOTTOM_MID: char = '┴';
const TABLE_BOTTOM_RIGHT: char = '┘';

// Corners of a fenced code block's frame.
const CODE_TOP_LEFT: char = '┌';
const CODE_BOTTOM_LEFT: char = '└';

/// Renders a Markdown document to styled terminal text wrapped to `width`
/// columns. Uses `ui` for every style, so a plain palette yields plain text.
pub fn render(markdown: &str, ui: &Palette, width: usize) -> String {
    let width = width.max(MIN_WIDTH);
    let mut out: Vec<String> = Vec::new();
    for block in parse_blocks(markdown) {
        render_block(&block, ui, width, &mut out);
    }
    finish(out)
}

/// A run of text sharing one [`Tone`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Segment {
    text: String,
    tone: Tone,
}

impl Segment {
    fn new(text: impl Into<String>, tone: Tone) -> Self {
        Self {
            text: text.into(),
            tone,
        }
    }
}

/// One rendered line: styled segments.
type Inline = Vec<Segment>;
/// A table row: one [`Inline`] per cell.
type Row = Vec<Inline>;

/// A parsed block, before it is styled.
#[derive(Debug)]
enum Block {
    Heading { level: usize, text: String },
    Paragraph(String),
    List { items: Vec<ListItem> },
    Table(Table),
    Code(Vec<String>),
    Quote(String),
    Rule,
}

/// One list item: its nesting `depth`, an ordered marker (if any) and its text.
#[derive(Debug)]
struct ListItem {
    depth: usize,
    number: Option<u32>,
    text: String,
}

/// A GFM pipe table.
#[derive(Debug)]
struct Table {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Block parsing
// ---------------------------------------------------------------------------

/// Splits the document into blocks. Blank lines only separate blocks; the
/// renderer decides the final spacing.
fn parse_blocks(markdown: &str) -> Vec<Block> {
    let lines: Vec<&str> = markdown.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }

        if fence(line).is_some() {
            i += 1;
            let mut code = Vec::new();
            while i < lines.len() && fence(lines[i]).is_none() {
                code.push(lines[i].to_string());
                i += 1;
            }
            // Skip the closing fence when present; an unterminated block ends
            // the document instead.
            if i < lines.len() {
                i += 1;
            }
            blocks.push(Block::Code(code));
            continue;
        }

        if let Some((level, text)) = heading(line) {
            blocks.push(Block::Heading {
                level,
                text: text.to_string(),
            });
            i += 1;
            continue;
        }

        if is_rule(line) {
            blocks.push(Block::Rule);
            i += 1;
            continue;
        }

        if quote(line).is_some() {
            let mut text = String::new();
            while i < lines.len() {
                let Some(rest) = quote(lines[i]) else { break };
                let rest = rest.trim();
                if !rest.is_empty() {
                    if !text.is_empty() {
                        text.push(' ');
                    }
                    text.push_str(rest);
                }
                i += 1;
            }
            blocks.push(Block::Quote(text));
            continue;
        }

        // A table starts at a row whose successor is a separator row.
        if line.contains('|') && i + 1 < lines.len() && is_separator_row(lines[i + 1]) {
            let header = split_row(line);
            i += 2;
            let mut rows = Vec::new();
            while i < lines.len() && lines[i].contains('|') && !lines[i].trim().is_empty() {
                rows.push(split_row(lines[i]));
                i += 1;
            }
            blocks.push(Block::Table(Table { header, rows }));
            continue;
        }

        if bullet(line).is_some() || ordered(line).is_some() {
            let (block, next) = parse_list(&lines, i);
            blocks.push(block);
            i = next;
            continue;
        }

        let mut text = String::new();
        while i < lines.len() {
            let current = lines[i];
            if current.trim().is_empty()
                || fence(current).is_some()
                || heading(current).is_some()
                || is_rule(current)
                || quote(current).is_some()
                || bullet(current).is_some()
                || ordered(current).is_some()
            {
                break;
            }
            if current.contains('|') && i + 1 < lines.len() && is_separator_row(lines[i + 1]) {
                break;
            }
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(current.trim());
            i += 1;
        }
        blocks.push(Block::Paragraph(text));
    }

    blocks
}

/// Parses a run of list items starting at `start`, returning the block and the
/// index of the first line after it.
fn parse_list(lines: &[&str], start: usize) -> (Block, usize) {
    let base = indent(lines[start]);
    let mut items: Vec<ListItem> = Vec::new();
    let mut i = start;

    while i < lines.len() {
        let line = lines[i];
        if line.trim().is_empty() {
            break;
        }
        let line_indent = indent(line);

        if let Some(content) = bullet(line) {
            let depth = list_depth(line_indent, base, &items);
            items.push(ListItem {
                depth,
                number: None,
                text: content.to_string(),
            });
            i += 1;
            continue;
        }
        if let Some((content, number)) = ordered(line) {
            let depth = list_depth(line_indent, base, &items);
            items.push(ListItem {
                depth,
                number: Some(number),
                text: content.to_string(),
            });
            i += 1;
            continue;
        }
        // An indented non-marker line continues the previous item.
        if line_indent > base {
            if let Some(last) = items.last_mut() {
                if !last.text.is_empty() {
                    last.text.push(' ');
                }
                last.text.push_str(line.trim());
                i += 1;
                continue;
            }
        }
        break;
    }

    (Block::List { items }, i)
}

/// Nesting depth of a marker line, capped one level below its predecessor so an
/// odd indentation cannot skip a level.
fn list_depth(line_indent: usize, base: usize, items: &[ListItem]) -> usize {
    let raw = line_indent.saturating_sub(base) / 2;
    let cap = items.last().map(|item| item.depth + 1).unwrap_or(0);
    raw.min(cap)
}

/// The info string of a fenced code line, if `line` opens or closes a fence.
fn fence(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    trimmed
        .strip_prefix("```")
        .or_else(|| trimmed.strip_prefix("~~~"))
        .map(str::trim)
}

/// `# title` → `(level, title)`.
fn heading(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    let level = trimmed.chars().take_while(|c| *c == '#').count();
    if level == 0 || level > 6 {
        return None;
    }
    let rest = &trimmed[level..];
    Some((level, rest.strip_prefix(' ').unwrap_or(rest).trim()))
}

/// `---`, `***`, `___` (3+ markers, spaces allowed) is a horizontal rule.
fn is_rule(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.chars().filter(|c| *c != ' ').count() < 3 {
        return false;
    }
    let mut marker = None;
    for ch in trimmed.chars() {
        if ch == ' ' {
            continue;
        }
        if !matches!(ch, '-' | '*' | '_') {
            return false;
        }
        match marker {
            None => marker = Some(ch),
            Some(previous) if previous == ch => {}
            Some(_) => return false,
        }
    }
    marker.is_some()
}

/// The text of a `> quote` line, with the marker stripped.
fn quote(line: &str) -> Option<&str> {
    line.trim_start().strip_prefix('>')
}

/// The text of a `- item` line, with the marker stripped.
fn bullet(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let marker = trimmed.chars().next()?;
    if !matches!(marker, '-' | '*' | '+') {
        return None;
    }
    let rest = &trimmed[marker.len_utf8()..];
    if rest.is_empty() {
        return Some("");
    }
    rest.strip_prefix(' ').map(str::trim_end)
}

/// The text and the number of a `1. item` line.
fn ordered(line: &str) -> Option<(&str, u32)> {
    let trimmed = line.trim_start();
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let rest = &trimmed[digits.len()..];
    let rest = rest.strip_prefix('.').or_else(|| rest.strip_prefix(')'))?;
    let content = rest.strip_prefix(' ')?;
    let number = digits.parse::<u32>().ok()?;
    Some((content.trim_end(), number))
}

/// Leading ASCII spaces of a line.
fn indent(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

/// Splits a table row into trimmed cells, honoring `\|` escapes and dropping
/// the empty cells a leading/trailing pipe produces.
fn split_row(line: &str) -> Vec<String> {
    let mut cells: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = line.trim().chars().peekable();
    while let Some(ch) = chars.next() {
        // A backslash only escapes a pipe or another backslash; elsewhere it is
        // literal (Windows paths in cells must survive).
        if ch == '\\' {
            match chars.peek() {
                Some('|') | Some('\\') => {
                    current.push(chars.next().unwrap_or(ch));
                }
                _ => current.push('\\'),
            }
            continue;
        }
        if ch == '|' {
            cells.push(current.trim().to_string());
            current.clear();
            continue;
        }
        current.push(ch);
    }
    cells.push(current.trim().to_string());

    if cells.first().is_some_and(String::is_empty) {
        cells.remove(0);
    }
    if cells.last().is_some_and(String::is_empty) {
        cells.pop();
    }
    cells
}

/// Whether `line` is a GFM separator row (`|---|---|`).
fn is_separator_row(line: &str) -> bool {
    if !line.contains('|') {
        return false;
    }
    let cells = split_row(line);
    !cells.is_empty() && cells.iter().all(|cell| is_dashes(cell))
}

/// Whether a table cell is a `---`, `:--` or `--:` alignment marker.
fn is_dashes(cell: &str) -> bool {
    let trimmed = cell.trim();
    let trimmed = trimmed.strip_prefix(':').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix(':').unwrap_or(trimmed);
    !trimmed.is_empty() && trimmed.chars().all(|c| c == '-')
}

// ---------------------------------------------------------------------------
// Block rendering
// ---------------------------------------------------------------------------

fn render_block(block: &Block, ui: &Palette, width: usize, out: &mut Vec<String>) {
    match block {
        Block::Heading { level, text } => render_heading(*level, text, ui, width, out),
        Block::Paragraph(text) => {
            blank(out);
            emit(ui, &parse_inline(text), &[], &[], width, out);
        }
        Block::List { items } => render_list(items, ui, width, out),
        Block::Table(table) => render_table(table, ui, width, out),
        Block::Code(code) => render_code(code, ui, out),
        Block::Quote(text) => render_quote(text, ui, width, out),
        Block::Rule => {
            blank(out);
            out.push(ui.rule(width));
        }
    }
}

/// Starts a new block with one blank separator line (never leading).
fn blank(out: &mut Vec<String>) {
    if out.last().is_some_and(|line| !line.is_empty()) {
        out.push(String::new());
    }
}

fn render_heading(level: usize, text: &str, ui: &Palette, width: usize, out: &mut Vec<String>) {
    blank(out);
    let inline = parse_inline(text);
    match level {
        1 => emit(ui, &rebase(inline, Tone::Brand), &[], &[], width, out),
        2 => {
            let mut content = vec![Segment::new(format!("{} ", glyph::BULLET), Tone::Brand)];
            content.extend(rebase(inline, Tone::Brand));
            emit(ui, &content, &[], &[], width, out);
            out.push(ui.rule(width));
        }
        _ => {
            let indent = vec![Segment::new("  ", Tone::Value)];
            emit(
                ui,
                &rebase(inline, Tone::Bold),
                &indent,
                &indent,
                width,
                out,
            );
        }
    }
}

fn render_list(items: &[ListItem], ui: &Palette, width: usize, out: &mut Vec<String>) {
    blank(out);
    for item in items {
        let pad = 2 + item.depth * 2;
        let mut first = vec![Segment::new(" ".repeat(pad), Tone::Value)];
        match item.number {
            Some(number) => first.push(Segment::new(format!("{number}. "), Tone::Dim)),
            None => first.push(Segment::new(format!("{} ", glyph::LIST), Tone::Dim)),
        }
        // Continuation lines align under the item text.
        let cont = vec![Segment::new(" ".repeat(visible_len(&first)), Tone::Value)];
        emit(ui, &parse_inline(&item.text), &first, &cont, width, out);
    }
}

fn render_quote(text: &str, ui: &Palette, width: usize, out: &mut Vec<String>) {
    blank(out);
    let inline = rebase(parse_inline(text), Tone::Dim);
    let prefix = vec![
        Segment::new("  ", Tone::Value),
        Segment::new(format!("{} ", glyph::BAR), Tone::Faint),
    ];
    emit(ui, &inline, &prefix, &prefix, width, out);
}

fn render_code(code: &[String], ui: &Palette, out: &mut Vec<String>) {
    blank(out);
    out.push(format!(
        "  {}",
        ui.faint(format!("{CODE_TOP_LEFT}{}", glyph::RULE))
    ));
    for line in code {
        out.push(format!("  {} {}", ui.faint(glyph::BAR), ui.code(line)));
    }
    out.push(format!(
        "  {}",
        ui.faint(format!("{CODE_BOTTOM_LEFT}{}", glyph::RULE))
    ));
}

fn render_table(table: &Table, ui: &Palette, width: usize, out: &mut Vec<String>) {
    blank(out);
    let columns = table.header.len();
    if columns == 0 {
        return;
    }

    let header: Row = table
        .header
        .iter()
        .map(|cell| rebase(parse_inline(cell), Tone::Bold))
        .collect();
    let rows: Vec<Row> = table
        .rows
        .iter()
        .map(|row| {
            (0..columns)
                .map(|c| parse_inline(row.get(c).map(String::as_str).unwrap_or("")))
                .collect()
        })
        .collect();

    // Column widths are the widest visible cell, squeezed to fit `width` when
    // the natural table would be too wide.
    let mut widths: Vec<usize> = header.iter().map(|cell| visible_len(cell)).collect();
    for row in &rows {
        for (column, cell) in widths.iter_mut().zip(row) {
            *column = (*column).max(visible_len(cell));
        }
    }
    let overhead = 3 * columns + 1;
    let available = width.saturating_sub(overhead).max(columns);
    while widths.iter().sum::<usize>() > available {
        let Some((index, _)) = widths
            .iter()
            .enumerate()
            .filter(|(_, column)| **column > 1)
            .max_by_key(|(_, column)| **column)
        else {
            break;
        };
        widths[index] -= 1;
    }

    out.push(border(
        TABLE_TOP_LEFT,
        TABLE_TOP_MID,
        TABLE_TOP_RIGHT,
        &widths,
        ui,
    ));
    push_row(&header, &widths, ui, out);
    out.push(border(
        TABLE_MID_LEFT,
        TABLE_MID_MID,
        TABLE_MID_RIGHT,
        &widths,
        ui,
    ));
    for row in &rows {
        push_row(row, &widths, ui, out);
    }
    out.push(border(
        TABLE_BOTTOM_LEFT,
        TABLE_BOTTOM_MID,
        TABLE_BOTTOM_RIGHT,
        &widths,
        ui,
    ));
}

/// A table border line: `┌───┬───┐`.
fn border(left: char, middle: char, right: char, widths: &[usize], ui: &Palette) -> String {
    let cells: Vec<String> = widths
        .iter()
        .map(|column| glyph::RULE.repeat(column + 2))
        .collect();
    ui.faint(format!("{left}{}{right}", cells.join(&middle.to_string())))
}

/// One physical table row: cells wrapped and padded to their column width, so a
/// wrapped row keeps its frame.
fn push_row(cells: &Row, widths: &[usize], ui: &Palette, out: &mut Vec<String>) {
    let wrapped: Vec<Row> = cells
        .iter()
        .zip(widths)
        .map(|(cell, width)| wrap(cell, (*width).max(1)))
        .collect();
    let height = wrapped.iter().map(Vec::len).max().unwrap_or(1).max(1);

    for line_index in 0..height {
        let mut line = String::new();
        line.push_str(&ui.faint(glyph::BAR.to_string()));
        for (cell, width) in wrapped.iter().zip(widths) {
            let empty: Inline = Vec::new();
            let content = cell.get(line_index).unwrap_or(&empty);
            let visible = visible_len(content);
            line.push(' ');
            line.push_str(&render_line(ui, content));
            line.push_str(&" ".repeat(width.saturating_sub(visible)));
            line.push(' ');
            line.push_str(&ui.faint(glyph::BAR.to_string()));
        }
        out.push(line);
    }
}

/// Wraps `content` to `width`, then prefixes the first line with `first` and the
/// continuations with `cont` (aligned under the content).
fn emit(
    ui: &Palette,
    content: &[Segment],
    first: &[Segment],
    cont: &[Segment],
    width: usize,
    out: &mut Vec<String>,
) {
    let lead = visible_len(first).max(visible_len(cont));
    let content_width = width.saturating_sub(lead).max(1);
    for (index, line) in wrap(content, content_width).iter().enumerate() {
        let prefix = if index == 0 { first } else { cont };
        let mut full: Inline = Vec::with_capacity(prefix.len() + line.len());
        full.extend_from_slice(prefix);
        full.extend_from_slice(line);
        out.push(render_line(ui, &full));
    }
}

/// Collapses blank runs, trims trailing blanks and ends with exactly one `\n`.
fn finish(lines: Vec<String>) -> String {
    let mut result: Vec<String> = Vec::new();
    let mut previous_blank = true;
    for line in lines {
        if line.trim().is_empty() {
            if !previous_blank {
                result.push(String::new());
            }
            previous_blank = true;
        } else {
            result.push(line);
            previous_blank = false;
        }
    }
    while result.last().is_some_and(String::is_empty) {
        result.pop();
    }
    if result.is_empty() {
        return String::new();
    }
    let mut text = result.join("\n");
    text.push('\n');
    text
}

// ---------------------------------------------------------------------------
// Inline parsing and wrapping
// ---------------------------------------------------------------------------

/// Parses a line of inline Markdown into styled segments.
fn parse_inline(text: &str) -> Inline {
    let mut out = Inline::new();
    parse_inline_into(text, 0, &mut out);
    out
}

/// The recursive workhorse of [`parse_inline`]: `depth` bounds nested emphasis.
fn parse_inline_into(text: &str, depth: usize, out: &mut Inline) {
    if depth > MAX_INLINE_DEPTH {
        push_text(out, text, Tone::Value);
        return;
    }

    let mut plain = String::new();
    let mut rest = text;
    while let Some(ch) = rest.chars().next() {
        if ch == '`' {
            let after = &rest[1..];
            if let Some(end) = after.find('`') {
                flush(&mut plain, out);
                push_text(out, &after[..end], Tone::Code);
                rest = &after[end + 1..];
                continue;
            }
        }

        if rest.starts_with("**") {
            let after = &rest[2..];
            if let Some(end) = after.find("**") {
                flush(&mut plain, out);
                let mut inner = Inline::new();
                parse_inline_into(&after[..end], depth + 1, &mut inner);
                out.extend(rebase(inner, Tone::Bold));
                rest = &after[end + 2..];
                continue;
            }
        }

        if ch == '[' {
            if let Some((label, url, consumed)) = parse_link(rest) {
                flush(&mut plain, out);
                let mut inner = Inline::new();
                parse_inline_into(label, depth + 1, &mut inner);
                out.extend(rebase(inner, Tone::Link));
                push_text(out, &format!(" ({url})"), Tone::Dim);
                rest = &rest[consumed..];
                continue;
            }
        }

        if ch == '*' || ch == '_' {
            let wordy_before = last_visible_char(out, &plain).is_some_and(char::is_alphanumeric);
            if !wordy_before {
                let after = &rest[1..];
                if let Some(end) = after.find(ch) {
                    let wordy_after = after[end + 1..]
                        .chars()
                        .next()
                        .is_some_and(char::is_alphanumeric);
                    if end > 0 && !wordy_after {
                        flush(&mut plain, out);
                        let mut inner = Inline::new();
                        parse_inline_into(&after[..end], depth + 1, &mut inner);
                        out.extend(rebase(inner, Tone::Italic));
                        rest = &after[end + 1..];
                        continue;
                    }
                }
            }
        }

        plain.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    flush(&mut plain, out);
}

/// Parses `[label](url)` at the start of `rest`, returning the label, the URL
/// and how many bytes of `rest` were consumed.
fn parse_link(rest: &str) -> Option<(&str, &str, usize)> {
    let after = rest.strip_prefix('[')?;
    let close = after.find("](")?;
    let label = &after[..close];
    let url_part = &after[close + 2..];
    let paren = url_part.find(')')?;
    let url = &url_part[..paren];
    Some((label, url, 1 + close + 2 + paren + 1))
}

/// Appends `text` under `tone`, merging with a preceding same-tone segment.
fn push_text(out: &mut Inline, text: &str, tone: Tone) {
    if text.is_empty() {
        return;
    }
    if let Some(last) = out.last_mut() {
        if last.tone == tone {
            last.text.push_str(text);
            return;
        }
    }
    out.push(Segment::new(text, tone));
}

/// Flushes the pending plain run.
fn flush(plain: &mut String, out: &mut Inline) {
    if !plain.is_empty() {
        push_text(out, plain, Tone::Value);
        plain.clear();
    }
}

/// The last visible character emitted so far (pending plain run or styled
/// segment), used to guard `_italic_` against identifiers like `min_uptime_min`.
fn last_visible_char<'a>(out: &'a [Segment], plain: &'a str) -> Option<char> {
    plain
        .chars()
        .last()
        .or_else(|| out.last().and_then(|segment| segment.text.chars().last()))
}

/// Re-tags plain runs (and only those), so emphasis wraps inline code without
/// flattening it.
fn rebase(segments: Inline, tone: Tone) -> Inline {
    segments
        .into_iter()
        .map(|segment| {
            if segment.tone == Tone::Value {
                Segment {
                    text: segment.text,
                    tone,
                }
            } else {
                segment
            }
        })
        .collect()
}

/// Wraps `content` to `width` visible columns, breaking on whitespace and
/// hard-breaking a word longer than the line.
fn wrap(content: &[Segment], width: usize) -> Vec<Inline> {
    let width = width.max(1);
    let mut lines: Vec<Inline> = Vec::new();
    let mut line: Inline = Vec::new();
    let mut line_width = 0usize;

    for word in split_words(content) {
        let word_width = visible_len(&word);
        if !line.is_empty() && line_width + 1 + word_width > width {
            lines.push(std::mem::take(&mut line));
            line_width = 0;
        }
        if line.is_empty() {
            if word_width <= width {
                line = word;
                line_width = word_width;
            } else {
                let mut chunks = hard_break(word, width);
                let tail = chunks.pop().unwrap_or_default();
                lines.append(&mut chunks);
                line = tail;
                line_width = visible_len(&line);
            }
        } else {
            line.push(Segment::new(" ", Tone::Value));
            line.extend(word);
            line_width += 1 + word_width;
        }
    }

    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Splits styled content into words, preserving each word's tones so a word
/// split across segments (`**Key**:`) never breaks in the middle.
fn split_words(content: &[Segment]) -> Vec<Inline> {
    let mut words: Vec<Inline> = Vec::new();
    let mut current: Inline = Vec::new();
    for segment in content {
        let mut run = String::new();
        for ch in segment.text.chars() {
            if ch.is_whitespace() {
                if !run.is_empty() {
                    current.push(Segment::new(std::mem::take(&mut run), segment.tone));
                }
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            } else {
                run.push(ch);
            }
        }
        if !run.is_empty() {
            current.push(Segment::new(run, segment.tone));
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Splits a word wider than `width` into chunks of at most `width` characters.
fn hard_break(word: Inline, width: usize) -> Vec<Inline> {
    let width = width.max(1);
    let mut chunks: Vec<Inline> = Vec::new();
    let mut chunk: Inline = Vec::new();
    let mut count = 0usize;
    for segment in word {
        for ch in segment.text.chars() {
            if count == width {
                chunks.push(std::mem::take(&mut chunk));
                count = 0;
            }
            push_char(&mut chunk, ch, segment.tone);
            count += 1;
        }
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    chunks
}

/// Appends one character to `chunk`, merging with a preceding same-tone run.
fn push_char(chunk: &mut Inline, ch: char, tone: Tone) {
    if let Some(last) = chunk.last_mut() {
        if last.tone == tone {
            last.text.push(ch);
            return;
        }
    }
    chunk.push(Segment::new(ch.to_string(), tone));
}

/// The number of visible columns of a styled line.
fn visible_len(segments: &[Segment]) -> usize {
    segments
        .iter()
        .map(|segment| segment.text.chars().count())
        .sum()
}

/// Renders a styled line, applying each segment's tone through the palette.
fn render_line(ui: &Palette, segments: &[Segment]) -> String {
    let mut out = String::new();
    for segment in segments {
        out.push_str(&style(ui, segment));
    }
    out
}

/// Styles one segment, routing the inline-format tones through the palette's
/// named helpers.
fn style(ui: &Palette, segment: &Segment) -> String {
    match segment.tone {
        Tone::Bold => ui.bold(&segment.text),
        Tone::Italic => ui.italic(&segment.text),
        Tone::Code => ui.code(&segment.text),
        Tone::Link => ui.link(&segment.text),
        other => ui.tone(other, &segment.text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(markdown: &str) -> String {
        render(markdown, &Palette::plain(), 80)
    }

    #[test]
    fn headings_render_without_hashes() {
        let out = plain("## What it does\n\nRuns it.\n");
        assert!(out.contains("What it does"), "{out}");
        assert!(!out.contains("##"), "{out}");
    }

    #[test]
    fn bullets_use_a_list_marker() {
        let out = plain("- first\n- second\n");
        assert!(out.contains(glyph::LIST), "{out}");
        assert!(out.contains("first") && out.contains("second"), "{out}");
        assert!(!out.contains("- first"), "{out}");
    }

    #[test]
    fn tables_are_boxed() {
        let out = plain("| A | B |\n|---|---|\n| 1 | 2 |\n");
        assert!(out.contains(TABLE_TOP_LEFT), "{out}");
        assert!(out.contains(glyph::BAR), "{out}");
        assert!(out.contains('A') && out.contains('1'), "{out}");
        assert!(!out.contains("|---|"), "{out}");
    }

    #[test]
    fn code_fences_are_stripped() {
        let out = plain("```yaml\nruntime: []\n```\n");
        assert!(!out.contains("```"), "{out}");
        assert!(!out.contains("yaml"), "{out}");
        assert!(out.contains("runtime: []"), "{out}");
    }

    #[test]
    fn inline_markers_are_consumed() {
        let out = plain("A **bold** and `code` word.\n");
        assert!(out.contains("bold"), "{out}");
        assert!(out.contains("code"), "{out}");
        assert!(!out.contains("**"), "{out}");
        assert!(!out.contains('`'), "{out}");
    }

    #[test]
    fn paragraphs_wrap_within_the_width() {
        let text = "word ".repeat(60);
        let width = 40;
        let out = render(text.trim(), &Palette::plain(), width);
        assert!(out.lines().count() > 1, "{out}");
        for line in out.lines() {
            assert!(line.chars().count() <= width, "overflow: {line:?}");
        }
    }

    #[test]
    fn list_continuation_aligns_under_the_text() {
        let out = plain(
            "- a very long bullet that has to wrap across more than one line because it is long\n",
        );
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.len() >= 2, "{out}");
        assert!(lines[1].starts_with("    "), "{:?}", lines[1]);
        assert!(!lines[1].trim_start().starts_with(glyph::LIST), "{out}");
    }

    #[test]
    fn quote_lines_use_a_gutter() {
        let out = plain("> quoted **text**\n> continues\n");
        assert!(out.contains(glyph::BAR), "{out}");
        assert!(out.contains("quoted"), "{out}");
        assert!(out.contains("continues"), "{out}");
    }

    #[test]
    fn horizontal_rules_render() {
        let out = plain("a\n\n---\n\nb\n");
        assert!(out.contains(glyph::RULE), "{out}");
    }

    #[test]
    fn nested_lists_indent() {
        let out = plain("- outer\n  - inner\n");
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("  "), "{out}");
        assert!(lines[1].starts_with("    "), "{out}");
    }

    #[test]
    fn identifiers_with_underscores_stay_plain() {
        let out = plain("Set min_uptime_min and max_ram_mb now.\n");
        assert!(out.contains("min_uptime_min"), "{out}");
        assert!(out.contains("max_ram_mb"), "{out}");
    }

    #[test]
    fn plain_palette_emits_no_escapes() {
        let out = plain(
            "# T\n\n## S\n\n- a `b` **c**\n\n| A |\n|---|\n| 1 |\n\n> q\n\n```rust\nlet x = 1;\n```\n",
        );
        assert!(!out.contains('\u{1b}'), "{out:?}");
    }

    #[test]
    fn colored_palette_emits_escapes() {
        let out = render("# Title\n\n**bold**\n", &Palette { color: true }, 80);
        assert!(out.contains('\u{1b}'), "{out:?}");
    }

    #[test]
    fn table_cells_keep_windows_paths() {
        let out = plain("| Path |\n|---|\n| `C:\\Windows\\System32\\svchost.exe` |\n");
        assert!(out.contains("C:\\Windows\\System32\\svchost.exe"), "{out}");
    }

    #[test]
    fn table_cells_unescape_pipes() {
        let out = plain("| Mode |\n|---|\n| `all` \\| `any` |\n");
        assert!(out.contains("all") && out.contains("any"), "{out}");
        assert!(out.contains('|'), "{out}");
    }

    #[test]
    fn empty_input_renders_empty() {
        assert_eq!(plain(""), "");
        assert_eq!(plain("\n\n"), "");
    }
}
