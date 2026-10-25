use super::*;

/// The prompting primitives, backend-agnostic. Both implementations share the
/// same semantics so the wizard (and its tests) never branch on the backend.
pub(super) trait Prompt {
    /// Renders an already-styled, non-interactive line.
    fn echo(&mut self, line: &str) -> Result<()>;
    /// Single choice; returns the selected index.
    fn select(&mut self, label: &str, options: &[(&str, &str)], default: usize) -> Result<usize>;
    /// Checkbox multi-choice; returns the selected indexes, sorted.
    fn multi_select(
        &mut self,
        label: &str,
        options: &[(&str, &str)],
        default: &[usize],
    ) -> Result<Vec<usize>>;
    /// Yes/no; returns the choice.
    fn confirm(&mut self, label: &str, default: bool) -> Result<bool>;
    /// Free text; an empty answer yields `default` (or `""` when `default` is
    /// `None`). `default` is also the editable starting value.
    fn text(&mut self, label: &str, default: Option<&str>) -> Result<String>;
    /// Optional free text; an empty answer yields `None`.
    fn optional_text(&mut self, label: &str, default: Option<&str>) -> Result<Option<String>>;
}

/// Interactive backend built on [`inquire`]: menus, checkboxes and confirmations
/// rendered by the terminal. Writes the non-interactive lines to stdout.
pub(super) struct InquirePrompt {
    out: anstream::AutoStream<std::io::Stdout>,
}

impl InquirePrompt {
    pub(super) fn new() -> Self {
        Self {
            out: anstream::stdout(),
        }
    }
}

/// Maps an [`inquire`] error, treating Esc/interrupt as a clean cancellation.
fn map_inquire(error: inquire::InquireError) -> PackerError {
    match error {
        // Esc goes back one section; Ctrl-C still aborts the wizard cleanly.
        inquire::InquireError::OperationCanceled => PackerError::Back,
        inquire::InquireError::OperationInterrupted => PackerError::Cancelled,
        other => PackerError::Validation(format!("interactive prompt failed: {other}")),
    }
}

/// `"name  description"` strings for an [`inquire`] menu.
fn menu_items(options: &[(&str, &str)]) -> Vec<String> {
    options
        .iter()
        .map(|(name, description)| {
            if description.is_empty() {
                (*name).to_string()
            } else {
                format!("{name}  {description}")
            }
        })
        .collect()
}

impl Prompt for InquirePrompt {
    fn echo(&mut self, line: &str) -> Result<()> {
        writeln!(self.out, "{line}")?;
        self.out.flush()?;
        Ok(())
    }

    fn select(&mut self, label: &str, options: &[(&str, &str)], default: usize) -> Result<usize> {
        let items = menu_items(options);
        let choice = Select::new(label, items.clone())
            .with_starting_cursor(default)
            .with_page_size(12)
            .with_help_message("Esc: back \u{00b7} Up/Down: move \u{00b7} Enter: select")
            .prompt()
            .map_err(map_inquire)?;
        Ok(items
            .iter()
            .position(|item| *item == choice)
            .unwrap_or(default))
    }

    fn multi_select(
        &mut self,
        label: &str,
        options: &[(&str, &str)],
        default: &[usize],
    ) -> Result<Vec<usize>> {
        let items = menu_items(options);
        let chosen = MultiSelect::new(label, items.clone())
            .with_default(default)
            .with_page_size(12)
            .with_help_message("Esc: back \u{00b7} Space: toggle \u{00b7} Enter: confirm")
            .prompt()
            .map_err(map_inquire)?;
        let mut selected: Vec<usize> = chosen
            .iter()
            .filter_map(|item| items.iter().position(|candidate| candidate == item))
            .collect();
        selected.sort_unstable();
        selected.dedup();
        Ok(selected)
    }

    fn confirm(&mut self, label: &str, default: bool) -> Result<bool> {
        Confirm::new(label)
            .with_default(default)
            .with_help_message("Esc: back \u{00b7} Enter accepts the default")
            .prompt()
            .map_err(map_inquire)
    }

    fn text(&mut self, label: &str, default: Option<&str>) -> Result<String> {
        let mut question = Text::new(label).with_help_message(if default.is_some() {
            "Esc: back \u{00b7} Enter accepts the default"
        } else {
            "Esc: back"
        });
        if let Some(default) = default {
            question = question.with_initial_value(default).with_default(default);
        }
        let value = question.prompt().map_err(map_inquire)?;
        Ok(value.trim().to_string())
    }

    fn optional_text(&mut self, label: &str, default: Option<&str>) -> Result<Option<String>> {
        let mut question =
            Text::new(label).with_help_message("Esc: back \u{00b7} leave empty to skip");
        if let Some(default) = default {
            question = question.with_initial_value(default);
        }
        let value = question.prompt().map_err(map_inquire)?;
        let value = value.trim();
        Ok((!value.is_empty()).then(|| value.to_string()))
    }
}

/// Plain line backend: used when the input is not a terminal (redirected or
/// scripted), and by the unit tests. Prompts print a `? label [default]:` line.
pub(super) struct LinePrompt<R: BufRead, W: Write> {
    pub(super) reader: R,
    pub(super) out: W,
    pub(super) ui: Palette,
}

impl<R: BufRead, W: Write> LinePrompt<R, W> {
    /// Reads one line, failing when the input ends mid-session.
    fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(PackerError::Validation(
                "interactive input ended before the wizard finished".to_string(),
            ));
        }
        Ok(line)
    }

    /// Writes a `? label [hint]: ` prompt and flushes it before blocking.
    fn prompt_line(&mut self, label: &str, hint: Option<&str>) -> Result<()> {
        let question = self.ui.question(label);
        let hint = match hint {
            Some(hint) => format!(" {}", self.ui.dim(format!("[{hint}]"))),
            None => String::new(),
        };
        let colon = self.ui.dim(":");
        write!(self.out, "{question}{hint}{colon} ")?;
        self.out.flush()?;
        Ok(())
    }

    /// A recoverable input problem, shown before re-asking.
    fn notice(&mut self, message: &str) -> Result<()> {
        let mark = self.ui.bang();
        let text = self.ui.warn(message);
        writeln!(self.out, "    {mark} {text}")?;
        Ok(())
    }
}

impl<R: BufRead, W: Write> Prompt for LinePrompt<R, W> {
    fn echo(&mut self, line: &str) -> Result<()> {
        writeln!(self.out, "{line}")?;
        self.out.flush()?;
        Ok(())
    }

    fn select(&mut self, label: &str, options: &[(&str, &str)], default: usize) -> Result<usize> {
        let question = self.ui.question(label);
        writeln!(self.out, "{question}")?;
        for (index, (name, description)) in options.iter().enumerate() {
            let entry = self.ui.menu(index + 1, name, description);
            writeln!(self.out, "{entry}")?;
        }
        loop {
            self.prompt_line("select", Some(&(default + 1).to_string()))?;
            let line = self.read_line()?;
            if back_requested(&line) {
                return Err(PackerError::Back);
            }
            match parse_choice(line.trim(), options, default) {
                Some(index) => return Ok(index),
                None => self.notice(&format!("enter a number between 1 and {}", options.len()))?,
            }
        }
    }

    fn multi_select(
        &mut self,
        label: &str,
        options: &[(&str, &str)],
        default: &[usize],
    ) -> Result<Vec<usize>> {
        if options.is_empty() {
            return Ok(Vec::new());
        }
        let question = self.ui.question(label);
        writeln!(self.out, "{question}")?;
        for (index, (name, description)) in options.iter().enumerate() {
            let entry = self.ui.menu(index + 1, name, description);
            writeln!(self.out, "{entry}")?;
        }
        loop {
            self.prompt_line("select", Some("comma-separated, blank for none"))?;
            let line = self.read_line()?;
            if back_requested(&line) {
                return Err(PackerError::Back);
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return Ok(default.to_vec());
            }
            match parse_multi(trimmed, options) {
                Some(selected) => return Ok(selected),
                None => self.notice(&format!("enter numbers between 1 and {}", options.len()))?,
            }
        }
    }

    fn confirm(&mut self, label: &str, default: bool) -> Result<bool> {
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            self.prompt_line(label, Some(hint))?;
            let line = self.read_line()?;
            if back_requested(&line) {
                return Err(PackerError::Back);
            }
            match parse_yes_no(line.trim(), default) {
                Some(value) => return Ok(value),
                None => self.notice("please answer y or n")?,
            }
        }
    }

    fn text(&mut self, label: &str, default: Option<&str>) -> Result<String> {
        self.prompt_line(label, default)?;
        let line = self.read_line()?;
        if back_requested(&line) {
            return Err(PackerError::Back);
        }
        let answer = line.trim();
        if !answer.is_empty() {
            return Ok(answer.to_string());
        }
        Ok(default.unwrap_or("").to_string())
    }

    fn optional_text(&mut self, label: &str, default: Option<&str>) -> Result<Option<String>> {
        self.prompt_line(label, Some("blank to skip"))?;
        let line = self.read_line()?;
        if back_requested(&line) {
            return Err(PackerError::Back);
        }
        let answer = line.trim();
        if !answer.is_empty() {
            return Ok(Some(answer.to_string()));
        }
        Ok(default.map(str::to_string))
    }
}
