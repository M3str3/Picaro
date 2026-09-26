//! Interactive `build` wizard (`batesian build interactive <payload>`).
//!
//! The wizard walks through the same decisions a schema YAML encodes (payload,
//! techniques, stub and output), assembles a [`Config`], shows it and writes it.
//! It then hands the file back to the normal build flow, so the generated YAML
//! is the single source of truth: editing it and running `batesian build <file>`
//! reproduces the build without any prompts.
//!
//! When stdin/stdout is a terminal the questions are rendered with
//! [`inquire`](https://docs.rs/inquire) — arrow-key menus, checkbox multi-selects
//! and confirmations — so choosing a technique is a matter of moving a cursor,
//! not typing numbers. The answers feed a final **review** screen
//! (`Build` / `Edit` / `Quit`); choosing `Edit` re-runs the questions with the
//! previous answers as the defaults, so a mistake is one cursor move away, never
//! a restart.
//!
//! The prompting primitives live behind the [`Prompt`] trait with two backends:
//! [`InquirePrompt`] for a real terminal and [`LinePrompt`] (a plain line reader)
//! for redirected or scripted input. That keeps the whole session testable: the
//! same wizard logic runs against `Cursor`/`Vec` in the unit tests.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use inquire::{Confirm, MultiSelect, Select, Text};

use crate::config::schema::{
    Arch, BuildConfig, Config, CryptoAlgorithm, CryptoConfig, KeySource, OutputConfig,
    PayloadConfig, StubConfig, Subsystem, TrimPaths, SUPPORTED_SCHEMA,
};
use crate::config::validate;
use crate::engine::args::ArgsMode;
use crate::engine::obfuscation::YamlStringsConfig;
use crate::engine::syscalls::YamlSyscallsConfig;
use crate::error::{PackerError, Result};
use crate::techniques::{
    self, anti_debug, bouncer, patch_amsi, patch_etw, process_hollowing, sleep_obfuscation,
    Category, RuntimeStep, TechniqueDef,
};
use crate::ui::Palette;

/// Runs the wizard against stdin/stdout, picking the prompt backend by whether
/// both streams are a terminal.
///
/// Returns the path of the written YAML, or `None` when the operator quit the
/// review screen without writing. The payload path is checked before the first
/// question so a typo fails before a dozen prompts.
pub fn run(payload: &Path, config_out: Option<&Path>, ui: &Palette) -> Result<Option<PathBuf>> {
    if !payload.is_file() {
        return Err(PackerError::Validation(format!(
            "payload does not exist: {}",
            payload.display()
        )));
    }

    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut prompts: Box<dyn Prompt> = if interactive {
        Box::new(InquirePrompt::new())
    } else {
        Box::new(LinePrompt {
            reader: std::io::stdin().lock(),
            out: anstream::stdout(),
            ui: *ui,
        })
    };

    run_wizard(payload, config_out, ui, prompts.as_mut())
}

/// Testable core of [`run`]: runs the wizard over `reader`/`out` with the plain
/// line backend, so unit tests can script a whole session.
#[cfg(test)]
fn run_with<R: BufRead, W: Write>(
    payload: &Path,
    config_out: Option<&Path>,
    ui: &Palette,
    reader: R,
    out: W,
) -> Result<Option<PathBuf>> {
    let mut line = LinePrompt {
        reader,
        out,
        ui: *ui,
    };
    run_wizard(payload, config_out, ui, &mut line)
}

/// Shared wizard flow, independent of the prompt backend.
fn run_wizard(
    payload: &Path,
    config_out: Option<&Path>,
    ui: &Palette,
    prompts: &mut dyn Prompt,
) -> Result<Option<PathBuf>> {
    let mut wizard = Wizard {
        ui: *ui,
        prompts,
        payload: payload.to_path_buf(),
        config_out: config_out.map(Path::to_path_buf),
    };

    wizard.echo(&ui.command_line("build interactive", payload.display()))?;
    wizard.blank()?;

    // First pass, then a review loop: build, or re-ask with the previous answers
    // as the defaults, or quit.
    let mut answers = wizard.ask_all(None)?;
    loop {
        let config = assemble(payload, &answers);
        validate::validate(&config)?;
        let yaml = serde_yml::to_string(&config).map_err(|source| {
            PackerError::Validation(format!(
                "could not serialize the generated config: {source}"
            ))
        })?;

        wizard.blank()?;
        wizard.section("CONFIG")?;
        let preview = wizard.ui.dim(yaml.trim_end());
        wizard.echo(&preview)?;
        wizard.blank()?;

        match wizard.prompts.select(
            "what now",
            &[
                ("build now", "write the config and run the build"),
                ("edit answers", "go back and change something"),
                ("quit", "discard and exit"),
            ],
            0,
        )? {
            0 => {
                let path = write_config(&config, &yaml, wizard.config_out.as_deref())?;
                wizard.blank()?;
                let line = wizard.ui.done("config", wizard.ui.target(path.display()));
                wizard.echo(&line)?;
                wizard.blank()?;
                return Ok(Some(path));
            }
            1 => answers = wizard.ask_all(Some(&answers))?,
            _ => {
                wizard.blank()?;
                let mark = wizard.ui.bang();
                let message = wizard.ui.warn("quit; nothing was written");
                wizard.echo(&format!("  {mark} {message}"))?;
                return Ok(None);
            }
        }
    }
}

/// Writes the serialized config to disk, creating the parent directory, and
/// returns the path it was written to.
fn write_config(config: &Config, yaml: &str, config_out: Option<&Path>) -> Result<PathBuf> {
    let path = config_out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("dist").join(format!("{}.yaml", config.name)));
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, yaml)?;
    Ok(path)
}

/// All the raw answers the wizard collects, kept separate from the assembled
/// [`Config`] so a review pass can seed each field's default from its previous
/// value.
#[derive(Debug, Clone)]
struct Answers {
    name: String,
    payload_args: Vec<String>,
    execution: RuntimeStep,
    preparations: Vec<RuntimeStep>,
    strings_strategy: String,
    syscalls_mode: String,
    output_path: String,
    strip: bool,
    trim_paths: TrimPaths,
}

/// The prompting primitives, backend-agnostic. Both implementations share the
/// same semantics so the wizard (and its tests) never branch on the backend.
trait Prompt {
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
struct InquirePrompt {
    out: anstream::AutoStream<std::io::Stdout>,
}

impl InquirePrompt {
    fn new() -> Self {
        Self {
            out: anstream::stdout(),
        }
    }
}

/// Maps an [`inquire`] error, treating Esc/interrupt as a clean cancellation.
fn map_inquire(error: inquire::InquireError) -> PackerError {
    match error {
        inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted => {
            PackerError::Cancelled
        }
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
            .prompt()
            .map_err(map_inquire)
    }

    fn text(&mut self, label: &str, default: Option<&str>) -> Result<String> {
        let mut question = Text::new(label);
        if let Some(default) = default {
            question = question.with_initial_value(default).with_default(default);
        }
        let value = question.prompt().map_err(map_inquire)?;
        Ok(value.trim().to_string())
    }

    fn optional_text(&mut self, label: &str, default: Option<&str>) -> Result<Option<String>> {
        let mut question = Text::new(label).with_help_message("leave empty to skip");
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
struct LinePrompt<R: BufRead, W: Write> {
    reader: R,
    out: W,
    ui: Palette,
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
            match parse_yes_no(line.trim(), default) {
                Some(value) => return Ok(value),
                None => self.notice("please answer y or n")?,
            }
        }
    }

    fn text(&mut self, label: &str, default: Option<&str>) -> Result<String> {
        self.prompt_line(label, default)?;
        let line = self.read_line()?;
        let answer = line.trim();
        if !answer.is_empty() {
            return Ok(answer.to_string());
        }
        Ok(default.unwrap_or("").to_string())
    }

    fn optional_text(&mut self, label: &str, default: Option<&str>) -> Result<Option<String>> {
        self.prompt_line(label, Some("blank to skip"))?;
        let line = self.read_line()?;
        let answer = line.trim();
        if !answer.is_empty() {
            return Ok(Some(answer.to_string()));
        }
        Ok(default.map(str::to_string))
    }
}

/// The wizard: the prompt backend plus the [`Palette`] for its own headings.
struct Wizard<'a> {
    ui: Palette,
    prompts: &'a mut dyn Prompt,
    payload: PathBuf,
    config_out: Option<PathBuf>,
}

impl Wizard<'_> {
    fn blank(&mut self) -> Result<()> {
        self.prompts.echo("")
    }

    fn echo(&mut self, line: &str) -> Result<()> {
        self.prompts.echo(line)
    }

    fn section(&mut self, title: &str) -> Result<()> {
        let heading = self.ui.heading(title);
        self.prompts.echo(&heading)
    }

    fn echo_field(&mut self, label: &str, value: &str) -> Result<()> {
        let line = self.ui.field(label, self.ui.dim(value));
        self.prompts.echo(&line)
    }

    /// A recoverable input problem, shown before re-asking.
    fn notice(&mut self, message: &str) -> Result<()> {
        let mark = self.ui.bang();
        let text = self.ui.warn(message);
        self.echo(&format!("    {mark} {text}"))
    }

    /// Asks a required text field; an empty answer falls back to `default`.
    fn ask_text(&mut self, label: &str, default: &str) -> Result<String> {
        let value = self.prompts.text(label, Some(default))?;
        if value.is_empty() {
            Ok(default.to_string())
        } else {
            Ok(value)
        }
    }

    fn ask_optional_text(&mut self, label: &str, default: Option<&str>) -> Result<Option<String>> {
        self.prompts.optional_text(label, default)
    }

    fn ask_list(&mut self, label: &str, previous: &[String]) -> Result<Vec<String>> {
        let default = previous.join(", ");
        let value = if default.is_empty() {
            self.prompts.text(label, None)?
        } else {
            self.prompts.text(label, Some(&default))?
        };
        Ok(split_list(&value))
    }

    fn ask_number(&mut self, label: &str, default: u64, min: u64, max: u64) -> Result<u64> {
        loop {
            let value = self.prompts.text(label, Some(&default.to_string()))?;
            match parse_number(&value, default, min, max) {
                Some(number) => return Ok(number),
                None => self.notice(&format!("enter a number between {min} and {max}"))?,
            }
        }
    }

    fn ask_optional_number(
        &mut self,
        label: &str,
        max: u64,
        previous: Option<u32>,
    ) -> Result<Option<u32>> {
        loop {
            let default = previous
                .map(|value| value.to_string())
                .unwrap_or_else(|| "0".to_string());
            let value = self.prompts.text(label, Some(&default))?;
            match parse_number(&value, 0, 0, max) {
                Some(0) => return Ok(None),
                Some(number) => return Ok(Some(number as u32)),
                None => self.notice(&format!("enter a number between 0 and {max}"))?,
            }
        }
    }

    /// Collects every field, seeding defaults from `previous` on a review pass.
    fn ask_all(&mut self, previous: Option<&Answers>) -> Result<Answers> {
        self.blank()?;
        self.section("PAYLOAD")?;
        self.echo_field("source", &self.payload.display().to_string())?;

        let default_name = previous
            .map(|answers| answers.name.clone())
            .unwrap_or_else(|| default_name(&self.payload));
        let name = self.ask_text("name", &default_name)?;

        let payload_args = self.ask_list(
            "payload args (comma-separated)",
            previous.map_or(&[], |answers| answers.payload_args.as_slice()),
        )?;

        self.section("TECHNIQUES")?;
        let execution = self.ask_execution(previous.map(|answers| &answers.execution))?;
        let preparations = self.ask_preparations(
            previous.map_or(&[][..], |answers| answers.preparations.as_slice()),
        )?;

        self.section("STUB")?;
        let strings_strategy = match self.ask_select(
            "strings",
            &[
                ("xor", "single-byte XOR per string, with a random key"),
                ("stack", "decoder-free, built on the stack"),
            ],
            previous
                .map(|answers| usize::from(answers.strings_strategy == "stack"))
                .unwrap_or(0),
        )? {
            0 => "xor".to_string(),
            _ => "stack".to_string(),
        };
        let default_syscalls = previous
            .map(|answers| usize::from(answers.syscalls_mode == "indirect"))
            .unwrap_or_else(|| {
                usize::from(
                    techniques::find(execution.name()).is_some_and(|def| !def.syscalls.is_empty()),
                )
            });
        let syscalls_mode = match self.ask_select(
            "syscalls",
            &[
                ("none", "call the Win32 APIs directly"),
                ("indirect", "resolve SSNs and invoke the kernel directly"),
            ],
            default_syscalls,
        )? {
            0 => "none".to_string(),
            _ => "indirect".to_string(),
        };

        self.section("OUTPUT")?;
        let default_output = previous
            .map(|answers| answers.output_path.clone())
            .unwrap_or_else(|| format!("./dist/{name}_packed.exe"));
        let output_path = self.ask_text("output path", &default_output)?;
        let strip = self.prompts.confirm(
            "strip symbols",
            previous.is_none_or(|answers| answers.strip),
        )?;
        let trim_paths = match self.ask_select(
            "trim paths",
            &[
                ("all", "remap every absolute path in the debug info"),
                ("none", "leave paths untouched"),
                ("relative", "remap only paths outside the project"),
            ],
            previous
                .map(|answers| trim_index(answers.trim_paths))
                .unwrap_or(0),
        )? {
            0 => TrimPaths::All,
            1 => TrimPaths::None,
            _ => TrimPaths::Relative,
        };

        Ok(Answers {
            name,
            payload_args,
            execution,
            preparations,
            strings_strategy,
            syscalls_mode,
            output_path,
            strip,
            trim_paths,
        })
    }

    fn ask_select(
        &mut self,
        label: &str,
        options: &[(&str, &str)],
        default: usize,
    ) -> Result<usize> {
        self.prompts.select(label, options, default)
    }

    /// Asks for the execution technique and its parameters.
    fn ask_execution(&mut self, previous: Option<&RuntimeStep>) -> Result<RuntimeStep> {
        let choices = execution_defs();
        let options = describe(&choices);
        let default = previous
            .and_then(|step| choices.iter().position(|def| def.name == step.name()))
            .unwrap_or_else(|| {
                choices
                    .iter()
                    .position(|def| def.name == "reflective_loading")
                    .unwrap_or(0)
            });
        let index = self.prompts.select("execution", &options, default)?;
        let def = choices[index];
        let previous = previous.filter(|step| step.name() == def.name);

        match def.name {
            "process_hollowing" => {
                let default_target = match previous {
                    Some(RuntimeStep::ProcessHollowing { params }) => params.target.clone(),
                    _ => process_hollowing::default_target(),
                };
                let target = self.ask_text("target", &default_target)?;
                Ok(RuntimeStep::ProcessHollowing {
                    params: process_hollowing::Params { target },
                })
            }
            _ => default_step(def),
        }
    }

    /// Asks which preparations to apply, then each one's parameters.
    fn ask_preparations(&mut self, previous: &[RuntimeStep]) -> Result<Vec<RuntimeStep>> {
        let choices = preparation_defs();
        let options = describe(&choices);
        let default: Vec<usize> = choices
            .iter()
            .enumerate()
            .filter(|(_, def)| previous.iter().any(|step| step.name() == def.name))
            .map(|(index, _)| index)
            .collect();
        let selected = self
            .prompts
            .multi_select("preparation", &options, &default)?;

        let mut out = Vec::new();
        for index in selected {
            let def = choices[index];
            let previous = previous.iter().find(|step| step.name() == def.name);
            out.push(self.ask_preparation(def, previous)?);
        }
        Ok(out)
    }

    /// Asks the parameters of one preparation technique.
    fn ask_preparation(
        &mut self,
        def: &TechniqueDef,
        previous: Option<&RuntimeStep>,
    ) -> Result<RuntimeStep> {
        self.blank()?;
        let heading = self.ui.heading(def.name);
        let subtitle = self.ui.dim(techniques::summary(def));
        self.echo(&format!("{heading}  {subtitle}"))?;

        match def.name {
            "bouncer" => {
                let previous = previous.and_then(|step| match step {
                    RuntimeStep::Bouncer { params } => Some(params),
                    _ => None,
                });
                Ok(RuntimeStep::Bouncer {
                    params: self.ask_bouncer(previous)?,
                })
            }
            "anti_debug" => {
                let previous = previous.and_then(|step| match step {
                    RuntimeStep::AntiDebug { params } => Some(params.action),
                    _ => None,
                });
                let action = match self.ask_select(
                    "action",
                    &[
                        ("abort", "never run the payload when a debugger is seen"),
                        ("continue", "note the detection and carry on"),
                    ],
                    matches!(previous, Some(anti_debug::Action::Continue)).into(),
                )? {
                    0 => anti_debug::Action::Abort,
                    _ => anti_debug::Action::Continue,
                };
                Ok(RuntimeStep::AntiDebug {
                    params: anti_debug::Params { action },
                })
            }
            "patch_amsi" => Ok(RuntimeStep::PatchAmsi {
                params: patch_amsi::Params {},
            }),
            "patch_etw" => {
                let previous = previous.and_then(|step| match step {
                    RuntimeStep::PatchEtw { params } => Some(params.full),
                    _ => None,
                });
                let full = self
                    .prompts
                    .confirm("also patch EtwEventWriteFull", previous.unwrap_or(true))?;
                Ok(RuntimeStep::PatchEtw {
                    params: patch_etw::Params { full },
                })
            }
            "sleep_obfuscation" => {
                let previous = previous.and_then(|step| match step {
                    RuntimeStep::SleepObfuscation { params } => Some(params.sleep_ms),
                    _ => None,
                });
                // Only `ekko` and `[payload]` are implemented, so the variant and
                // the encrypted regions are not questions yet.
                let sleep_ms =
                    self.ask_number("sleep_ms", previous.unwrap_or(5000), 1, u32::MAX as u64)?;
                Ok(RuntimeStep::SleepObfuscation {
                    params: sleep_obfuscation::Params {
                        variant: sleep_obfuscation::Variant::Ekko,
                        sleep_ms,
                        encrypt_regions: vec![sleep_obfuscation::EncryptRegion::Payload],
                    },
                })
            }
            _ => default_step(def),
        }
    }

    /// The bouncer gate: how the checks combine, what to do on rejection, and
    /// which checks to declare (each with its own value question).
    fn ask_bouncer(&mut self, previous: Option<&bouncer::Params>) -> Result<bouncer::Params> {
        let mode = match self.ask_select(
            "mode",
            &[
                ("all", "every declared check must pass"),
                ("any", "at least one declared check must pass"),
            ],
            matches!(previous.map(|params| params.mode), Some(bouncer::Mode::Any)).into(),
        )? {
            0 => bouncer::Mode::All,
            _ => bouncer::Mode::Any,
        };
        let on_fail = match self.ask_select(
            "on_fail",
            &[
                ("silent", "stop with exit code 0"),
                ("exit", "stop with exit code 1"),
            ],
            matches!(
                previous.map(|params| params.on_fail),
                Some(bouncer::OnFail::Exit)
            )
            .into(),
        )? {
            0 => bouncer::OnFail::Silent,
            _ => bouncer::OnFail::Exit,
        };

        let checks: [(&str, &str); 9] = [
            ("hostname", "required computer name (glob)"),
            ("username", "required user name (glob)"),
            ("domain", "required DNS domain (glob)"),
            ("language", "accepted BCP-47 locales"),
            ("keyboard", "accepted 4-digit layout codes"),
            ("not_in_vm", "require no hypervisor (CPUID)"),
            ("not_in_sandbox", "require the sandbox heuristic to pass"),
            ("min_uptime_min", "minimum uptime, in minutes"),
            ("min_ram_mb", "minimum physical memory, in MiB"),
        ];
        let default: Vec<usize> = checks
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| check_is_declared(name, previous))
            .map(|(index, _)| index)
            .collect();
        let selected = self.prompts.multi_select("checks", &checks, &default)?;

        let mut params = bouncer::Params {
            mode,
            on_fail,
            ..Default::default()
        };
        for index in selected {
            match checks[index].0 {
                "hostname" => {
                    params.hostname = self.ask_optional_text(
                        "hostname",
                        previous.and_then(|params| params.hostname.as_deref()),
                    )?
                }
                "username" => {
                    params.username = self.ask_optional_text(
                        "username",
                        previous.and_then(|params| params.username.as_deref()),
                    )?
                }
                "domain" => {
                    params.domain = self.ask_optional_text(
                        "domain",
                        previous.and_then(|params| params.domain.as_deref()),
                    )?
                }
                "language" => {
                    params.language = self.ask_list(
                        "language",
                        previous.map_or(&[], |params| params.language.as_slice()),
                    )?
                }
                "keyboard" => {
                    params.keyboard = self.ask_list(
                        "keyboard",
                        previous.map_or(&[], |params| params.keyboard.as_slice()),
                    )?
                }
                // Selecting either flag means "require it"; `false` and absent
                // skip the check alike, so there is nothing more to ask.
                "not_in_vm" => params.not_in_vm = Some(true),
                "not_in_sandbox" => params.not_in_sandbox = Some(true),
                "min_uptime_min" => {
                    params.min_uptime_min = self.ask_optional_number(
                        "min_uptime_min",
                        u32::MAX as u64,
                        previous.and_then(|params| params.min_uptime_min),
                    )?
                }
                "min_ram_mb" => {
                    params.min_ram_mb = self.ask_optional_number(
                        "min_ram_mb",
                        u32::MAX as u64,
                        previous.and_then(|params| params.min_ram_mb),
                    )?
                }
                _ => {}
            }
        }
        Ok(params)
    }
}

/// Whether a bouncer check field is declared (i.e. activates a check).
fn check_is_declared(name: &str, previous: Option<&bouncer::Params>) -> bool {
    let Some(params) = previous else {
        return false;
    };
    match name {
        "hostname" => params.hostname.is_some(),
        "username" => params.username.is_some(),
        "domain" => params.domain.is_some(),
        "language" => !params.language.is_empty(),
        "keyboard" => !params.keyboard.is_empty(),
        "not_in_vm" => params.not_in_vm == Some(true),
        "not_in_sandbox" => params.not_in_sandbox == Some(true),
        "min_uptime_min" => params.min_uptime_min.is_some(),
        "min_ram_mb" => params.min_ram_mb.is_some(),
        _ => false,
    }
}

/// The index of a [`TrimPaths`] in the wizard's menu.
fn trim_index(trim: TrimPaths) -> usize {
    match trim {
        TrimPaths::All => 0,
        TrimPaths::None => 1,
        TrimPaths::Relative => 2,
    }
}

/// The registered Execution techniques, in registry order.
fn execution_defs() -> Vec<&'static TechniqueDef> {
    techniques::all()
        .iter()
        .filter(|def| def.category == Category::Execution)
        .collect()
}

/// Preparation techniques in the order the wizard offers them.
///
/// The gate (`bouncer`) runs first, then the process-state patches, then the
/// sleep obfuscator. A technique missing from the ranking still appears, at the
/// end and keeping the registry order, so a newly registered preparation is
/// never silently dropped.
fn preparation_defs() -> Vec<&'static TechniqueDef> {
    let mut defs: Vec<&'static TechniqueDef> = techniques::all()
        .iter()
        .filter(|def| def.category == Category::Preparation)
        .collect();
    defs.sort_by_key(|def| prep_rank(def.name));
    defs
}

/// Preferred pipeline position of each preparation (see [`preparation_defs`]).
fn prep_rank(name: &str) -> usize {
    match name {
        "bouncer" => 0,
        "anti_debug" => 1,
        "patch_amsi" => 2,
        "patch_etw" => 3,
        "sleep_obfuscation" => 4,
        _ => usize::MAX,
    }
}

/// `(name, one-line summary)` pairs for a menu.
fn describe(defs: &[&'static TechniqueDef]) -> Vec<(&'static str, &'static str)> {
    defs.iter()
        .map(|def| (def.name, techniques::summary(def)))
        .collect()
}

/// Assembles the [`Config`] from the answered questions.
fn assemble(payload: &Path, answers: &Answers) -> Config {
    let mut runtime = answers.preparations.clone();
    runtime.push(answers.execution.clone());

    Config {
        schema: SUPPORTED_SCHEMA,
        name: answers.name.clone(),
        build: BuildConfig {
            payload: PayloadConfig {
                source: payload.display().to_string(),
                args: (!answers.payload_args.is_empty()).then(|| answers.payload_args.clone()),
                args_mode: ArgsMode::Join,
                crypto: CryptoConfig {
                    algo: CryptoAlgorithm::XChaCha20Poly1305,
                    key: KeySource::Random,
                },
                // Integrity pinning is an advanced setting; edit it in the YAML.
                sha256: None,
            },
            stub: StubConfig {
                // The wizard always renders the builtin stub.
                path: None,
                // Omitted when `none` so the generated YAML stays minimal.
                syscalls: (answers.syscalls_mode == "indirect").then(|| YamlSyscallsConfig {
                    mode: answers.syscalls_mode.clone(),
                    resolver: "hells_gate".to_string(),
                }),
                strings: Some(YamlStringsConfig {
                    strategy: answers.strings_strategy.clone(),
                    // A literal key is an advanced setting; edit it in the YAML.
                    key: "random".to_string(),
                }),
            },
            output: OutputConfig {
                path: PathBuf::from(&answers.output_path),
                // The stub is always compiled for x86-64.
                arch: Arch::X64,
                strip: answers.strip,
                trim_paths: answers.trim_paths,
                manifest: true,
                // PE resources are an advanced setting; edit them in the YAML.
                resources: None,
                // The stub prints markers for the tests, so it stays a console app.
                subsystem: Subsystem::Console,
                sign: None,
            },
        },
        runtime,
    }
}

/// Builds a step from the technique's documented `params_example`.
///
/// Used for techniques the wizard has no tailored questions for yet: the
/// registry guarantees the snippet parses, so a newly registered technique
/// arrives with its YAML defaults instead of being unreachable.
fn default_step(def: &TechniqueDef) -> Result<RuntimeStep> {
    serde_yml::from_str(def.params_example).map_err(|source| {
        PackerError::Validation(format!(
            "technique '{}' has unparsable default params: {source}",
            def.name
        ))
    })
}

/// Derives the default build name from the payload filename.
fn default_name(payload: &Path) -> String {
    payload
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("payload")
        .to_string()
}

/// Splits a comma-separated answer, dropping empty items.
fn split_list(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parses a yes/no answer. `None` means "not understood, ask again".
fn parse_yes_no(input: &str, default: bool) -> Option<bool> {
    match input.to_ascii_lowercase().as_str() {
        "" => Some(default),
        "y" | "yes" | "true" | "1" => Some(true),
        "n" | "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

/// Parses a menu answer: a 1-based number, an option name, or blank for the
/// default. `None` means "not understood, ask again".
fn parse_choice(input: &str, options: &[(&str, &str)], default: usize) -> Option<usize> {
    if input.is_empty() {
        return Some(default);
    }
    if let Ok(number) = input.parse::<usize>() {
        return (1..=options.len()).contains(&number).then(|| number - 1);
    }
    options
        .iter()
        .position(|(name, _)| name.eq_ignore_ascii_case(input))
}

/// Parses a multi-select answer: comma/space/semicolon separated numbers or
/// names. Blank means "none". The result is sorted and de-duplicated so the
/// pipeline order is deterministic regardless of the order typed.
fn parse_multi(input: &str, options: &[(&str, &str)]) -> Option<Vec<usize>> {
    if input.is_empty() {
        return Some(Vec::new());
    }
    let mut selected = Vec::new();
    for token in input
        .split([',', ' ', ';'])
        .filter(|token| !token.is_empty())
    {
        selected.push(parse_choice(token, options, 0)?);
    }
    selected.sort_unstable();
    selected.dedup();
    Some(selected)
}

/// Parses a bounded number. `None` means "not understood, ask again".
fn parse_number(input: &str, default: u64, min: u64, max: u64) -> Option<u64> {
    if input.is_empty() {
        return Some(default);
    }
    let value: u64 = input.replace('_', "").parse().ok()?;
    (min..=max).contains(&value).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use crate::config::load_config;

    /// Joins answer lines the way a terminal would deliver them.
    fn script(lines: &[&str]) -> String {
        let mut input = lines.join("\n");
        input.push('\n');
        input
    }

    /// A unique, empty directory for one test's generated config.
    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("batesian_wizard_tests")
            .join(test);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Runs a scripted session and returns its written config path and output.
    fn session(
        payload: &str,
        answers: &[&str],
        config_out: Option<&Path>,
    ) -> (Option<PathBuf>, String) {
        let mut out = Vec::new();
        let result = run_with(
            Path::new(payload),
            config_out,
            &Palette::plain(),
            Cursor::new(script(answers)),
            &mut out,
        )
        .expect("the scripted session should succeed");
        (
            result,
            String::from_utf8(out).expect("the transcript is utf-8"),
        )
    }

    #[test]
    fn parse_yes_no_accepts_common_spellings() {
        assert_eq!(parse_yes_no("", true), Some(true));
        assert_eq!(parse_yes_no("", false), Some(false));
        assert_eq!(parse_yes_no("Y", false), Some(true));
        assert_eq!(parse_yes_no("no", true), Some(false));
        assert_eq!(parse_yes_no("0", true), Some(false));
        assert_eq!(parse_yes_no("maybe", true), None);
    }

    #[test]
    fn parse_choice_accepts_numbers_and_names() {
        let options = [("xor", "a"), ("stack", "b")];
        assert_eq!(parse_choice("", &options, 1), Some(1));
        assert_eq!(parse_choice("1", &options, 0), Some(0));
        assert_eq!(parse_choice("2", &options, 0), Some(1));
        assert_eq!(parse_choice("STACK", &options, 0), Some(1));
        assert_eq!(parse_choice("3", &options, 0), None);
        assert_eq!(parse_choice("nope", &options, 0), None);
    }

    #[test]
    fn parse_multi_sorts_and_dedups() {
        let options = [("a", ""), ("b", ""), ("c", "")];
        assert_eq!(parse_multi("", &options), Some(vec![]));
        assert_eq!(parse_multi("3,1,1", &options), Some(vec![0, 2]));
        assert_eq!(parse_multi("b c", &options), Some(vec![1, 2]));
        assert_eq!(parse_multi("9", &options), None);
    }

    #[test]
    fn parse_number_stays_within_bounds() {
        assert_eq!(parse_number("", 5, 0, 10), Some(5));
        assert_eq!(parse_number("0", 5, 0, 10), Some(0));
        assert_eq!(parse_number("1_000", 0, 0, 2000), Some(1000));
        assert_eq!(parse_number("11", 5, 0, 10), None);
        assert_eq!(parse_number("abc", 5, 0, 10), None);
    }

    #[test]
    fn split_list_trims_and_drops_empty_items() {
        assert_eq!(split_list(" a , b ,, "), vec!["a", "b"]);
        assert!(split_list("  ").is_empty());
    }

    #[test]
    fn default_name_uses_the_file_stem() {
        assert_eq!(default_name(Path::new("C:\\tmp\\mimikatz.exe")), "mimikatz");
        assert_eq!(default_name(Path::new("payload")), "payload");
    }

    /// Nine blank first-pass answers plus a blank review selection (`build now`)
    /// produce a config the packer accepts as-is.
    #[test]
    fn defaults_produce_a_valid_reflective_config() {
        let dir = temp_dir("defaults");
        let config_path = dir.join("out.yaml");
        let answers = ["", "", "", "", "", "", "", "", "", ""];

        let (written, transcript) = session("payload.exe", &answers, Some(&config_path));

        assert_eq!(written.as_deref(), Some(config_path.as_path()));
        assert!(
            transcript.contains("build interactive"),
            "no echo: {transcript}"
        );

        let config = load_config(&config_path, &BTreeMap::new()).expect("valid config");
        assert_eq!(config.name, "payload");
        assert_eq!(config.build.payload.source, "payload.exe");
        assert!(config.build.payload.args.is_none());
        assert_eq!(
            config.build.output.path,
            PathBuf::from("./dist/payload_packed.exe")
        );
        assert!(config.build.output.strip);
        assert_eq!(config.runtime.len(), 1);
        assert!(
            matches!(config.runtime[0], RuntimeStep::ReflectiveLoading { .. }),
            "got {:?}",
            config.runtime[0]
        );
        assert!(config.build.stub.syscalls.is_none());
        assert!(config.build.stub.strings.is_some());
    }

    /// A full script exercises the execution choice, a preparation with several
    /// follow-ups, the payload args and the syscall default.
    #[test]
    fn hollowing_with_a_bouncer_keeps_the_pipeline_order() {
        let dir = temp_dir("hollowing");
        let config_path = dir.join("out.yaml");
        let answers = [
            "demo",              // name
            "a,b",               // payload args
            "process_hollowing", // execution
            "",                  // target -> default
            "1",                 // preparation: bouncer
            "",                  // bouncer mode -> all
            "",                  // bouncer on_fail -> silent
            "1,6",               // checks: hostname + not_in_vm
            "WORKSTATION-*",     // hostname
            "",                  // strings -> xor
            "",                  // syscalls -> indirect (hollowing needs it)
            "",                  // output path
            "",                  // strip
            "",                  // trim paths
            "",                  // review -> build now
        ];

        let (written, _) = session("mimikatz.exe", &answers, Some(&config_path));
        assert!(written.is_some());

        let config = load_config(&config_path, &BTreeMap::new()).expect("valid config");
        assert_eq!(config.name, "demo");
        assert_eq!(
            config.build.payload.args,
            Some(vec!["a".to_string(), "b".to_string()])
        );

        assert_eq!(config.runtime.len(), 2);
        let RuntimeStep::Bouncer { params } = &config.runtime[0] else {
            panic!("expected a bouncer first, got {:?}", config.runtime[0]);
        };
        assert_eq!(params.mode, bouncer::Mode::All);
        assert_eq!(params.on_fail, bouncer::OnFail::Silent);
        assert_eq!(params.hostname.as_deref(), Some("WORKSTATION-*"));
        assert_eq!(params.not_in_vm, Some(true));

        let RuntimeStep::ProcessHollowing { params } = &config.runtime[1] else {
            panic!(
                "expected process_hollowing second, got {:?}",
                config.runtime[1]
            );
        };
        assert_eq!(params.target, process_hollowing::default_target());

        let syscalls = config.build.stub.syscalls.expect("indirect syscalls");
        assert_eq!(syscalls.mode, "indirect");
        assert_eq!(syscalls.resolver, "hells_gate");
    }

    /// Choosing `edit answers` at the review re-asks the questions with the
    /// previous values as defaults, so a single field can be corrected.
    #[test]
    fn editing_answers_updates_a_single_field() {
        let dir = temp_dir("edit");
        let config_path = dir.join("out.yaml");
        let answers = [
            "first",  // name
            "",       // payload args
            "",       // execution
            "",       // preparation
            "",       // strings
            "",       // syscalls
            "",       // output path
            "",       // strip
            "",       // trim paths
            "2",      // review -> edit answers
            "second", // name (corrected)
            "",       // payload args
            "",       // execution
            "",       // preparation
            "",       // strings
            "",       // syscalls
            "",       // output path
            "",       // strip
            "",       // trim paths
            "",       // review -> build now
        ];

        let (written, _) = session("payload.exe", &answers, Some(&config_path));
        assert!(written.is_some());

        let config = load_config(&config_path, &BTreeMap::new()).expect("valid config");
        assert_eq!(config.name, "second");
    }

    /// Choosing `quit` at the review leaves the disk untouched.
    #[test]
    fn quitting_the_review_writes_nothing() {
        let dir = temp_dir("aborted");
        let config_path = dir.join("out.yaml");
        let answers = ["", "", "", "", "", "", "", "", "", "3"];

        let (written, _) = session("payload.exe", &answers, Some(&config_path));

        assert!(written.is_none());
        assert!(!config_path.exists(), "the config must not be written");
    }

    /// A closed stdin mid-session is an error, not a silent all-defaults build.
    #[test]
    fn truncated_input_is_an_error() {
        let dir = temp_dir("truncated");
        let config_path = dir.join("out.yaml");
        let err = run_with(
            Path::new("payload.exe"),
            Some(&config_path),
            &Palette::plain(),
            Cursor::new(String::new()),
            Vec::new(),
        )
        .expect_err("an empty input must fail");
        assert!(
            err.to_string().contains("input ended"),
            "unclear error: {err}"
        );
    }
}
