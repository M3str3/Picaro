//! Interactive `build` wizard (`picaro build interactive <payload>`).
//!
//! The wizard walks through the same decisions a schema YAML encodes (payload,
//! techniques, stub and output), assembles a [`Plan`], shows it and writes it.
//! It then hands the file back to the normal build flow, so the generated YAML
//! is the single source of truth: editing it and running `picaro build <file>`
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

use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use inquire::{Confirm, MultiSelect, Select, Text};

use crate::engine::args::ArgsMode;
use crate::engine::obfuscation::YamlStringsPlan;
use crate::engine::syscalls::YamlSyscallsPlan;
use crate::error::{PackerError, Result};
use crate::plan::schema::{
    Arch, BuildPlan, CryptoAlgorithm, CryptoPlan, DllEntry, KeySource, OutputKind, OutputPlan,
    PayloadFormat, PayloadPlan, Plan, StubPlan, Subsystem, TrimPaths, SUPPORTED_SCHEMA,
};
use crate::plan::validate;
use crate::techniques::{
    self, anti_debug, bouncer, early_bird, living_off_the_land, module_stomping, patch_amsi,
    patch_etw, pe_injection, process_hollowing, sleep, sleep_obfuscation, Category, RuntimeStep,
    TechniqueDef, TechniqueKind,
};
use crate::ui::Palette;

/// Runs the wizard against stdin/stdout, picking the prompt backend by whether
/// both streams are a terminal.
///
/// Returns the path of the written YAML, or `None` when the operator quit the
/// review screen without writing. The payload path is checked before the first
/// question so a typo fails before a dozen prompts.
pub fn run(payload: &Path, plan_out: Option<&Path>, ui: &Palette) -> Result<Option<PathBuf>> {
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

    run_wizard(payload, plan_out, ui, prompts.as_mut())
}

/// Testable core of [`run`]: runs the wizard over `reader`/`out` with the plain
/// line backend, so unit tests can script a whole session.
#[cfg(test)]
fn run_with<R: BufRead, W: Write>(
    payload: &Path,
    plan_out: Option<&Path>,
    ui: &Palette,
    reader: R,
    out: W,
) -> Result<Option<PathBuf>> {
    let mut line = LinePrompt {
        reader,
        out,
        ui: *ui,
    };
    run_wizard(payload, plan_out, ui, &mut line)
}

/// Shared wizard flow, independent of the prompt backend.
fn run_wizard(
    payload: &Path,
    plan_out: Option<&Path>,
    ui: &Palette,
    prompts: &mut dyn Prompt,
) -> Result<Option<PathBuf>> {
    let mut wizard = Wizard {
        ui: *ui,
        prompts,
        payload: payload.to_path_buf(),
        plan_out: plan_out.map(Path::to_path_buf),
    };

    wizard.echo(&ui.command_line("build interactive", payload.display()))?;
    wizard.blank()?;

    // First pass, then a review loop: build, or re-ask with the previous answers
    // as the defaults, or quit.
    let mut answers = wizard.ask_all(None)?;
    loop {
        let plan = assemble(payload, &answers);
        validate::validate(&plan)?;
        let yaml = serde_yml::to_string(&plan).map_err(|source| {
            PackerError::Validation(format!("could not serialize the generated plan: {source}"))
        })?;

        wizard.blank()?;
        wizard.section("PLAN")?;
        let preview = wizard.ui.dim(yaml.trim_end());
        wizard.echo(&preview)?;
        wizard.blank()?;

        match wizard.prompts.select(
            "what now",
            &[
                ("build now", "write the plan and run the build"),
                ("edit answers", "go back and change something"),
                ("quit", "discard and exit"),
            ],
            0,
        )? {
            0 => {
                let path = write_plan(&plan, &yaml, wizard.plan_out.as_deref())?;
                wizard.blank()?;
                let line = wizard.ui.done("plan", wizard.ui.target(path.display()));
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

/// Writes the serialized plan to disk, creating the parent directory, and
/// returns the path it was written to.
fn write_plan(plan: &Plan, yaml: &str, plan_out: Option<&Path>) -> Result<PathBuf> {
    let path = plan_out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("dist").join(format!("{}.yaml", plan.name)));
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, yaml)?;
    Ok(path)
}

/// All the raw answers the wizard collects, kept separate from the assembled
/// [`Plan`] so a review pass can seed each field's default from its previous
/// value.
#[derive(Debug, Clone)]
struct Answers {
    name: String,
    payload_args: Vec<String>,
    execution: TechniqueKind,
    preparations: Vec<TechniqueKind>,
    /// Additional runtime steps appended after the execution technique, in
    /// order (Control steps and in-process runners that return control).
    additional_steps: Vec<TechniqueKind>,
    strings_strategy: String,
    syscalls_mode: String,
    output_path: String,
    /// `build.output.kind`: a standalone executable or a host-loaded DLL.
    output_kind: OutputKind,
    /// `build.output.entry` for a DLL build (always `auto` for an executable).
    dll_entry: DllEntry,
    /// `build.output.arch` as the wizard's answer string (`x64` / `x86`).
    arch: String,
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
    plan_out: Option<PathBuf>,
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

        // Asked before the techniques: the stub and the payload share an
        // architecture, and `syscalls: indirect` is x64-only.
        let arch = match self.ask_select(
            "arch",
            &[
                ("x64", "64-bit stub and payload (the default)"),
                (
                    "x86",
                    "32-bit stub and payload; runs under WOW64 on 64-bit Windows",
                ),
            ],
            previous
                .map(|answers| usize::from(answers.arch == "x86"))
                .unwrap_or(0),
        )? {
            0 => "x64".to_string(),
            _ => "x86".to_string(),
        };

        // The output kind gates which techniques are runnable — a DLL lives in a
        // host process and must not touch that process's image — so it is asked
        // before the techniques, for the same reason as `arch`.
        let output_kind = match self.ask_select(
            "output kind",
            &[
                ("exe", "a standalone executable (the default)"),
                (
                    "dll",
                    "a DLL a host process loads (ctypes, P/Invoke, a JVM)",
                ),
            ],
            previous
                .map(|answers| usize::from(answers.output_kind == OutputKind::Dll))
                .unwrap_or(0),
        )? {
            0 => OutputKind::Exe,
            _ => OutputKind::Dll,
        };

        self.section("TECHNIQUES")?;
        let execution = self.ask_execution(previous.map(|answers| &answers.execution))?;
        let format = default_format(&execution);
        let preparations = self.ask_preparations(
            previous.map_or(&[][..], |answers| answers.preparations.as_slice()),
            output_kind,
        )?;
        let additional_steps = self.ask_additional_steps(
            previous.map(|answers| answers.additional_steps.as_slice()),
            &execution,
            format,
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
        // `indirect` needs the x64 trampoline, so an x86 plan never offers it
        // (the wizard only produces plans the packer accepts).
        let mut syscall_options: Vec<(&str, &str)> = vec![("none", "call the Win32 APIs directly")];
        if arch != "x86" {
            syscall_options.push(("indirect", "resolve SSNs and invoke the kernel directly"));
        }
        let default_syscalls = if arch == "x86" {
            0
        } else {
            previous
                .map(|answers| usize::from(answers.syscalls_mode == "indirect"))
                .unwrap_or_else(|| {
                    usize::from(
                        techniques::find(execution.name())
                            .is_some_and(|def| !def.syscalls.is_empty()),
                    )
                })
        };
        let syscalls_mode = match self.ask_select("syscalls", &syscall_options, default_syscalls)? {
            0 => "none".to_string(),
            _ => "indirect".to_string(),
        };

        self.section("OUTPUT")?;
        // `entry` only applies to a DLL; an executable starts at `main`.
        let dll_entry = if output_kind == OutputKind::Dll {
            let default_entry = previous.map_or(0, |answers| dll_entry_index(&answers.dll_entry));
            match self.ask_select(
                "entry",
                &[
                    (
                        "auto",
                        "export `JNI_OnLoad` and `Run`, so any host can call it",
                    ),
                    (
                        "jni_on_load",
                        "export only `JNI_OnLoad` (a JVM's `System.load`)",
                    ),
                    ("export", "export only one function name of your choice"),
                ],
                default_entry,
            )? {
                1 => DllEntry::JniOnLoad,
                2 => {
                    let default_export = match previous.map(|answers| &answers.dll_entry) {
                        Some(DllEntry::Export(name)) => name.clone(),
                        _ => DllEntry::AUTO_EXPORT.to_string(),
                    };
                    DllEntry::Export(self.ask_text("export name", &default_export)?)
                }
                _ => DllEntry::Auto,
            }
        } else {
            DllEntry::Auto
        };

        // A DLL the host loads carries the `.dll` extension, an executable
        // `.exe`; a path the operator typed is kept only while the kind still
        // matches it.
        let default_output = previous
            .filter(|answers| answers.output_kind == output_kind)
            .map(|answers| answers.output_path.clone())
            .unwrap_or_else(|| format!("./dist/{name}_packed.{}", output_kind.label()));
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
            additional_steps,
            strings_strategy,
            syscalls_mode,
            output_path,
            output_kind,
            dll_entry,
            arch,
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
    fn ask_execution(&mut self, previous: Option<&TechniqueKind>) -> Result<TechniqueKind> {
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
        self.ask_execution_params(def, previous)
    }

    /// Asks the parameters of one Execution technique.
    ///
    /// Shared by the primary execution question and the appended runtime steps,
    /// so an appended `module_stomping` asks for its stomp target the same way
    /// the primary one does. Techniques the wizard has no tailored questions for
    /// fall back to their documented `params_example`.
    fn ask_execution_params(
        &mut self,
        def: &TechniqueDef,
        previous: Option<&TechniqueKind>,
    ) -> Result<TechniqueKind> {
        match def.name {
            "process_hollowing" => {
                let default_target = match previous {
                    Some(TechniqueKind::ProcessHollowing { params }) => params.target.clone(),
                    _ => process_hollowing::default_target(),
                };
                let target = self.ask_text("target", &default_target)?;
                Ok(TechniqueKind::ProcessHollowing {
                    params: process_hollowing::Params {
                        payload: None,
                        target,
                    },
                })
            }
            "module_stomping" => {
                let default_module = match previous {
                    Some(TechniqueKind::ModuleStomping { params }) => params.module.clone(),
                    _ => module_stomping::default_module(),
                };
                let module = self.ask_text("module", &default_module)?;
                Ok(TechniqueKind::ModuleStomping {
                    params: module_stomping::Params {
                        payload: None,
                        module,
                    },
                })
            }
            "early_bird" => {
                let (default_target, default_wait) = match previous {
                    Some(TechniqueKind::EarlyBird { params }) => {
                        (params.target.clone(), params.wait_ms)
                    }
                    _ => (early_bird::default_target(), 0),
                };
                let target = self.ask_text("target", &default_target)?;
                let wait_ms =
                    self.ask_number("wait_ms (0 = do not wait)", default_wait, 0, u64::MAX)?;
                Ok(TechniqueKind::EarlyBird {
                    params: early_bird::Params {
                        payload: None,
                        target,
                        wait_ms,
                    },
                })
            }
            "pe_injection" => {
                let (default_target, default_timeout) = match previous {
                    Some(TechniqueKind::PeInjection { params }) => {
                        (params.target.clone(), u64::from(params.timeout_ms))
                    }
                    _ => (pe_injection::default_target(), 0),
                };
                let target = self.ask_text("target", &default_target)?;
                let timeout_ms = self.ask_number(
                    "timeout_ms (0 = wait forever)",
                    default_timeout,
                    0,
                    u64::from(u32::MAX),
                )? as u32;
                Ok(TechniqueKind::PeInjection {
                    params: pe_injection::Params {
                        payload: None,
                        target,
                        timeout_ms,
                    },
                })
            }
            _ => default_step(def),
        }
    }

    /// Asks which preparations to apply, then each one's parameters.
    ///
    /// A `kind: dll` build cannot run a preparation that acts on the *running
    /// image* (that image is the host's), so those are not offered at all — the
    /// same way `syscalls: indirect` is hidden on x86.
    fn ask_preparations(
        &mut self,
        previous: &[TechniqueKind],
        kind: OutputKind,
    ) -> Result<Vec<TechniqueKind>> {
        let choices: Vec<&'static TechniqueDef> = preparation_defs()
            .into_iter()
            .filter(|def| !(kind == OutputKind::Dll && is_dll_incompatible(def.name)))
            .collect();
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
            out.push(self.ask_preparation(def, previous, kind)?);
        }
        Ok(out)
    }

    /// Asks the parameters of one preparation technique.
    fn ask_preparation(
        &mut self,
        def: &TechniqueDef,
        previous: Option<&TechniqueKind>,
        kind: OutputKind,
    ) -> Result<TechniqueKind> {
        self.blank()?;
        let heading = self.ui.heading(def.name);
        let subtitle = self.ui.dim(techniques::summary(def));
        self.echo(&format!("{heading}  {subtitle}"))?;

        match def.name {
            "bouncer" => {
                let previous = previous.and_then(|step| match step {
                    TechniqueKind::Bouncer { params } => Some(params),
                    _ => None,
                });
                Ok(TechniqueKind::Bouncer {
                    params: self.ask_bouncer(previous, kind)?,
                })
            }
            "anti_debug" => {
                let previous = previous.and_then(|step| match step {
                    TechniqueKind::AntiDebug { params } => Some(params.action),
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
                Ok(TechniqueKind::AntiDebug {
                    params: anti_debug::Params { action },
                })
            }
            "patch_amsi" => {
                let previous = previous.and_then(|step| match step {
                    TechniqueKind::PatchAmsi { params } => {
                        Some((params.scan_string, params.open_session))
                    }
                    _ => None,
                });
                let (prev_string, prev_session) = previous.unwrap_or((true, true));
                let scan_string = self
                    .prompts
                    .confirm("also patch AmsiScanString", prev_string)?;
                let open_session = self
                    .prompts
                    .confirm("also patch AmsiOpenSession", prev_session)?;
                Ok(TechniqueKind::PatchAmsi {
                    params: patch_amsi::Params {
                        scan_string,
                        open_session,
                    },
                })
            }
            "patch_etw" => {
                let previous = previous.and_then(|step| match step {
                    TechniqueKind::PatchEtw { params } => {
                        Some((params.full, params.ex, params.nt_trace))
                    }
                    _ => None,
                });
                let (prev_full, prev_ex, prev_nt_trace) = previous.unwrap_or((true, true, true));
                let full = self
                    .prompts
                    .confirm("also patch EtwEventWriteFull", prev_full)?;
                let ex = self
                    .prompts
                    .confirm("also patch EtwEventWriteEx", prev_ex)?;
                let nt_trace = self
                    .prompts
                    .confirm("also patch NtTraceEvent", prev_nt_trace)?;
                Ok(TechniqueKind::PatchEtw {
                    params: patch_etw::Params { full, ex, nt_trace },
                })
            }
            "sleep_obfuscation" => {
                let previous = previous.and_then(|step| match step {
                    TechniqueKind::SleepObfuscation { params } => Some(params.sleep_ms),
                    _ => None,
                });
                // Only `ekko` and `[payload]` are implemented, so the variant and
                // the encrypted regions are not questions yet.
                let sleep_ms =
                    self.ask_number("sleep_ms", previous.unwrap_or(5000), 1, u32::MAX as u64)?;
                Ok(TechniqueKind::SleepObfuscation {
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

    /// Asks whether to append more runtime steps after the execution technique.
    ///
    /// The loader keeps control only when the execution technique returns; when
    /// it is terminal (`dotnet_hosting`, or `reflective_loading` of a PE
    /// executable) a following step would never run, so nothing is appended. The
    /// Control steps always return; the in-process runners return only for a
    /// shellcode payload, so they are offered only then.
    fn ask_additional_steps(
        &mut self,
        previous: Option<&[TechniqueKind]>,
        execution: &TechniqueKind,
        format: PayloadFormat,
    ) -> Result<Vec<TechniqueKind>> {
        if execution_is_terminal(execution, format) {
            return Ok(Vec::new());
        }
        let choices = appendable_defs(format);
        let options = describe(&choices);

        let mut steps = Vec::new();
        let mut position = 0;
        loop {
            let previous_step = previous.and_then(|steps| steps.get(position));
            if !self
                .prompts
                .confirm("add another runtime step?", previous_step.is_some())?
            {
                break;
            }
            let default = previous_step
                .and_then(|step| choices.iter().position(|def| def.name == step.name()))
                .unwrap_or(0);
            let index = self.prompts.select("append step", &options, default)?;
            let def = choices[index];
            let previous_step = previous_step.filter(|step| step.name() == def.name);
            steps.push(self.ask_additional_step(def, previous_step)?);
            position += 1;
        }
        Ok(steps)
    }

    /// Asks the parameters of one appended runtime step.
    fn ask_additional_step(
        &mut self,
        def: &TechniqueDef,
        previous: Option<&TechniqueKind>,
    ) -> Result<TechniqueKind> {
        self.blank()?;
        let heading = self.ui.heading(def.name);
        let subtitle = self.ui.dim(techniques::summary(def));
        self.echo(&format!("{heading}  {subtitle}"))?;

        match def.name {
            "sleep" => {
                let default_ms = match previous {
                    Some(TechniqueKind::Sleep { params }) => params.ms,
                    _ => sleep::default_ms(),
                };
                let ms = self.ask_number("ms", default_ms, 1, u64::MAX)?;
                Ok(TechniqueKind::Sleep {
                    params: sleep::Params { ms },
                })
            }
            "living_off_the_land" => {
                let (default_binary, default_args) = match previous {
                    Some(TechniqueKind::LivingOffTheLand { params }) => {
                        (params.binary.clone(), params.args.clone())
                    }
                    _ => ("cmd.exe".to_string(), Vec::new()),
                };
                let binary = self.ask_text("binary", &default_binary)?;
                let args = self.ask_list("args (comma-separated)", &default_args)?;
                Ok(TechniqueKind::LivingOffTheLand {
                    params: living_off_the_land::Params {
                        binary,
                        args,
                        ..Default::default()
                    },
                })
            }
            // The in-process runners reuse the primary execution's questions
            // (`module_stomping` asks its target; the no-arg runners keep their
            // `params_example` defaults).
            _ => self.ask_execution_params(def, previous),
        }
    }

    /// The bouncer gate: how the checks combine, what to do on rejection, and
    /// which checks to declare (each with its own value question).
    fn ask_bouncer(
        &mut self,
        previous: Option<&bouncer::Params>,
        kind: OutputKind,
    ) -> Result<bouncer::Params> {
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
        // `on_fail: exit` calls `std::process::exit`, which would kill the host
        // process, so a DLL build only offers the silent rejection.
        let on_fail = if kind == OutputKind::Dll {
            bouncer::OnFail::Silent
        } else {
            match self.ask_select(
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
            }
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

/// The index of a [`DllEntry`] in the wizard's entry menu.
fn dll_entry_index(entry: &DllEntry) -> usize {
    match entry {
        DllEntry::Auto => 0,
        DllEntry::JniOnLoad => 1,
        DllEntry::Export(_) => 2,
    }
}

/// A preparation a `kind: dll` build cannot run: both act on the *running image*
/// (`GetModuleHandleA(NULL)`), which in a DLL build is the host process.
/// `plan::validate` rejects them, so the wizard must not offer them.
fn is_dll_incompatible(name: &str) -> bool {
    matches!(name, "self_deletion" | "sleep_obfuscation")
}

/// Whether an execution technique hands the whole process to the payload, so a
/// following step would never run. Mirrors `plan::validate`'s terminal-step rule
/// so the wizard never offers to append a step past it.
fn execution_is_terminal(technique: &TechniqueKind, format: PayloadFormat) -> bool {
    match technique {
        TechniqueKind::DotnetHosting { .. } => true,
        TechniqueKind::ReflectiveLoading { .. } => format == PayloadFormat::Pe,
        _ => false,
    }
}

/// The techniques the wizard offers as appendable runtime steps, in menu order.
///
/// The Control steps (`sleep`, `living_off_the_land`) always return control and
/// are always offered. The in-process runners (`execution_callbacks`,
/// `module_stomping`, `fibers`, `reflective_loading`) return only for a shellcode
/// payload, so they are offered only then; a PE `reflective_loading` would be
/// terminal.
fn appendable_defs(format: PayloadFormat) -> Vec<&'static TechniqueDef> {
    let mut names: Vec<&'static str> = vec!["sleep", "living_off_the_land"];
    if format == PayloadFormat::Shellcode {
        names.extend([
            "execution_callbacks",
            "module_stomping",
            "fibers",
            "reflective_loading",
        ]);
    }
    names
        .into_iter()
        .filter_map(|name| techniques::find(name))
        .collect()
}

/// The registered Execution techniques, in registry order.
fn execution_defs() -> Vec<&'static TechniqueDef> {
    techniques::all()
        .iter()
        .filter(|def| def.category == Category::Execution)
        // The wizard builds an executable or a native DLL; `import_powermodule`
        // only exists inside a `kind: psmodule` build (assembled in the YAML).
        .filter(|def| def.name != "import_powermodule")
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
        "hide_thread_from_debugger" => 2,
        "process_mitigations" => 3,
        "patch_amsi" => 4,
        "patch_etw" => 5,
        "hardware_breakpoints" => 6,
        "sleep_obfuscation" => 7,
        _ => usize::MAX,
    }
}

/// `(name, one-line summary)` pairs for a menu.
fn describe(defs: &[&'static TechniqueDef]) -> Vec<(&'static str, &'static str)> {
    defs.iter()
        .map(|def| (def.name, techniques::summary(def)))
        .collect()
}

/// Assembles the [`Plan`] from the answered questions.
///
/// The wizard builds a single-payload plan: the payload's key is the file stem,
/// and the crypto lives on `build.crypto` (no per-payload block).
fn assemble(payload: &Path, answers: &Answers) -> Plan {
    let mut runtime: Vec<RuntimeStep> = answers
        .preparations
        .iter()
        .cloned()
        .map(RuntimeStep::new)
        .collect();
    runtime.push(RuntimeStep::new(answers.execution.clone()));
    runtime.extend(
        answers
            .additional_steps
            .iter()
            .cloned()
            .map(RuntimeStep::new),
    );

    let payload_name = default_name(payload);
    let mut payloads = BTreeMap::new();
    payloads.insert(
        payload_name,
        PayloadPlan {
            source: payload.display().to_string(),
            // The wizard writes one payload and never asks for its format, so it
            // must pick one the chosen technique runs (see `default_format`);
            // anything else is an advanced setting edited in the YAML.
            format: default_format(&answers.execution),
            export: None,
            args: (!answers.payload_args.is_empty()).then(|| answers.payload_args.clone()),
            args_mode: ArgsMode::Join,
            // The crypto lives on `build.crypto`; inherited by the payload.
            crypto: None,
            // Integrity pinning is an advanced setting; edit it in the YAML.
            sha256: None,
        },
    );

    Plan {
        schema: SUPPORTED_SCHEMA,
        name: answers.name.clone(),
        build: BuildPlan {
            crypto: Some(CryptoPlan {
                algo: CryptoAlgorithm::XChaCha20Poly1305,
                key: KeySource::Random,
            }),
            payloads,
            stub: StubPlan {
                // The wizard always renders the builtin stub.
                path: None,
                // Omitted when `none` so the generated YAML stays minimal.
                syscalls: (answers.syscalls_mode == "indirect").then(|| YamlSyscallsPlan {
                    mode: answers.syscalls_mode.clone(),
                    resolver: "hells_gate".to_string(),
                }),
                // API resolution is an advanced loader setting; edit it in the YAML.
                api_resolution: None,
                strings: Some(YamlStringsPlan {
                    strategy: answers.strings_strategy.clone(),
                    // A literal key is an advanced setting; edit it in the YAML.
                    key: "random".to_string(),
                }),
                // Debug builds are a lab setting; edit it in the YAML.
                debug: false,
            },
            // Polymorphism is on by default (`mode: full`); omitted here so the
            // generated YAML stays minimal.
            polymorphism: None,
            output: OutputPlan {
                path: PathBuf::from(&answers.output_path),
                kind: answers.output_kind,
                entry: answers.dll_entry.clone(),
                arch: if answers.arch == "x86" {
                    Arch::X86
                } else {
                    Arch::X64
                },
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

/// The payload format the wizard writes for an execution technique.
///
/// `plan::validate` rejects a plan whose payload format the technique cannot
/// run, and the wizard never asks for the format, so the default has to be one
/// the chosen technique accepts. Formats the wizard cannot infer (a DLL export,
/// or shellcode for `reflective_loading`) are edited in the YAML afterwards.
fn default_format(technique: &TechniqueKind) -> PayloadFormat {
    match technique {
        TechniqueKind::DotnetHosting { .. } => PayloadFormat::Dotnet,
        TechniqueKind::PowershellHosting { .. } | TechniqueKind::ImportPowermodule { .. } => {
            PayloadFormat::Powershell
        }
        TechniqueKind::ExecutionCallbacks { .. }
        | TechniqueKind::ModuleStomping { .. }
        | TechniqueKind::EarlyBird { .. }
        | TechniqueKind::ThreadHijacking { .. }
        | TechniqueKind::Fibers { .. }
        | TechniqueKind::DllHollowing { .. } => PayloadFormat::Shellcode,
        _ => PayloadFormat::Pe,
    }
}

/// Builds a step from the technique's documented `params_example`.
///
/// Used for techniques the wizard has no tailored questions for yet: the
/// registry guarantees the snippet parses, so a newly registered technique
/// arrives with its YAML defaults instead of being unreachable.
fn default_step(def: &TechniqueDef) -> Result<TechniqueKind> {
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

    use crate::plan::load_plan;

    /// Joins answer lines the way a terminal would deliver them.
    fn script(lines: &[&str]) -> String {
        let mut input = lines.join("\n");
        input.push('\n');
        input
    }

    /// A unique, empty directory for one test's generated plan.
    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("picaro_wizard_tests").join(test);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Runs a scripted session and returns its written plan path and output.
    fn session(
        payload: &str,
        answers: &[&str],
        plan_out: Option<&Path>,
    ) -> (Option<PathBuf>, String) {
        let mut out = Vec::new();
        let result = run_with(
            Path::new(payload),
            plan_out,
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

    /// Twelve blank first-pass answers plus a blank review selection (`build
    /// now`) produce a plan the packer accepts as-is.
    #[test]
    fn defaults_produce_a_valid_reflective_plan() {
        let dir = temp_dir("defaults");
        let plan_path = dir.join("out.yaml");
        let answers = ["", "", "", "", "", "", "", "", "", "", "", ""];

        let (written, transcript) = session("payload.exe", &answers, Some(&plan_path));

        assert_eq!(written.as_deref(), Some(plan_path.as_path()));
        assert!(
            transcript.contains("build interactive"),
            "no echo: {transcript}"
        );

        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        assert_eq!(plan.name, "payload");
        assert_eq!(plan.build.output.arch, Arch::X64, "the default arch is x64");
        assert_eq!(
            plan.build.output.kind,
            OutputKind::Exe,
            "the default output kind is exe"
        );
        let payload = plan.build.payloads.get("payload").expect("the payload");
        assert_eq!(payload.source, "payload.exe");
        assert!(payload.args.is_none());
        assert!(plan.build.crypto.is_some(), "build.crypto is the default");
        assert_eq!(
            plan.build.output.path,
            PathBuf::from("./dist/payload_packed.exe")
        );
        assert!(plan.build.output.strip);
        assert_eq!(plan.runtime.len(), 1);
        assert!(
            matches!(
                plan.runtime[0].technique,
                TechniqueKind::ReflectiveLoading { .. }
            ),
            "got {:?}",
            plan.runtime[0]
        );
        // The execution technique (reflective_loading) uses the syscall layer,
        // so the syscalls question defaults to `indirect`.
        let syscalls = plan.build.stub.syscalls.expect("indirect syscalls");
        assert_eq!(syscalls.mode, "indirect");
        assert_eq!(syscalls.resolver, "hells_gate");
        assert!(plan.build.stub.strings.is_some());
    }

    /// The execution techniques the wizard has tailored questions for must
    /// honour the answers instead of silently keeping the `params_example`
    /// defaults.
    #[test]
    fn prompts_the_execution_technique_params() {
        // module_stomping: which module to stomp.
        let dir = temp_dir("exec_params_module");
        let plan_path = dir.join("out.yaml");
        let answers = [
            "demo",
            "",
            "",
            "",
            "module_stomping",
            "dbghelp.dll",
            "",
            "", // add another runtime step? -> no
            "",
            "",
            "",
            "",
            "",
            "",
        ];
        let (written, _) = session("payload.exe", &answers, Some(&plan_path));
        assert_eq!(written.as_deref(), Some(plan_path.as_path()));
        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        match &plan.runtime[0].technique {
            TechniqueKind::ModuleStomping { params } => {
                assert_eq!(params.module, "dbghelp.dll");
                assert_eq!(params.payload, None);
            }
            other => panic!("expected module_stomping, got {other:?}"),
        }

        // early_bird: the target and the bounded wait.
        let dir = temp_dir("exec_params_early_bird");
        let plan_path = dir.join("out.yaml");
        let answers = [
            "demo",
            "",
            "",
            "",
            "early_bird",
            "C:\\Windows\\System32\\notepad.exe",
            "1500",
            "",
            "", // add another runtime step? -> no
            "",
            "",
            "",
            "",
            "",
            "",
        ];
        let (written, _) = session("payload.exe", &answers, Some(&plan_path));
        assert_eq!(written.as_deref(), Some(plan_path.as_path()));
        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        match &plan.runtime[0].technique {
            TechniqueKind::EarlyBird { params } => {
                assert_eq!(params.target, "C:\\Windows\\System32\\notepad.exe");
                assert_eq!(params.wait_ms, 1500);
            }
            other => panic!("expected early_bird, got {other:?}"),
        }
        let payload = plan.build.payloads.get("payload").expect("the payload");
        assert_eq!(payload.format, PayloadFormat::Shellcode);
    }

    /// Every Execution technique must assemble a plan the packer accepts.
    ///
    /// The wizard writes a single payload and never asks for its format, so the
    /// assembled plan must use a format the chosen technique runs
    /// (`dotnet_hosting` hosts a managed assembly; the in-process shellcode
    /// runners execute raw code) and the step's `params_example` must not name
    /// a payload the plan does not declare.
    #[test]
    fn every_execution_technique_assembles_a_valid_plan() {
        use crate::plan::validate;

        for def in execution_defs() {
            let answers = Answers {
                name: "demo".to_string(),
                payload_args: Vec::new(),
                execution: default_step(def).expect("params_example parses"),
                preparations: Vec::new(),
                additional_steps: Vec::new(),
                strings_strategy: "xor".to_string(),
                syscalls_mode: "none".to_string(),
                output_path: "./dist/demo_packed.exe".to_string(),
                output_kind: OutputKind::Exe,
                dll_entry: DllEntry::Auto,
                arch: "x64".to_string(),
                strip: true,
                trim_paths: TrimPaths::All,
            };

            let plan = assemble(Path::new("payload.exe"), &answers);
            let payload = plan.build.payloads.get("payload").expect("the payload");
            assert_eq!(
                payload.format,
                default_format(&answers.execution),
                "{}: the payload format must be one the technique runs",
                def.name
            );
            validate::validate(&plan).unwrap_or_else(|e| panic!("{}: {e}", def.name));
        }
    }

    /// The wizard names its payload after the input file, so an Execution
    /// technique's `params_example` must not name one: the default step would
    /// reference a payload the plan never declares.
    #[test]
    fn execution_params_examples_do_not_name_a_payload() {
        for def in execution_defs() {
            let step: RuntimeStep =
                serde_yml::from_str(def.params_example).expect("params_example parses");
            assert!(
                step.technique.payload_name().is_none(),
                "{}: params_example names a payload; the wizard's payload is named after the input \
                 file",
                def.name
            );
        }
    }

    /// A full script exercises the execution choice, a preparation with several
    /// follow-ups, the payload args and the syscall default.
    #[test]
    fn hollowing_with_a_bouncer_keeps_the_pipeline_order() {
        let dir = temp_dir("hollowing");
        let plan_path = dir.join("out.yaml");
        let answers = [
            "demo",              // name
            "a,b",               // payload args
            "2",                 // arch -> x86
            "",                  // output kind -> exe
            "process_hollowing", // execution
            "",                  // target -> default
            "1",                 // preparation: bouncer
            "",                  // bouncer mode -> all
            "",                  // bouncer on_fail -> silent
            "1,6",               // checks: hostname + not_in_vm
            "WORKSTATION-*",     // hostname
            "",                  // add another runtime step? -> no
            "",                  // strings -> xor
            "",                  // syscalls -> none (indirect is x64-only)
            "",                  // output path
            "",                  // strip
            "",                  // trim paths
            "",                  // review -> build now
        ];

        let (written, _) = session("mimikatz.exe", &answers, Some(&plan_path));
        assert!(written.is_some());

        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        assert_eq!(plan.name, "demo");
        assert_eq!(
            plan.build.payloads.get("mimikatz").expect("payload").args,
            Some(vec!["a".to_string(), "b".to_string()])
        );

        assert_eq!(plan.runtime.len(), 2);
        let TechniqueKind::Bouncer { params } = &plan.runtime[0].technique else {
            panic!("expected a bouncer first, got {:?}", plan.runtime[0]);
        };
        assert_eq!(params.mode, bouncer::Mode::All);
        assert_eq!(params.on_fail, bouncer::OnFail::Silent);
        assert_eq!(params.hostname.as_deref(), Some("WORKSTATION-*"));
        assert_eq!(params.not_in_vm, Some(true));

        let TechniqueKind::ProcessHollowing { params } = &plan.runtime[1].technique else {
            panic!(
                "expected process_hollowing second, got {:?}",
                plan.runtime[1]
            );
        };
        assert_eq!(params.target, process_hollowing::default_target());

        // The wizard can produce an x86 plan (`x86` was chosen above), and for
        // x86 it does not offer `syscalls: indirect` at all.
        assert_eq!(plan.build.output.arch, Arch::X86);
        assert!(
            plan.build.stub.syscalls.is_none(),
            "an x86 plan must not select indirect syscalls"
        );
    }

    /// A shellcode payload can run several in-process steps: the wizard appends
    /// Control and Execution steps in order, and every appended Execution step
    /// references the single payload.
    #[test]
    fn a_multi_step_runtime_appends_steps_in_order() {
        let dir = temp_dir("multistep");
        let plan_path = dir.join("out.yaml");
        let answers = [
            "demo",                // name
            "",                    // payload args
            "",                    // arch -> x64
            "",                    // output kind -> exe
            "fibers",              // execution (a shellcode runner)
            "",                    // preparations -> none
            "y",                   // add another runtime step? -> yes
            "sleep",               // append step -> sleep (menu #1)
            "500",                 // sleep ms
            "y",                   // add another runtime step? -> yes
            "living_off_the_land", // append step -> exec (menu #2)
            "certutil.exe",        // binary
            "-urlcache,-f",        // args
            "y",                   // add another runtime step? -> yes
            "module_stomping",     // append step -> module_stomping (menu #4)
            "dbghelp.dll",         // module
            "",                    // add another runtime step? -> no
            "",                    // strings
            "",                    // syscalls
            "",                    // output path
            "",                    // strip
            "",                    // trim paths
            "",                    // review -> build now
        ];

        let (written, _) = session("payload.exe", &answers, Some(&plan_path));
        assert_eq!(written.as_deref(), Some(plan_path.as_path()));

        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        assert_eq!(plan.runtime.len(), 4);

        let TechniqueKind::Fibers { params } = &plan.runtime[0].technique else {
            panic!("expected fibers first, got {:?}", plan.runtime[0]);
        };
        assert_eq!(params.payload, None);

        let TechniqueKind::Sleep { params } = &plan.runtime[1].technique else {
            panic!("expected sleep second, got {:?}", plan.runtime[1]);
        };
        assert_eq!(params.ms, 500);

        let TechniqueKind::LivingOffTheLand { params } = &plan.runtime[2].technique else {
            panic!(
                "expected living_off_the_land third, got {:?}",
                plan.runtime[2]
            );
        };
        assert_eq!(params.binary, "certutil.exe");
        assert_eq!(params.args, vec!["-urlcache", "-f"]);

        let TechniqueKind::ModuleStomping { params } = &plan.runtime[3].technique else {
            panic!("expected module_stomping fourth, got {:?}", plan.runtime[3]);
        };
        assert_eq!(params.module, "dbghelp.dll");
        assert_eq!(params.payload, None);

        // Every appended step still references the one wizard payload.
        let payload = plan.build.payloads.get("payload").expect("the payload");
        assert_eq!(payload.format, PayloadFormat::Shellcode);
    }

    /// A terminal execution (`reflective_loading` of a PE executable) hands the
    /// process to the payload, so the wizard must not offer to append a step
    /// after it.
    #[test]
    fn a_terminal_execution_offers_no_further_steps() {
        let dir = temp_dir("terminal");
        let plan_path = dir.join("out.yaml");
        let answers = ["", "", "", "", "", "", "", "", "", "", "", ""];

        let (written, transcript) = session("payload.exe", &answers, Some(&plan_path));
        assert_eq!(written.as_deref(), Some(plan_path.as_path()));

        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        assert_eq!(plan.runtime.len(), 1);
        assert!(
            !transcript.contains("add another runtime step"),
            "a terminal execution must not offer appended steps: {transcript}"
        );
    }

    /// `kind: dll` turns the wizard into a DLL build: it asks for the entry, the
    /// default path carries the `.dll` extension, and the preparations that act
    /// on the running image are not offered (a DLL's image is the host's).
    #[test]
    fn a_dll_build_asks_for_the_entry_and_hides_image_scoped_preparations() {
        let dir = temp_dir("dll");
        let plan_path = dir.join("out.yaml");
        let answers = [
            "demo",   // name
            "",       // payload args
            "",       // arch -> x64
            "dll",    // output kind
            "",       // execution -> reflective_loading
            "",       // preparation -> none
            "",       // strings
            "",       // syscalls
            "export", // entry
            "Start",  // export name
            "",       // output path -> default
            "",       // strip
            "",       // trim paths
            "",       // review -> build now
        ];

        let (written, transcript) = session("payload.exe", &answers, Some(&plan_path));
        assert_eq!(written.as_deref(), Some(plan_path.as_path()));

        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        let output = &plan.build.output;
        assert_eq!(output.kind, OutputKind::Dll);
        assert_eq!(output.entry, DllEntry::Export("Start".to_string()));
        assert_eq!(
            output.path,
            PathBuf::from("./dist/demo_packed.dll"),
            "a DLL build defaults to the `.dll` extension"
        );

        // `self_deletion` and `sleep_obfuscation` rewrite the running image,
        // which in a DLL build is the host, so `plan::validate` rejects them and
        // the wizard must not offer them at all.
        assert!(
            !transcript.contains("self_deletion") && !transcript.contains("sleep_obfuscation"),
            "image-scoped preparations must be hidden in a DLL build: {transcript}"
        );
    }

    /// A DLL build never offers `bouncer`'s `on_fail: exit` (which would kill the
    /// host process), so the bouncer question flow is one prompt shorter.
    #[test]
    fn a_dll_build_never_offers_the_process_killing_bouncer_rejection() {
        use crate::techniques::bouncer;

        let dir = temp_dir("dll_bouncer");
        let plan_path = dir.join("out.yaml");
        let answers = [
            "demo", // name
            "",     // payload args
            "",     // arch -> x64
            "dll",  // output kind
            "",     // execution -> reflective_loading
            "1",    // preparation: bouncer
            "",     // bouncer mode -> all
            "1",    // checks: hostname
            "PC-*", // hostname
            "",     // strings
            "",     // syscalls
            "",     // entry -> auto
            "",     // output path
            "",     // strip
            "",     // trim paths
            "",     // review -> build now
        ];

        let (written, _) = session("payload.exe", &answers, Some(&plan_path));
        assert_eq!(written.as_deref(), Some(plan_path.as_path()));

        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        let TechniqueKind::Bouncer { params } = &plan.runtime[0].technique else {
            panic!("expected a bouncer first, got {:?}", plan.runtime[0]);
        };
        assert_eq!(params.mode, bouncer::Mode::All);
        assert_eq!(params.hostname.as_deref(), Some("PC-*"));
        assert_eq!(
            params.on_fail,
            bouncer::OnFail::Silent,
            "a DLL build must never select the exiting rejection"
        );
        assert_eq!(plan.build.output.kind, OutputKind::Dll);
    }

    /// Choosing `edit answers` at the review re-asks the questions with the
    /// previous values as defaults, so a single field can be corrected.
    #[test]
    fn editing_answers_updates_a_single_field() {
        let dir = temp_dir("edit");
        let plan_path = dir.join("out.yaml");
        let answers = [
            "first",  // name
            "",       // payload args
            "",       // arch
            "",       // output kind
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
            "",       // arch
            "",       // output kind
            "",       // execution
            "",       // preparation
            "",       // strings
            "",       // syscalls
            "",       // output path
            "",       // strip
            "",       // trim paths
            "",       // review -> build now
        ];

        let (written, _) = session("payload.exe", &answers, Some(&plan_path));
        assert!(written.is_some());

        let plan = load_plan(&plan_path, &BTreeMap::new()).expect("valid plan");
        assert_eq!(plan.name, "second");
    }

    /// Choosing `quit` at the review leaves the disk untouched.
    #[test]
    fn quitting_the_review_writes_nothing() {
        let dir = temp_dir("aborted");
        let plan_path = dir.join("out.yaml");
        let answers = ["", "", "", "", "", "", "", "", "", "", "", "3"];

        let (written, _) = session("payload.exe", &answers, Some(&plan_path));

        assert!(written.is_none());
        assert!(!plan_path.exists(), "the plan must not be written");
    }

    /// A closed stdin mid-session is an error, not a silent all-defaults build.
    #[test]
    fn truncated_input_is_an_error() {
        let dir = temp_dir("truncated");
        let plan_path = dir.join("out.yaml");
        let err = run_with(
            Path::new("payload.exe"),
            Some(&plan_path),
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
