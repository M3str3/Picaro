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
use crate::engine::syscalls::{YamlStackSpoofing, YamlSyscallsPlan};
use crate::error::{PackerError, Result};
use crate::plan::schema::{
    Arch, BuildPlan, ConsoleMode, CryptoAlgorithm, CryptoPlan, DllEntry, KeySource, OutputKind,
    OutputPlan, PayloadFormat, PayloadPlan, Plan, StubPlan, Subsystem, TrimPaths, SUPPORTED_SCHEMA,
};
use crate::plan::validate;

mod helpers;
mod prompt;

use crate::techniques::{
    self, anti_debug, bouncer, early_bird, living_off_the_land, module_stomping, patch_amsi,
    patch_etw, pe_injection, ppid_spoofing, process_hollowing, reflective_loading, sleep,
    sleep_obfuscation, Capability, Category, RuntimeStep, TechniqueDef, TechniqueKind,
};
use crate::ui::Palette;
use helpers::*;
use prompt::*;

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
        section: 0,
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
        wizard.section_at(7, "REVIEW")?;
        let preview = wizard.ui.dim(yaml.trim_end());
        wizard.echo(&preview)?;
        wizard.blank()?;

        let choice = match wizard.prompts.select(
            "what now",
            &[
                ("build now", "write the plan and run the build"),
                ("edit answers", "go back and change something"),
                ("quit", "discard and exit"),
            ],
            0,
        ) {
            Ok(choice) => choice,
            // Esc at the review is the same as "edit answers": go back to the
            // first section with the current answers as defaults.
            Err(PackerError::Back) => {
                answers = wizard.ask_all(Some(&answers))?;
                continue;
            }
            Err(error) => return Err(error),
        };
        match choice {
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
    /// Payload format sniffed from the file (PE, DLL, .NET, shellcode or a
    /// PowerShell script). The wizard does not ask: the file decides, and the
    /// runtime editor only offers techniques that accept it.
    payload_format: PayloadFormat,
    /// The runtime chain, in the order the stub runs it. Preparations, the
    /// execution technique and controls can be mixed freely; `plan::validate`
    /// enforces the model limits (terminal step, conflicts, formats).
    runtime: Vec<TechniqueKind>,
    strings_strategy: String,
    syscalls_mode: String,
    /// `build.stub.syscalls.resolver` (`hells_gate`, `tartarus_gate`,
    /// `api_hash`, `halos_gate`); only meaningful with `mode: indirect`.
    syscalls_resolver: String,
    /// `build.stub.syscalls.stack_spoofing`; only with `mode: indirect`.
    stack_spoofing: bool,
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

/// The answers collected so far, one `Option` per field.
///
/// The form is sectioned and can go back, so it fills this incrementally; at the
/// end every field is present and [`Partial::into_answers`] returns the typed
/// [`Answers`]. Seeding it from a previous pass is what makes `edit answers`
/// reuse the old values.
#[derive(Debug, Clone, Default)]
struct Partial {
    name: Option<String>,
    payload_args: Option<Vec<String>>,
    payload_format: Option<PayloadFormat>,
    arch: Option<String>,
    output_kind: Option<OutputKind>,
    runtime: Option<Vec<TechniqueKind>>,
    strings_strategy: Option<String>,
    syscalls_mode: Option<String>,
    syscalls_resolver: Option<String>,
    stack_spoofing: Option<bool>,
    output_path: Option<String>,
    dll_entry: Option<DllEntry>,
    strip: Option<bool>,
    trim_paths: Option<TrimPaths>,
}

impl Partial {
    fn from_answers(answers: &Answers) -> Self {
        Self {
            name: Some(answers.name.clone()),
            payload_args: Some(answers.payload_args.clone()),
            payload_format: Some(answers.payload_format),
            arch: Some(answers.arch.clone()),
            output_kind: Some(answers.output_kind),
            runtime: Some(answers.runtime.clone()),
            strings_strategy: Some(answers.strings_strategy.clone()),
            syscalls_mode: Some(answers.syscalls_mode.clone()),
            syscalls_resolver: Some(answers.syscalls_resolver.clone()),
            stack_spoofing: Some(answers.stack_spoofing),
            output_path: Some(answers.output_path.clone()),
            dll_entry: Some(answers.dll_entry.clone()),
            strip: Some(answers.strip),
            trim_paths: Some(answers.trim_paths),
        }
    }

    fn into_answers(self) -> Result<Answers> {
        let missing =
            |field: &str| PackerError::Validation(format!("wizard is missing the {field} answer"));
        Ok(Answers {
            name: self.name.ok_or_else(|| missing("name"))?,
            payload_args: self
                .payload_args
                .ok_or_else(|| missing("payload arguments"))?,
            payload_format: self
                .payload_format
                .ok_or_else(|| missing("payload format"))?,
            runtime: self.runtime.ok_or_else(|| missing("runtime chain"))?,
            strings_strategy: self
                .strings_strategy
                .ok_or_else(|| missing("strings strategy"))?,
            syscalls_mode: self.syscalls_mode.ok_or_else(|| missing("syscall mode"))?,
            syscalls_resolver: self
                .syscalls_resolver
                .ok_or_else(|| missing("syscall resolver"))?,
            stack_spoofing: self
                .stack_spoofing
                .ok_or_else(|| missing("stack spoofing"))?,
            output_path: self.output_path.ok_or_else(|| missing("output path"))?,
            output_kind: self.output_kind.ok_or_else(|| missing("output kind"))?,
            dll_entry: self.dll_entry.ok_or_else(|| missing("DLL entry"))?,
            arch: self.arch.ok_or_else(|| missing("architecture"))?,
            strip: self.strip.ok_or_else(|| missing("strip symbols"))?,
            trim_paths: self.trim_paths.ok_or_else(|| missing("path trimming"))?,
        })
    }
}

/// The wizard: the prompt backend plus the [`Palette`] for its own headings.
struct Wizard<'a> {
    ui: Palette,
    prompts: &'a mut dyn Prompt,
    payload: PathBuf,
    plan_out: Option<PathBuf>,
    /// Number of the section being asked (1-based, for the heading).
    section: usize,
}

impl Wizard<'_> {
    fn blank(&mut self) -> Result<()> {
        self.prompts.echo("")
    }

    fn echo(&mut self, line: &str) -> Result<()> {
        self.prompts.echo(line)
    }

    /// Prints a numbered section heading. The number is explicit because going
    /// back re-asks a section: a counter would keep growing.
    fn section_at(&mut self, number: usize, title: &str) -> Result<()> {
        self.section = number;
        let heading = self.ui.heading(format!("{number}. {title}"));
        self.prompts.echo(&heading)
    }

    /// Shows what a chosen technique does, after the menu.
    ///
    /// The menus carry names only (all the descriptions on one line were
    /// unreadable); this block is where the summary, stability, ATT&CK id and
    /// requirements go.
    fn announce(&mut self, def: &TechniqueDef) -> Result<()> {
        self.blank()?;
        let heading = self.ui.heading(def.name);
        self.echo(&heading)?;
        let mut meta = vec![def.stability.label().to_string()];
        if !def.attck.is_empty() {
            meta.push(def.attck.join(", "));
        }
        if !def.requires.is_empty() {
            meta.push(techniques::capabilities(def.requires));
        }
        let meta = self.ui.dim(meta.join(" \u{00b7} "));
        self.echo(&meta)?;
        let summary = self.ui.dim(techniques::summary(def));
        self.echo(&summary)?;
        Ok(())
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
    ///
    /// Each section is re-askable: `Esc` (interactive) or `:b` (line backend)
    /// returns to the previous section, keeping what was already answered as
    /// defaults. On the first section it cancels.
    fn ask_all(&mut self, previous: Option<&Answers>) -> Result<Answers> {
        let mut state = previous.map(Partial::from_answers).unwrap_or_default();
        let mut position = 0usize;
        loop {
            let step = match position {
                0 => self.ask_payload_section(&mut state),
                1 => self.ask_stub_section(&mut state),
                2 => self.ask_runtime_section(&mut state),
                3 => self.ask_output_section(&mut state),
                _ => break,
            };
            match step {
                Ok(()) => position += 1,
                Err(PackerError::Back) => {
                    if position == 0 {
                        return Err(PackerError::Cancelled);
                    }
                    position -= 1;
                }
                Err(error) => return Err(error),
            }
        }
        state.into_answers()
    }

    /// Payload identity, architecture and output kind.
    fn ask_payload_section(&mut self, state: &mut Partial) -> Result<()> {
        self.section_at(1, "PAYLOAD")?;
        self.echo_field("source", &self.payload.display().to_string())?;
        let format = crate::plan::format::detect(&self.payload);
        state.payload_format = Some(format);
        self.echo_field("format", &format!("{} (detected)", format_label(format)))?;

        let default_name = state
            .name
            .clone()
            .unwrap_or_else(|| default_name(&self.payload));
        state.name = Some(self.ask_text("name", &default_name)?);

        let payload_args = state.payload_args.clone().unwrap_or_default();
        state.payload_args = Some(self.ask_list("payload args (comma-separated)", &payload_args)?);

        // Asked before the techniques: the stub and the payload share an
        // architecture, and `syscalls: indirect` is x64-only.
        let arch_default = usize::from(state.arch.as_deref() == Some("x86"));
        state.arch = Some(
            match self.ask_select(
                "arch",
                &[
                    ("x64", "64-bit stub and payload (the default)"),
                    (
                        "x86",
                        "32-bit stub and payload; runs under WOW64 on 64-bit Windows",
                    ),
                ],
                arch_default,
            )? {
                0 => "x64".to_string(),
                _ => "x86".to_string(),
            },
        );

        // The output kind gates which techniques are runnable — a DLL lives in a
        // host process and must not touch that process's image — so it is asked
        // before the techniques, for the same reason as `arch`.
        let previous_kind = state.output_kind;
        let kind_default = match previous_kind {
            Some(OutputKind::Dll) => 1,
            Some(OutputKind::Shellcode) => 2,
            _ => 0,
        };
        let kind = match self.ask_select(
            "output kind",
            &[
                ("exe", "a standalone executable (the default)"),
                (
                    "dll",
                    "a DLL a host process loads (ctypes, P/Invoke, a JVM)",
                ),
                (
                    "shellcode",
                    "position-independent code wrapped in a reflective loader",
                ),
            ],
            kind_default,
        )? {
            0 => OutputKind::Exe,
            1 => OutputKind::Dll,
            _ => OutputKind::Shellcode,
        };
        if previous_kind.is_some_and(|previous| previous != kind) {
            // The generated path carries the extension; a kind change invalidates
            // the previous default.
            state.output_path = None;
        }
        state.output_kind = Some(kind);
        Ok(())
    }

    /// Loader-wide configuration: strings and the syscall layer.
    fn ask_stub_section(&mut self, state: &mut Partial) -> Result<()> {
        self.section_at(2, "STUB")?;
        let strings_default = usize::from(state.strings_strategy.as_deref() == Some("stack"));
        state.strings_strategy = Some(
            match self.ask_select(
                "strings",
                &[
                    ("xor", "single-byte XOR per string, with a random key"),
                    ("stack", "decoder-free, built on the stack"),
                ],
                strings_default,
            )? {
                0 => "xor".to_string(),
                _ => "stack".to_string(),
            },
        );

        // `indirect` needs the x64 trampoline, so an x86 plan never offers it.
        let arch = state.arch.clone().unwrap_or_else(|| "x64".to_string());
        let mut syscall_options: Vec<(&str, &str)> = vec![("none", "call the Win32 APIs directly")];
        if arch != "x86" {
            syscall_options.push(("indirect", "resolve SSNs and invoke the kernel directly"));
        }
        let default_syscalls = if arch == "x86" {
            0
        } else {
            usize::from(state.syscalls_mode.as_deref() == Some("indirect"))
        };
        let mode = match self.ask_select("syscalls", &syscall_options, default_syscalls)? {
            0 => "none".to_string(),
            _ => "indirect".to_string(),
        };
        state.syscalls_mode = Some(mode.clone());

        if mode == "indirect" {
            let resolvers = [
                ("hells_gate", "scan ntdll for the SSN (the classic)"),
                (
                    "tartarus_gate",
                    "neighbour-derived SSNs (Halo's Gate family)",
                ),
                ("api_hash", "match exports by FNV-1a hash, no Nt* strings"),
                (
                    "halos_gate",
                    "derive the SSN from neighbouring stubs (experimental)",
                ),
            ];
            let default_resolver = resolvers
                .iter()
                .position(|(name, _)| Some(*name) == state.syscalls_resolver.as_deref())
                .unwrap_or(0);
            let index = self.ask_select("resolver", &resolvers, default_resolver)?;
            state.syscalls_resolver = Some(resolvers[index].0.to_string());
            state.stack_spoofing = Some(
                self.prompts
                    .confirm("stack spoofing", state.stack_spoofing.unwrap_or(false))?,
            );
        } else {
            // Keep a valid resolver for the record; `assemble` ignores it when
            // the mode is `none`.
            state.syscalls_resolver = Some("hells_gate".to_string());
            state.stack_spoofing = Some(false);
        }
        Ok(())
    }

    /// The runtime chain: any preparation, execution or control step, in the
    /// order the operator chooses.
    ///
    /// Only the model limits are enforced: single payload format, terminal
    /// step, architecture, conflicts and `requires_indirect_syscalls`.
    fn ask_runtime_section(&mut self, state: &mut Partial) -> Result<()> {
        self.section_at(3, "RUNTIME")?;
        let mut steps = state.runtime.clone().unwrap_or_default();
        loop {
            self.show_chain(&steps)?;
            let action = self.prompts.select(
                "runtime",
                &[
                    (
                        "add a step",
                        "append a preparation, execution or control technique",
                    ),
                    ("edit a step", "re-ask its parameters"),
                    ("remove a step", ""),
                    ("move a step up", ""),
                    ("move a step down", ""),
                    ("done", "accept the chain"),
                ],
                0,
            )?;
            match action {
                0 => {
                    if let Some(def) = self.ask_add_step(&steps, state)? {
                        let step = match self.ask_step_params(
                            def,
                            None,
                            state.output_kind.unwrap_or(OutputKind::Exe),
                            state.payload_format.unwrap_or(PayloadFormat::Pe),
                        ) {
                            Ok(step) => step,
                            // Esc in the params re-opens the runtime menu; Esc at
                            // the action menu leaves the section.
                            Err(PackerError::Back) => continue,
                            Err(error) => return Err(error),
                        };
                        let format = state.payload_format.unwrap_or(PayloadFormat::Pe);
                        // A terminal step must stay last: insert before it.
                        let insert_at = steps
                            .iter()
                            .position(|candidate| step_is_terminal(candidate, format))
                            .unwrap_or(steps.len());
                        steps.insert(insert_at, step);
                    }
                }
                1 => {
                    if let Some(index) = self.ask_step_index("edit", &steps)? {
                        let previous = steps[index].clone();
                        let def = techniques::find(previous.name()).ok_or_else(|| {
                            PackerError::Validation(format!(
                                "unknown technique: {}",
                                previous.name()
                            ))
                        })?;
                        match self.ask_step_params(
                            def,
                            Some(&previous),
                            state.output_kind.unwrap_or(OutputKind::Exe),
                            state.payload_format.unwrap_or(PayloadFormat::Pe),
                        ) {
                            Ok(step) => steps[index] = step,
                            Err(PackerError::Back) => continue,
                            Err(error) => return Err(error),
                        }
                    }
                }
                2 => {
                    if let Some(index) = self.ask_step_index("remove", &steps)? {
                        steps.remove(index);
                    }
                }
                3 => {
                    if let Some(index) = self.ask_step_index("move up", &steps)? {
                        if index == 0 {
                            self.notice("the first step cannot move up")?;
                        } else {
                            steps.swap(index, index - 1);
                            if !chain_ok(&steps, state.payload_format.unwrap_or(PayloadFormat::Pe))
                            {
                                steps.swap(index, index - 1);
                                self.notice("a terminal execution must stay last")?;
                            }
                        }
                    }
                }
                4 => {
                    if let Some(index) = self.ask_step_index("move down", &steps)? {
                        if index + 1 >= steps.len() {
                            self.notice("the last step cannot move down")?;
                        } else {
                            steps.swap(index, index + 1);
                            if !chain_ok(&steps, state.payload_format.unwrap_or(PayloadFormat::Pe))
                            {
                                steps.swap(index, index + 1);
                                self.notice("a terminal execution must stay last")?;
                            }
                        }
                    }
                }
                _ => {
                    if !steps
                        .iter()
                        .any(|step| step.category() == Category::Execution)
                    {
                        self.notice("add an execution technique before finishing")?;
                        continue;
                    }
                    break;
                }
            }
        }
        state.runtime = Some(steps);
        Ok(())
    }

    fn show_chain(&mut self, steps: &[TechniqueKind]) -> Result<()> {
        self.blank()?;
        if steps.is_empty() {
            let line = self.ui.dim("  (empty)");
            return self.echo(&line);
        }
        for (index, step) in steps.iter().enumerate() {
            let category =
                techniques::find(step.name()).map_or("unknown", |def| def.category.label());
            let label = format!("{}. {}", index + 1, step.name());
            let line = self.ui.field(&label, self.ui.dim(category));
            self.echo(&line)?;
        }
        Ok(())
    }

    fn ask_add_step(
        &mut self,
        steps: &[TechniqueKind],
        state: &Partial,
    ) -> Result<Option<&'static TechniqueDef>> {
        let (available, unavailable) = eligible_steps(steps, state);
        if !unavailable.is_empty() {
            let line = self
                .ui
                .dim(format!("unavailable: {}", unavailable.join("; ")));
            self.echo(&line)?;
        }
        if available.is_empty() {
            self.notice("no technique can be added to this chain")?;
            return Ok(None);
        }
        let options: Vec<(&str, &str)> = available
            .iter()
            .map(|def| (def.name, def.category.label()))
            .collect();
        let index = self.prompts.select("add", &options, 0)?;
        Ok(Some(available[index]))
    }

    fn ask_step_index(&mut self, label: &str, steps: &[TechniqueKind]) -> Result<Option<usize>> {
        if steps.is_empty() {
            self.notice("the chain is empty")?;
            return Ok(None);
        }
        let options: Vec<(&str, &str)> = steps.iter().map(|step| (step.name(), "")).collect();
        Ok(Some(self.prompts.select(label, &options, 0)?))
    }

    /// One parameter pass for any step, dispatched by category.
    fn ask_step_params(
        &mut self,
        def: &TechniqueDef,
        previous: Option<&TechniqueKind>,
        kind: OutputKind,
        format: PayloadFormat,
    ) -> Result<TechniqueKind> {
        self.announce(def)?;
        match def.category {
            Category::Preparation => self.ask_preparation(def, previous, kind),
            Category::Execution => self.ask_execution_params(def, previous, format),
            Category::Control => self.ask_control_params(def, previous),
        }
    }

    fn ask_control_params(
        &mut self,
        def: &TechniqueDef,
        previous: Option<&TechniqueKind>,
    ) -> Result<TechniqueKind> {
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
            "ppid_spoofing" => {
                let default = ppid_spoofing::Params::default();
                let (binary, args, parent, wait) = match previous {
                    Some(TechniqueKind::PpidSpoofing { params }) => (
                        params.binary.clone(),
                        params.args.clone(),
                        params.parent.clone(),
                        params.wait,
                    ),
                    _ => (default.binary, default.args, default.parent, default.wait),
                };
                let binary = self.ask_text("binary", &binary)?;
                let args = self.ask_list("args (comma-separated)", &args)?;
                let parent = self.ask_text("parent", &parent)?;
                let wait = self.prompts.confirm("wait for the child", wait)?;
                Ok(TechniqueKind::PpidSpoofing {
                    params: ppid_spoofing::Params {
                        binary,
                        args,
                        parent,
                        wait,
                    },
                })
            }
            "network_stager" => {
                let default_url = match previous {
                    Some(TechniqueKind::NetworkStager { params }) => params.url.clone(),
                    _ => "https://example.invalid/payload.bin".to_string(),
                };
                let url = self.ask_text("url", &default_url)?;
                let mut step = default_step(def)?;
                if let TechniqueKind::NetworkStager { params } = &mut step {
                    params.payload = default_name(&self.payload);
                    params.url = url;
                }
                Ok(step)
            }
            _ => default_step(def),
        }
    }

    fn ask_output_section(&mut self, state: &mut Partial) -> Result<()> {
        self.section_at(4, "OUTPUT")?;
        let kind = state.output_kind.unwrap_or(OutputKind::Exe);
        let default_export = match state.dll_entry.as_ref() {
            Some(DllEntry::Export(name)) => name.clone(),
            _ => DllEntry::AUTO_EXPORT.to_string(),
        };
        // `entry` only applies to a DLL; an executable starts at `main`.
        let dll_entry = if kind == OutputKind::Dll {
            let default_entry = state.dll_entry.as_ref().map_or(0, dll_entry_index);
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
                2 => DllEntry::Export(self.ask_text("export name", &default_export)?),
                _ => DllEntry::Auto,
            }
        } else {
            DllEntry::Auto
        };
        state.dll_entry = Some(dll_entry);

        // A DLL the host loads carries the `.dll` extension, an executable
        // `.exe`; a path the operator typed is kept as-is.
        let name = state
            .name
            .clone()
            .unwrap_or_else(|| default_name(&self.payload));
        let default_output = state
            .output_path
            .clone()
            .unwrap_or_else(|| format!("./dist/{name}_packed.{}", kind.extension()));
        state.output_path = Some(self.ask_text("output path", &default_output)?);
        state.strip = Some(
            self.prompts
                .confirm("strip symbols", state.strip.unwrap_or(true))?,
        );
        let trim_default = state.trim_paths.map_or(0, trim_index);
        state.trim_paths = Some(
            match self.ask_select(
                "trim paths",
                &[
                    ("all", "remap every absolute path in the debug info"),
                    ("none", "leave paths untouched"),
                    ("relative", "remap only paths outside the project"),
                ],
                trim_default,
            )? {
                0 => TrimPaths::All,
                1 => TrimPaths::None,
                _ => TrimPaths::Relative,
            },
        );
        Ok(())
    }

    fn ask_select(
        &mut self,
        label: &str,
        options: &[(&str, &str)],
        default: usize,
    ) -> Result<usize> {
        self.prompts.select(label, options, default)
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
        format: PayloadFormat,
    ) -> Result<TechniqueKind> {
        match def.name {
            "reflective_loading" => {
                let (erase_header, default_patch_exit) = match previous {
                    Some(TechniqueKind::ReflectiveLoading { params }) => {
                        (params.erase_header, params.patch_exit)
                    }
                    _ => (false, false),
                };
                // Raw shellcode has no import table, so `patch_exit` does not
                // apply and `plan::validate` rejects it.
                let patch_exit = if format.is_pe_image() {
                    self.prompts.confirm(
                        "patch exit calls (keep the chain running)",
                        default_patch_exit,
                    )?
                } else {
                    false
                };
                Ok(TechniqueKind::ReflectiveLoading {
                    params: reflective_loading::Params {
                        payload: None,
                        erase_header,
                        patch_exit,
                    },
                })
            }
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

    /// Asks the parameters of one preparation technique.
    fn ask_preparation(
        &mut self,
        def: &TechniqueDef,
        previous: Option<&TechniqueKind>,
        kind: OutputKind,
    ) -> Result<TechniqueKind> {
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

    /// The bouncer gate: what to do on rejection and which requirements to
    /// declare (each with its own value question).
    fn ask_bouncer(
        &mut self,
        previous: Option<&bouncer::Params>,
        kind: OutputKind,
    ) -> Result<bouncer::Params> {
        // `action: exit` calls `std::process::exit`, which would kill the host
        // process, so a DLL build only offers `abort`.
        let action = if kind == OutputKind::Dll {
            bouncer::RejectAction::Abort
        } else {
            match self.ask_select(
                "on_reject.action",
                &[
                    ("abort", "stop with exit code 0"),
                    ("exit", "stop with exit code 1"),
                ],
                matches!(
                    previous.map(|params| params.on_reject.action),
                    Some(bouncer::RejectAction::Exit)
                )
                .into(),
            )? {
                0 => bouncer::RejectAction::Abort,
                _ => bouncer::RejectAction::Exit,
            }
        };

        let checks: [(&str, &str); 13] = [
            ("hostname", "required computer name (glob)"),
            ("username", "required user name (glob)"),
            ("domain", "required DNS domain (glob)"),
            ("language", "accepted BCP-47 locales"),
            ("keyboard", "accepted 4-digit layout codes"),
            ("ip", "accepted local IPv4/IPv6 CIDRs"),
            ("elevation", "required token elevation"),
            ("integrity", "accepted token integrity levels"),
            ("privilege", "privilege enabled in the token"),
            ("hypervisor", "require no hypervisor (CPUID)"),
            ("sandbox", "require the sandbox heuristic to pass"),
            ("uptime_min", "minimum uptime, in minutes"),
            ("ram_mb", "minimum physical memory, in MiB"),
        ];
        let previous_checks = PreviousChecks::from_params(previous);
        let default: Vec<usize> = checks
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| previous_checks.is_declared(name))
            .map(|(index, _)| index)
            .collect();
        let selected = self.prompts.multi_select("checks", &checks, &default)?;

        let mut params = bouncer::Params {
            on_reject: bouncer::OnReject {
                action,
                ..Default::default()
            },
            ..Default::default()
        };
        for index in selected {
            match checks[index].0 {
                "hostname" => {
                    if let Some(value) =
                        self.ask_optional_text("hostname", previous_checks.hostname)?
                    {
                        params.require.push(bouncer::Requirement::Hostname(value));
                    }
                }
                "username" => {
                    if let Some(value) =
                        self.ask_optional_text("username", previous_checks.username)?
                    {
                        params.require.push(bouncer::Requirement::Username(value));
                    }
                }
                "domain" => {
                    if let Some(value) = self.ask_optional_text("domain", previous_checks.domain)? {
                        params.require.push(bouncer::Requirement::Domain(value));
                    }
                }
                "language" => {
                    let values = self.ask_list("language", previous_checks.locale)?;
                    if !values.is_empty() {
                        params.require.push(bouncer::Requirement::Locale(values));
                    }
                }
                "keyboard" => {
                    let values = self.ask_list("keyboard", previous_checks.keyboard)?;
                    if !values.is_empty() {
                        params.require.push(bouncer::Requirement::Keyboard(values));
                    }
                }
                "ip" => {
                    let values = self.ask_list("ip (CIDRs)", previous_checks.ip)?;
                    if !values.is_empty() {
                        params.require.push(bouncer::Requirement::Ip(values));
                    }
                }
                "elevation" => {
                    let elevation = match self.ask_select(
                        "elevation",
                        &[
                            ("elevated", "require an elevated token"),
                            ("unelevated", "require an unelevated token"),
                        ],
                        matches!(
                            previous_checks.elevation,
                            Some(bouncer::Elevation::Unelevated)
                        )
                        .into(),
                    )? {
                        0 => bouncer::Elevation::Elevated,
                        _ => bouncer::Elevation::Unelevated,
                    };
                    params
                        .require
                        .push(bouncer::Requirement::Elevation(elevation));
                }
                "integrity" => {
                    const LEVELS: [bouncer::IntegrityLevel; 4] = [
                        bouncer::IntegrityLevel::Low,
                        bouncer::IntegrityLevel::Medium,
                        bouncer::IntegrityLevel::High,
                        bouncer::IntegrityLevel::System,
                    ];
                    let options: [(&str, &str); 4] = [
                        ("low", "low integrity"),
                        ("medium", "medium integrity"),
                        ("high", "high integrity"),
                        ("system", "SYSTEM integrity"),
                    ];
                    let default: Vec<usize> = LEVELS
                        .iter()
                        .enumerate()
                        .filter(|(_, level)| previous_checks.integrity.contains(level))
                        .map(|(index, _)| index)
                        .collect();
                    let selected = self.prompts.multi_select("integrity", &options, &default)?;
                    let values: Vec<bouncer::IntegrityLevel> = selected
                        .into_iter()
                        .filter_map(|index| LEVELS.get(index).copied())
                        .collect();
                    if !values.is_empty() {
                        params.require.push(bouncer::Requirement::Integrity(values));
                    }
                }
                "privilege" => {
                    if let Some(value) =
                        self.ask_optional_text("privilege", previous_checks.privilege)?
                    {
                        params.require.push(bouncer::Requirement::Privilege(value));
                    }
                }
                // The two heuristics are hard vetoes, not `require` entries.
                "hypervisor" => params.anti_analysis.hypervisor = true,
                "sandbox" => params.anti_analysis.sandbox = true,
                "uptime_min" => {
                    if let Some(value) = self.ask_optional_number(
                        "uptime_min",
                        u32::MAX as u64,
                        previous_checks.uptime_min,
                    )? {
                        params.require.push(bouncer::Requirement::UptimeMin(value));
                    }
                }
                "ram_mb" => {
                    if let Some(value) =
                        self.ask_optional_number("ram_mb", u32::MAX as u64, previous_checks.ram_mb)?
                    {
                        params.require.push(bouncer::Requirement::RamMb(value));
                    }
                }
                _ => {}
            }
        }
        Ok(params)
    }
}

#[cfg(test)]
mod tests;
