//! Interactive `build` wizard (`batesian build interactive <payload>`).
//!
//! The wizard walks through the same decisions a schema-3 YAML encodes
//! (payload, techniques, stub and output), assembles a [`Config`], shows it and
//! writes it to disk. It then hands the file back to the normal build flow, so
//! the generated YAML is the single source of truth: editing it and running
//! `batesian build <file>` reproduces the build without any prompts.
//!
//! Prompts are answered on stdin and every value the stub will carry at runtime
//! (target path, bouncer checks, payload args) goes through the same YAML
//! validation as a hand-written config, so the wizard can never emit a document
//! the packer would reject. Only the questions are interactive: the format,
//! defaults and string obfuscation come from the existing code, keeping a single
//! implementation of each rule.
//!
//! The prompt primitives live in [`Prompter`], generic over the input reader and
//! the output writer so the whole session is testable end to end.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::config::schema::{
    Arch, BuildConfig, Config, CryptoAlgorithm, CryptoConfig, KeySource, OutputConfig,
    PayloadConfig, StubConfig, TrimPaths, SUPPORTED_SCHEMA,
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

/// Runs the wizard against stdin/stdout.
///
/// Returns the path of the written YAML, or `None` when the operator declined
/// the final confirmation (nothing is written in that case). The payload path is
/// checked before the first question so a typo fails before a dozen prompts.
pub fn run(payload: &Path, config_out: Option<&Path>, ui: &Palette) -> Result<Option<PathBuf>> {
    if !payload.is_file() {
        return Err(PackerError::Validation(format!(
            "payload does not exist: {}",
            payload.display()
        )));
    }

    let stdin = std::io::stdin();
    let stdout = anstream::stdout();
    run_with(payload, config_out, ui, stdin.lock(), stdout)
}

/// Testable core of [`run`]: reads answers from `reader`, prompts into `out`.
pub fn run_with<R: BufRead, W: Write>(
    payload: &Path,
    config_out: Option<&Path>,
    ui: &Palette,
    reader: R,
    out: W,
) -> Result<Option<PathBuf>> {
    let mut p = Prompter {
        reader,
        out,
        ui: *ui,
    };

    let echo = p.ui.command_line("build interactive", payload.display());
    writeln!(p.out, "{echo}")?;
    p.blank()?;

    // --- Payload -----------------------------------------------------------
    p.section("PAYLOAD")?;
    p.echo_field("source", &payload.display().to_string())?;
    let name = p.ask_text("name", Some(&default_name(payload)))?;
    let payload_args = p.ask_list("payload args", "comma-separated, blank for none")?;

    // --- Techniques --------------------------------------------------------
    p.section("TECHNIQUES")?;
    let execution_choices = execution_defs();
    let execution_options = describe(&execution_choices);
    let default_execution = execution_choices
        .iter()
        .position(|def| def.name == "reflective_loading")
        .unwrap_or(0);
    let execution = execution_choices[p.ask_choice(
        "execution",
        &execution_options,
        default_execution,
    )?];

    // Syscalls only help an execution technique that routes Nt* through the
    // layer; defaulting to `indirect` otherwise would produce a warning.
    let default_syscalls = usize::from(!execution.syscalls.is_empty());

    // Ask the execution technique's own parameters right after the choice, but
    // hold the step back: preparations run first in the generated runtime.
    let execution_step = p.ask_execution(execution)?;

    let preparation_choices = preparation_defs();
    let preparation_options = describe(&preparation_choices);
    let chosen_preparations = p.ask_multi("preparation", &preparation_options)?;

    let mut runtime = Vec::new();
    for index in chosen_preparations {
        runtime.push(p.ask_preparation(preparation_choices[index])?);
    }
    runtime.push(execution_step);

    // --- Stub --------------------------------------------------------------
    p.section("STUB")?;
    let strings_strategy = match p.ask_choice(
        "strings",
        &[
            ("xor", "single-byte XOR per string, with a random key"),
            ("stack", "decoder-free, built on the stack"),
        ],
        0,
    )? {
        0 => "xor",
        _ => "stack",
    };
    let syscalls_mode = match p.ask_choice(
        "syscalls",
        &[
            ("none", "call the Win32 APIs directly"),
            ("indirect", "resolve SSNs and invoke the kernel directly"),
        ],
        default_syscalls,
    )? {
        0 => "none",
        _ => "indirect",
    };

    // --- Output ------------------------------------------------------------
    p.section("OUTPUT")?;
    let output_path = p.ask_text(
        "output path",
        Some(&format!("./dist/{name}_packed.exe")),
    )?;
    let strip = p.ask_yes_no("strip symbols", true)?;
    let trim_paths = match p.ask_choice(
        "trim paths",
        &[
            ("all", "remap every absolute path in the debug info"),
            ("none", "leave paths untouched"),
            ("relative", "remap only paths outside the project"),
        ],
        0,
    )? {
        0 => TrimPaths::All,
        1 => TrimPaths::None,
        _ => TrimPaths::Relative,
    };

    let config_path = match config_out {
        Some(path) => {
            let display = path.display().to_string();
            p.echo_field("config file", &display)?;
            path.to_path_buf()
        }
        None => PathBuf::from(p.ask_text(
            "config file",
            Some(&format!("./dist/{name}.yaml")),
        )?),
    };

    // --- Assemble, validate and confirm ------------------------------------
    let config = assemble(
        payload,
        name,
        payload_args,
        runtime,
        strings_strategy,
        syscalls_mode,
        output_path,
        strip,
        trim_paths,
    );
    validate::validate(&config)?;
    let yaml = serde_yml::to_string(&config).map_err(|source| {
        PackerError::Validation(format!("could not serialize the generated config: {source}"))
    })?;

    p.blank()?;
    p.section("CONFIG")?;
    let preview = p.ui.dim(yaml.trim_end());
    writeln!(p.out, "{preview}")?;
    p.blank()?;

    if !p.ask_yes_no("write this config and build", true)? {
        let mark = p.ui.bang();
        let message = p.ui.warn("aborted; nothing was written");
        writeln!(p.out, "  {mark} {message}")?;
        return Ok(None);
    }

    if let Some(parent) = config_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&config_path, &yaml)?;

    p.blank()?;
    let line = p
        .ui
        .done("config", p.ui.target(config_path.display().to_string()));
    writeln!(p.out, "{line}")?;
    p.blank()?;
    p.out.flush()?;

    Ok(Some(config_path))
}

/// Assembles the [`Config`] from the answered questions.
///
/// Kept pure (no I/O) so the mapping from answers to YAML is one reviewable
/// function; `runtime` arrives already ordered (preparations, then execution),
/// matching what [`validate`] requires.
#[allow(clippy::too_many_arguments)]
fn assemble(
    payload: &Path,
    name: String,
    payload_args: Vec<String>,
    runtime: Vec<RuntimeStep>,
    strings_strategy: &str,
    syscalls_mode: &str,
    output_path: String,
    strip: bool,
    trim_paths: TrimPaths,
) -> Config {
    Config {
        schema: SUPPORTED_SCHEMA,
        name,
        build: BuildConfig {
            payload: PayloadConfig {
                source: payload.display().to_string(),
                args: (!payload_args.is_empty()).then_some(payload_args),
                args_mode: ArgsMode::Join,
                crypto: CryptoConfig {
                    algo: CryptoAlgorithm::XChaCha20Poly1305,
                    key: KeySource::Random,
                },
            },
            stub: StubConfig {
                // The wizard always renders the builtin stub.
                path: None,
                // Omitted when `none` so the generated YAML stays minimal.
                syscalls: (syscalls_mode == "indirect").then(|| YamlSyscallsConfig {
                    mode: syscalls_mode.to_string(),
                    resolver: "hells_gate".to_string(),
                }),
                strings: Some(YamlStringsConfig {
                    strategy: strings_strategy.to_string(),
                    // A literal key is an advanced setting; edit it in the YAML.
                    key: "random".to_string(),
                }),
            },
            output: OutputConfig {
                path: PathBuf::from(output_path),
                // The stub is always compiled for x86-64.
                arch: Arch::X64,
                strip,
                trim_paths,
            },
        },
        runtime,
    }
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

/// The registered Execution techniques, in registry order.
fn execution_defs() -> Vec<&'static TechniqueDef> {
    techniques::all()
        .iter()
        .filter(|def| def.category == Category::Execution)
        .collect()
}

/// `(name, one-line summary)` pairs for a menu.
fn describe(defs: &[&'static TechniqueDef]) -> Vec<(&'static str, &'static str)> {
    defs.iter()
        .map(|def| (def.name, techniques::summary(def)))
        .collect()
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
    for token in input.split([',', ' ', ';']).filter(|token| !token.is_empty()) {
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

/// Reads answers from a [`BufRead`] and formats prompts into a [`Write`].
struct Prompter<R: BufRead, W: Write> {
    reader: R,
    out: W,
    ui: Palette,
}

impl<R: BufRead, W: Write> Prompter<R, W> {
    /// Reads one line, failing when the input ends mid-session.
    ///
    /// Silently accepting the defaults on EOF would build something the operator
    /// never confirmed, so a truncated input is an error.
    fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(PackerError::Validation(
                "interactive input ended before the wizard finished".to_string(),
            ));
        }
        Ok(line)
    }

    fn blank(&mut self) -> Result<()> {
        writeln!(self.out)?;
        Ok(())
    }

    fn section(&mut self, title: &str) -> Result<()> {
        let heading = self.ui.heading(title);
        writeln!(self.out, "{heading}")?;
        Ok(())
    }

    /// Prints an answered/summary value: `  label  value`.
    fn echo_field(&mut self, label: &str, value: &str) -> Result<()> {
        let line = self.ui.field(label, self.ui.dim(value));
        writeln!(self.out, "{line}")?;
        Ok(())
    }

    /// A recoverable input problem: re-ask after saying what was expected.
    fn notice(&mut self, message: &str) -> Result<()> {
        let mark = self.ui.bang();
        let text = self.ui.warn(message);
        writeln!(self.out, "    {mark} {text}")?;
        Ok(())
    }

    /// Writes a prompt (with an optional hint) and flushes it before blocking.
    fn prompt_line(&mut self, label: &str, hint: Option<String>) -> Result<()> {
        let question = self.ui.question(label);
        let hint = match hint {
            Some(hint) => format!(" {}", self.ui.dim(hint)),
            None => String::new(),
        };
        let colon = self.ui.dim(":");
        write!(self.out, "{question}{hint}{colon} ")?;
        self.out.flush()?;
        Ok(())
    }

    /// Prints a numbered menu for `options`.
    fn menu(&mut self, options: &[(&str, &str)]) -> Result<()> {
        for (index, (name, description)) in options.iter().enumerate() {
            let entry = self.ui.menu(index + 1, name, description);
            writeln!(self.out, "{entry}")?;
        }
        Ok(())
    }

    /// Asks for a required value; blank falls back to `default`.
    fn ask_text(&mut self, label: &str, default: Option<&str>) -> Result<String> {
        loop {
            self.prompt_line(label, default.map(|d| format!("[{d}]")))?;
            let line = self.read_line()?;
            let answer = line.trim();
            if !answer.is_empty() {
                return Ok(answer.to_string());
            }
            if let Some(default) = default {
                return Ok(default.to_string());
            }
            self.notice("a value is required")?;
        }
    }

    /// Asks for an optional value; blank (or EOF-free empty input) means "skip".
    fn ask_optional_text(&mut self, label: &str) -> Result<Option<String>> {
        self.prompt_line(label, Some("blank to skip".to_string()))?;
        let line = self.read_line()?;
        let answer = line.trim();
        Ok((!answer.is_empty()).then(|| answer.to_string()))
    }

    /// Asks for a comma-separated list; blank means "none".
    fn ask_list(&mut self, label: &str, hint: &str) -> Result<Vec<String>> {
        self.prompt_line(label, Some(hint.to_string()))?;
        let line = self.read_line()?;
        Ok(split_list(&line))
    }

    /// Asks a yes/no question; blank takes `default`.
    fn ask_yes_no(&mut self, label: &str, default: bool) -> Result<bool> {
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            self.prompt_line(label, Some(hint.to_string()))?;
            let line = self.read_line()?;
            match parse_yes_no(line.trim(), default) {
                Some(value) => return Ok(value),
                None => self.notice("please answer y or n")?,
            }
        }
    }

    /// Asks a single-choice question; blank takes the default index.
    fn ask_choice(
        &mut self,
        label: &str,
        options: &[(&str, &str)],
        default: usize,
    ) -> Result<usize> {
        let question = self.ui.question(label);
        writeln!(self.out, "{question}")?;
        self.menu(options)?;
        loop {
            self.prompt_line("select", Some(format!("[{}]", default + 1)))?;
            let line = self.read_line()?;
            match parse_choice(line.trim(), options, default) {
                Some(index) => return Ok(index),
                None => self.notice(&format!(
                    "enter a number between 1 and {}",
                    options.len()
                ))?,
            }
        }
    }

    /// Asks a multi-select question; blank selects nothing.
    fn ask_multi(&mut self, label: &str, options: &[(&str, &str)]) -> Result<Vec<usize>> {
        if options.is_empty() {
            return Ok(Vec::new());
        }
        let question = self.ui.question(label);
        writeln!(self.out, "{question}")?;
        self.menu(options)?;
        loop {
            self.prompt_line("select", Some("comma-separated, blank for none".to_string()))?;
            let line = self.read_line()?;
            match parse_multi(line.trim(), options) {
                Some(selected) => return Ok(selected),
                None => self.notice(&format!(
                    "enter numbers between 1 and {}",
                    options.len()
                ))?,
            }
        }
    }

    /// Asks for a bounded number; blank takes `default`.
    fn ask_number(&mut self, label: &str, default: u64, min: u64, max: u64) -> Result<u64> {
        loop {
            self.prompt_line(label, Some(format!("[{default}]")))?;
            let line = self.read_line()?;
            match parse_number(line.trim(), default, min, max) {
                Some(value) => return Ok(value),
                None => self.notice(&format!("enter a number between {min} and {max}"))?,
            }
        }
    }

    /// Asks for an optional number; blank or `0` means "skip".
    fn ask_optional_number(&mut self, label: &str, max: u64) -> Result<Option<u32>> {
        loop {
            self.prompt_line(label, Some("0 to skip".to_string()))?;
            let line = self.read_line()?;
            match parse_number(line.trim(), 0, 0, max) {
                Some(0) => return Ok(None),
                Some(value) => return Ok(Some(value as u32)),
                None => self.notice(&format!("enter a number between 0 and {max}"))?,
            }
        }
    }

    /// Asks the follow-up questions for one Preparation technique.
    fn ask_preparation(&mut self, def: &TechniqueDef) -> Result<RuntimeStep> {
        self.blank()?;
        let heading = self.ui.heading(def.name);
        let subtitle = self.ui.dim(techniques::summary(def));
        writeln!(self.out, "{heading}  {subtitle}")?;

        match def.name {
            "bouncer" => Ok(RuntimeStep::Bouncer {
                params: self.ask_bouncer()?,
            }),
            "anti_debug" => {
                let action = match self.ask_choice(
                    "action",
                    &[
                        ("abort", "never run the payload when a debugger is seen"),
                        ("continue", "note the detection and carry on"),
                    ],
                    0,
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
                let full = self.ask_yes_no("also patch EtwEventWriteFull", true)?;
                Ok(RuntimeStep::PatchEtw {
                    params: patch_etw::Params { full },
                })
            }
            "sleep_obfuscation" => {
                // Only `ekko` and `[payload]` are implemented, so the variant and
                // the encrypted regions are not questions yet.
                let sleep_ms = self.ask_number("sleep_ms", 5000, 1, u32::MAX as u64)?;
                Ok(RuntimeStep::SleepObfuscation {
                    params: sleep_obfuscation::Params {
                        variant: sleep_obfuscation::Variant::Ekko,
                        sleep_ms,
                        encrypt_regions: vec![sleep_obfuscation::EncryptRegion::Payload],
                    },
                })
            }
            // A preparation without wizard questions uses its documented
            // defaults, so a new technique still works before its prompts exist.
            _ => default_step(def),
        }
    }

    /// Asks the follow-up questions for the chosen Execution technique.
    fn ask_execution(&mut self, def: &TechniqueDef) -> Result<RuntimeStep> {
        self.blank()?;
        let heading = self.ui.heading(def.name);
        let subtitle = self.ui.dim(techniques::summary(def));
        writeln!(self.out, "{heading}  {subtitle}")?;

        match def.name {
            "process_hollowing" => {
                let target = self.ask_text("target", Some(&process_hollowing::default_target()))?;
                Ok(RuntimeStep::ProcessHollowing {
                    params: process_hollowing::Params { target },
                })
            }
            _ => default_step(def),
        }
    }

    /// The bouncer gate: how the checks combine, what to do on rejection, and
    /// which checks to declare (each with its own value question).
    fn ask_bouncer(&mut self) -> Result<bouncer::Params> {
        let mode = match self.ask_choice(
            "mode",
            &[
                ("all", "every declared check must pass"),
                ("any", "at least one declared check must pass"),
            ],
            0,
        )? {
            0 => bouncer::Mode::All,
            _ => bouncer::Mode::Any,
        };
        let on_fail = match self.ask_choice(
            "on_fail",
            &[
                ("silent", "stop with exit code 0"),
                ("exit", "stop with exit code 1"),
            ],
            0,
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
        let selected = self.ask_multi("checks", &checks)?;

        let mut params = bouncer::Params {
            mode,
            on_fail,
            ..Default::default()
        };
        for index in selected {
            match checks[index].0 {
                "hostname" => params.hostname = self.ask_optional_text("hostname")?,
                "username" => params.username = self.ask_optional_text("username")?,
                "domain" => params.domain = self.ask_optional_text("domain")?,
                "language" => params.language = self.ask_list("language", "comma-separated")?,
                "keyboard" => params.keyboard = self.ask_list("keyboard", "comma-separated")?,
                // Selecting either flag means "require it"; `false` and absent
                // skip the check alike, so there is nothing more to ask.
                "not_in_vm" => params.not_in_vm = Some(true),
                "not_in_sandbox" => params.not_in_sandbox = Some(true),
                "min_uptime_min" => {
                    params.min_uptime_min =
                        self.ask_optional_number("min_uptime_min", u32::MAX as u64)?
                }
                "min_ram_mb" => {
                    params.min_ram_mb =
                        self.ask_optional_number("min_ram_mb", u32::MAX as u64)?
                }
                _ => {}
            }
        }
        Ok(params)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use crate::config::load_config;
    use crate::techniques::{bouncer, process_hollowing};

    /// Joins answer lines the way a terminal would deliver them.
    fn script(lines: &[&str]) -> String {
        let mut input = lines.join("\n");
        input.push('\n');
        input
    }

    /// A unique, empty directory for one test's generated config.
    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("batesian_wizard_tests").join(test);
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
        (result, String::from_utf8(out).expect("the transcript is utf-8"))
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

    /// A blank script walks every menu with its defaults and produces a config
    /// the packer accepts as-is.
    #[test]
    fn defaults_produce_a_valid_reflective_config() {
        let dir = temp_dir("defaults");
        let config_path = dir.join("out.yaml");
        let answers = ["", "", "", "", "", "", "", "", "", ""];

        let (written, transcript) = session("payload.exe", &answers, Some(&config_path));

        assert_eq!(written.as_deref(), Some(config_path.as_path()));
        assert!(transcript.contains("build interactive"), "no echo: {transcript}");

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
        // No syscall-using technique, so the block stays out of the YAML.
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
            "",                  // confirm
        ];

        let (written, _) = session("mimikatz.exe", &answers, Some(&config_path));
        assert!(written.is_some());

        let config = load_config(&config_path, &BTreeMap::new()).expect("valid config");
        assert_eq!(config.name, "demo");
        assert_eq!(
            config.build.payload.args,
            Some(vec!["a".to_string(), "b".to_string()])
        );

        // Preparation first, then the execution technique.
        assert_eq!(config.runtime.len(), 2);
        let RuntimeStep::Bouncer { params } = &config.runtime[0] else {
            panic!("expected a bouncer first, got {:?}", config.runtime[0]);
        };
        assert_eq!(params.mode, bouncer::Mode::All);
        assert_eq!(params.on_fail, bouncer::OnFail::Silent);
        assert_eq!(params.hostname.as_deref(), Some("WORKSTATION-*"));
        assert_eq!(params.not_in_vm, Some(true));

        let RuntimeStep::ProcessHollowing { params } = &config.runtime[1] else {
            panic!("expected process_hollowing second, got {:?}", config.runtime[1]);
        };
        assert_eq!(params.target, process_hollowing::default_target());

        let syscalls = config.build.stub.syscalls.expect("indirect syscalls");
        assert_eq!(syscalls.mode, "indirect");
        assert_eq!(syscalls.resolver, "hells_gate");
    }

    /// Declining the confirmation leaves the disk untouched.
    #[test]
    fn declining_the_confirmation_writes_nothing() {
        let dir = temp_dir("aborted");
        let config_path = dir.join("out.yaml");
        let answers = ["", "", "", "", "", "", "", "", "", "n"];

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
