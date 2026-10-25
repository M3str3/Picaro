//! `picaro pack`: compose a schema-6 plan from flags.
//!
//! The YAML plan stays the source of truth. This module is a frontend: it turns
//! the operator's flags into a [`Plan`], serializes it next to the artifact and
//! hands it to the same loader and build path as `picaro build`, so the two
//! commands cannot disagree about defaults, validation or reproducibility.
//!
//! The generated plan is always inspectable (`--print-plan`) and, by default,
//! saved (`<output dir>/<payload>/plan.yaml`). A user who outgrows the flags
//! edits that document and continues with `picaro build`.
//!
//! Defaults can be changed in `picaro.config.yaml` (or `--config`), a small file
//! with a single `pack:` block; CLI flags always win over it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::audit::pe_info;
use crate::engine::args::ArgsMode;
use crate::engine::obfuscation::YamlStringsPlan;
use crate::engine::syscalls::{YamlStackSpoofing, YamlSyscallsPlan};
use crate::error::{PackerError, Result};
use crate::plan::schema::{
    Arch, BuildPlan, ConsoleMode, CryptoAlgorithm, CryptoPlan, DllEntry, IconPlan, KeySource,
    OutputKind, OutputPlan, PayloadFormat, PayloadPlan, Plan, ResourcesPlan, SignPlan, StubPlan,
    Subsystem, TrimPaths, SUPPORTED_SCHEMA,
};
use crate::plan::{format, load_plan_str};
use crate::techniques::{self, Category, RuntimeStep, Stability, TechniqueKind};

/// Configuration file looked up in the current directory when `--config` is
/// not passed.
pub const CONFIG_FILE: &str = "picaro.config.yaml";

/// Default root of the per-payload output folders.
pub const DEFAULT_OUTPUT_DIR: &str = "packed";

/// Name of the generated plan inside a pack folder.
pub const PLAN_FILE: &str = "plan.yaml";

/// The optional `picaro.config.yaml` document.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Defaults for `picaro pack`.
    #[serde(default)]
    pub pack: Defaults,
}

/// Defaults applied by `picaro pack` when the matching flag is absent.
///
/// Every field is optional: a missing one falls back to the built-in default
/// documented on [`compose`]. An explicit CLI flag always wins.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Output root; each payload gets a folder named after its file stem.
    pub dir: Option<PathBuf>,
    /// Execution technique, or `auto` to pick it from the payload format.
    pub exec: Option<String>,
    /// `x64` or `x86`.
    pub arch: Option<String>,
    /// `exe`, `dll`, `shellcode` or `psmodule`.
    pub kind: Option<String>,
    /// `none` or `indirect`.
    pub syscalls: Option<String>,
    /// `hells_gate`, `tartarus_gate`, `api_hash` or `halos_gate`.
    pub resolver: Option<String>,
    /// Fabricate ntdll-shaped frames around every indirect syscall.
    pub stack_spoofing: Option<bool>,
    /// `xor` or `stack`.
    pub strings: Option<String>,
    /// `none`, `lab`, `store` or `file`.
    pub sign: Option<String>,
    /// Certificate subject for `lab`/`store`.
    pub sign_subject: Option<String>,
    /// Certificate thumbprint for `store`.
    pub sign_thumbprint: Option<String>,
    /// `.pfx`/`.p12` path for `file`.
    pub sign_file: Option<PathBuf>,
    /// Environment variable holding the `.pfx` password.
    pub sign_password_env: Option<String>,
    /// RFC 3161 timestamp server.
    pub timestamp_url: Option<String>,
    /// `random` or a `.ico` path.
    pub icon: Option<String>,
    /// Strip the symbol/debug tables (default: `true`).
    pub strip: Option<bool>,
    /// Build a GUI-subsystem artifact (default: `false`).
    pub gui: Option<bool>,
    /// Save the generated plan next to the artifact (default: `true`).
    pub plan: Option<bool>,
    /// Accept non-`Stable` techniques without passing `--allow-experimental`.
    pub allow_experimental: Option<bool>,
}

/// The flags of one `picaro pack` invocation.
#[derive(Debug, Clone)]
pub struct PackArgs {
    pub payload: PathBuf,
    pub exec: Option<String>,
    pub techniques: Vec<String>,
    pub steps: Vec<PathBuf>,
    pub syscalls: Option<String>,
    pub resolver: Option<String>,
    /// `Some(true)`/`Some(false)` when `--stack-spoofing`/`--no-stack-spoofing`
    /// was passed; `None` leaves the config/default in charge.
    pub stack_spoofing: Option<bool>,
    pub strings: Option<String>,
    pub out: Option<PathBuf>,
    pub dir: Option<PathBuf>,
    pub plan_out: Option<PathBuf>,
    pub no_save_plan: bool,
    pub arch: Option<String>,
    pub kind: Option<String>,
    pub entry: Option<String>,
    pub export: Option<String>,
    pub sign: Option<String>,
    pub sign_subject: Option<String>,
    pub sign_thumbprint: Option<String>,
    pub sign_file: Option<PathBuf>,
    pub sign_password_env: Option<String>,
    pub timestamp_url: Option<String>,
    pub icon: Option<String>,
    /// `Some(true)`/`Some(false)` for `--strip`/`--no-strip`, `None` otherwise.
    pub strip: Option<bool>,
    /// `Some(true)`/`Some(false)` for `--gui`/`--console`, `None` otherwise.
    pub gui: Option<bool>,
    pub target: Option<String>,
    pub sleep_ms: Option<u64>,
    /// Compile a debuggable stub (`build.stub.debug`).
    pub debug: bool,
    pub reflective_loading: bool,
    pub hollow: bool,
    pub patch_amsi: bool,
    pub patch_etw: bool,
    pub erase_header: bool,
    pub unhook: bool,
    pub hide_module: bool,
    pub allow_experimental: bool,
}

/// A composed, validated plan and the paths the build will use.
#[derive(Debug, Clone)]
pub struct PackOutcome {
    /// The plan after going through the same loader and validator as a file.
    pub plan: Plan,
    /// Canonical YAML of [`Self::plan`], what `--print-plan` emits.
    pub plan_yaml: String,
    /// Where the plan is (or would be) written.
    pub plan_path: PathBuf,
    /// Final artifact path (`<dir>/<payload>/<payload>.exe` by default).
    pub artifact_path: PathBuf,
    /// Concrete payload format detected from the input.
    pub format: PayloadFormat,
    /// Execution techniques in the composed chain.
    pub executions: Vec<String>,
    /// Whether the caller should write the plan file.
    pub save_plan: bool,
    /// Non-fatal notices (an experimental default, an accepted experimental
    /// technique, …) the caller prints before building.
    pub warnings: Vec<String>,
}

/// Loads `picaro.config.yaml`, or the explicit `--config` file.
///
/// A missing implicit file is not an error: it just means "use the built-in
/// defaults". A missing explicit file is an error, because the operator named it.
pub fn load_config(path: Option<&Path>) -> Result<Defaults> {
    match path {
        Some(path) => load_config_at(path, true),
        None => load_config_at(Path::new(CONFIG_FILE), false),
    }
}

/// Loads `path`, optionally treating its absence as "use the defaults".
///
/// The implicit lookup is optional because most repositories do not carry a
/// config; an explicit `--config` path is required, because the operator named
/// it.
fn load_config_at(path: &Path, required: bool) -> Result<Defaults> {
    if !path.is_file() && !required {
        return Ok(Defaults::default());
    }
    read_config(path)
}

/// Reads and parses one config document.
fn read_config(path: &Path) -> Result<Defaults> {
    let raw = std::fs::read_to_string(path).map_err(|source| PackerError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let config: Config = serde_yml::from_str(&raw).map_err(|source| PackerError::ParseConfig {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(config.pack)
}

/// Composes and validates the plan described by `args` and `defaults`.
///
/// Built-in defaults, before the config file:
/// - execution: `reflective_loading` for `pe`/`dll`/`shellcode`,
///   `dotnet_hosting` for `.NET`, `powershell_hosting` for `.ps1`;
/// - syscalls: `indirect` with `hells_gate` (x64 only);
/// - strings: `xor` + a random key;
/// - output: `packed/<payload>/<payload>.exe`, `strip: true`, `trim_paths: all`;
/// - the plan is saved as `<folder>/plan.yaml`.
///
/// Non-`Stable` techniques selected explicitly need `--allow-experimental`. A
/// non-`Stable` technique chosen *by the format default* still builds (otherwise
/// zero-config would never work), but produces a warning until the flag
/// acknowledges it.
pub fn compose(args: &PackArgs, defaults: &Defaults) -> Result<PackOutcome> {
    if !args.payload.is_file() {
        return Err(PackerError::Usage(format!(
            "payload '{}' does not exist or is not a file",
            args.payload.display()
        )));
    }

    let format = format::detect(&args.payload);
    if format == PayloadFormat::Plain {
        return Err(PackerError::Usage(
            "the payload is a plain data file, not something the loader can run".to_string(),
        ));
    }

    if args.no_save_plan && args.plan_out.is_some() {
        return Err(PackerError::Usage(
            "--no-save-plan and --plan-out cannot be used together".to_string(),
        ));
    }

    let allow_experimental =
        args.allow_experimental || defaults.allow_experimental.unwrap_or(false);

    let arch = parse_arch(
        args.arch
            .as_deref()
            .or(defaults.arch.as_deref())
            .unwrap_or("x64"),
    )?;
    let kind = parse_kind(
        args.kind
            .as_deref()
            .or(defaults.kind.as_deref())
            .unwrap_or("exe"),
    )?;

    let dir = args
        .dir
        .clone()
        .or_else(|| defaults.dir.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIR));
    let (artifact_path, plan_path) = output_paths(
        &args.payload,
        &dir,
        kind,
        args.out.as_deref(),
        args.plan_out.as_deref(),
    );

    let mut warnings = Vec::new();
    let runtime = compose_steps(args, defaults, format, allow_experimental, &mut warnings)?;
    let export = resolve_dll_export(args, format, &runtime, &mut warnings)?;
    let plan = compose_plan(
        args,
        defaults,
        PlanShape {
            format,
            arch,
            kind,
            artifact_path: artifact_path.clone(),
            export,
        },
        runtime,
    )?;

    let yaml = serde_yml::to_string(&plan).map_err(|source| {
        PackerError::Validation(format!("could not serialize the generated plan: {source}"))
    })?;
    // Feed the document back through the real loader: the saved plan is
    // byte-for-byte the one that gets built, and format/validation behave
    // exactly as they do for a hand-written file.
    let plan = load_plan_str(&yaml, &plan_path, &BTreeMap::new())?;
    let plan_yaml = serde_yml::to_string(&plan).map_err(|source| {
        PackerError::Validation(format!("could not serialize the generated plan: {source}"))
    })?;

    let executions = plan
        .runtime
        .iter()
        .filter(|step| step.category() == Category::Execution)
        .map(|step| step.name().to_string())
        .collect();

    Ok(PackOutcome {
        plan,
        plan_yaml,
        plan_path,
        artifact_path,
        format,
        executions,
        save_plan: save_plan(args, defaults),
        warnings,
    })
}

/// Writes the generated plan, creating its parent folder when needed.
pub fn write_plan(outcome: &PackOutcome) -> Result<()> {
    if let Some(parent) = outcome
        .plan_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&outcome.plan_path, &outcome.plan_yaml).map_err(|source| {
        PackerError::WritePlan {
            path: outcome.plan_path.clone(),
            source,
        }
    })
}

/// Whether the plan should be written to disk.
fn save_plan(args: &PackArgs, defaults: &Defaults) -> bool {
    if args.no_save_plan {
        return false;
    }
    if args.plan_out.is_some() {
        return true;
    }
    defaults.plan.unwrap_or(true)
}

/// Builds the ordered runtime chain from the selected techniques.
///
/// Order: `--step` files, then `-t` techniques (both in the order given), then
/// the preparation shortcuts, then `--sleep`, and finally the execution step.
/// The shortcuts and the sleep are inserted *before* the first execution step,
/// so `-t reflective_loading --patch-amsi` still runs the patch first. An
/// execution already present in `--step`/`-t` is not duplicated.
fn compose_steps(
    args: &PackArgs,
    defaults: &Defaults,
    format: PayloadFormat,
    allow_experimental: bool,
    warnings: &mut Vec<String>,
) -> Result<Vec<RuntimeStep>> {
    let mut steps = Vec::new();

    for path in &args.steps {
        let step = load_step(path)?;
        check_stability(step.name(), allow_experimental, warnings)?;
        steps.push(step);
    }

    for name in &args.techniques {
        let (def, step) = named_step(name)?;
        check_stability(def.name, allow_experimental, warnings)?;
        steps.push(step);
    }

    let explicit_exec = explicit_execution(args, defaults)?;
    if let Some(name) = &explicit_exec {
        let def = techniques::find(name).ok_or_else(|| unknown(name))?;
        check_stability(def.name, allow_experimental, warnings)?;
    }

    let execution_present = steps.iter().any(is_execution);
    if explicit_exec.is_some() && execution_present {
        return Err(PackerError::Usage(
            "-t/--step already declares an execution step; drop --exec (or the step), or use \
             -t for the whole chain"
                .to_string(),
        ));
    }

    for name in preparation_sugars(args) {
        let (def, step) = named_step(name)?;
        check_stability(def.name, allow_experimental, warnings)?;
        insert_before_execution(&mut steps, step);
    }

    if let Some(ms) = args.sleep_ms {
        insert_before_execution(
            &mut steps,
            RuntimeStep::new(TechniqueKind::Sleep {
                params: crate::techniques::sleep::Params { ms },
            }),
        );
    }

    match explicit_exec {
        Some(name) => {
            let (_, mut step) = named_step(&name)?;
            apply_target(&mut step, args.target.as_deref())?;
            steps.push(step);
        }
        None if !execution_present => {
            let name = default_execution(format);
            let (def, mut step) = named_step(name)?;
            if def.stability != Stability::Stable && !allow_experimental {
                warnings.push(format!(
                    "default execution '{}' is {}; pass --allow-experimental to acknowledge it, \
                     or choose another with --exec",
                    def.name,
                    def.stability.label()
                ));
            }
            apply_target(&mut step, args.target.as_deref())?;
            steps.push(step);
        }
        None => {
            if let Some(target) = args.target.as_deref() {
                apply_target_to_existing(&mut steps, target)?;
            }
        }
    }

    Ok(steps)
}

/// The techniques requested by `--reflective-loading` / `--hollow`.
fn explicit_execution(args: &PackArgs, defaults: &Defaults) -> Result<Option<String>> {
    let shortcut = if args.reflective_loading {
        Some("reflective_loading")
    } else if args.hollow {
        Some("process_hollowing")
    } else {
        None
    };

    if shortcut.is_some() && args.exec.is_some() {
        return Err(PackerError::Usage(
            "use either --exec or the shortcut flag, not both".to_string(),
        ));
    }

    let requested = args.exec.clone().or_else(|| shortcut.map(str::to_string));

    let chosen = match requested {
        Some(value) if is_auto(&value) => None,
        Some(value) if !value.trim().is_empty() => Some(value),
        Some(_) => None,
        None => match defaults.exec.as_deref() {
            Some(value) if !is_auto(value) && !value.trim().is_empty() => Some(value.to_string()),
            _ => None,
        },
    };

    let Some(chosen) = chosen else {
        return Ok(None);
    };
    let def = techniques::find(&chosen).ok_or_else(|| unknown(&chosen))?;
    if def.category != Category::Execution {
        return Err(PackerError::Usage(format!(
            "--exec expects an execution technique; '{}' is a {} (use -t for it)",
            def.name,
            def.category.label()
        )));
    }
    Ok(Some(def.name.to_string()))
}

/// The preparation shortcuts, in their fixed canonical order.
fn preparation_sugars(args: &PackArgs) -> Vec<&'static str> {
    let mut names = Vec::new();
    if args.patch_amsi {
        names.push("patch_amsi");
    }
    if args.patch_etw {
        names.push("patch_etw");
    }
    if args.erase_header {
        names.push("erase_pe_header");
    }
    if args.unhook {
        names.push("unhook_ntdll");
    }
    if args.hide_module {
        names.push("hide_module");
    }
    names
}

/// Parses a technique name with its serde defaults.
fn named_step(name: &str) -> Result<(&'static techniques::TechniqueDef, RuntimeStep)> {
    let def = techniques::find(name).ok_or_else(|| unknown(name))?;
    let yaml = format!("technique: {}\n", def.name);
    let step = serde_yml::from_str(&yaml).map_err(|source| {
        PackerError::Validation(format!(
            "could not build technique '{}' from its defaults: {source}",
            def.name
        ))
    })?;
    Ok((def, step))
}

/// Reads one `RuntimeStep` document for `--step`.
fn load_step(path: &Path) -> Result<RuntimeStep> {
    let raw = std::fs::read_to_string(path).map_err(|source| PackerError::ReadPlan {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yml::from_str(&raw).map_err(|source| PackerError::ParsePlan {
        path: path.to_path_buf(),
        source,
    })
}

/// Rejects an explicit non-`Stable` technique unless `--allow-experimental`.
fn check_stability(name: &str, allow_experimental: bool, warnings: &mut Vec<String>) -> Result<()> {
    let def = techniques::find(name).ok_or_else(|| unknown(name))?;
    if def.stability == Stability::Stable {
        return Ok(());
    }
    if !allow_experimental {
        return Err(PackerError::Usage(format!(
            "technique '{}' is {} and needs --allow-experimental (it is not a measured, stable \
             baseline); see `picaro techniques show {}`",
            def.name,
            def.stability.label(),
            def.name
        )));
    }
    warnings.push(format!(
        "technique '{}' is {}: continuing because --allow-experimental was passed",
        def.name,
        def.stability.label()
    ));
    Ok(())
}

/// The execution technique used when none is selected.
fn default_execution(format: PayloadFormat) -> &'static str {
    match format {
        PayloadFormat::Dotnet => "dotnet_hosting",
        PayloadFormat::Powershell => "powershell_hosting",
        PayloadFormat::Pe | PayloadFormat::Dll | PayloadFormat::Shellcode => "reflective_loading",
        PayloadFormat::Auto | PayloadFormat::Plain => "reflective_loading",
    }
}

/// Whether a step runs a payload.
fn is_execution(step: &RuntimeStep) -> bool {
    step.category() == Category::Execution
}

/// Inserts a preparation/control step before the first execution step.
fn insert_before_execution(steps: &mut Vec<RuntimeStep>, step: RuntimeStep) {
    match steps.iter().position(is_execution) {
        Some(index) => steps.insert(index, step),
        None => steps.push(step),
    }
}

/// Applies `--target` to a step, or explains that it has no such parameter.
fn apply_target(step: &mut RuntimeStep, target: Option<&str>) -> Result<()> {
    let Some(target) = target else {
        return Ok(());
    };
    let applied = match &mut step.technique {
        TechniqueKind::ProcessHollowing { params } => {
            params.target = target.to_string();
            true
        }
        TechniqueKind::EarlyBird { params } => {
            params.target = target.to_string();
            true
        }
        TechniqueKind::PeInjection { params } => {
            params.target = target.to_string();
            true
        }
        TechniqueKind::ThreadHijacking { params } => {
            params.target = target.to_string();
            true
        }
        _ => false,
    };
    if applied {
        Ok(())
    } else {
        Err(PackerError::Usage(format!(
            "--target does not apply to '{}'; it is only understood by process_hollowing, \
             early_bird, pe_injection and thread_hijacking",
            step.name()
        )))
    }
}

/// Applies `--target` to the single execution step already in the chain.
fn apply_target_to_existing(steps: &mut [RuntimeStep], target: &str) -> Result<()> {
    let positions: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| is_execution(step))
        .map(|(index, _)| index)
        .collect();
    match positions.as_slice() {
        [index] => apply_target(&mut steps[*index], Some(target)),
        [] => Err(PackerError::Usage(
            "--target needs an execution step".to_string(),
        )),
        _ => Err(PackerError::Usage(
            "--target is ambiguous with more than one execution step; pass it per step with a \
             --step document"
                .to_string(),
        )),
    }
}

/// Resolves the payload's `export` for a DLL.
///
/// A mapped DLL only initializes with `DllMain`; the chain needs a callable
/// export. With no `--export`, the single non-entry export is selected and
/// announced; several are an error that lists them, because guessing would call
/// the wrong function.
fn resolve_dll_export(
    args: &PackArgs,
    format: PayloadFormat,
    runtime: &[RuntimeStep],
    warnings: &mut Vec<String>,
) -> Result<Option<String>> {
    if format != PayloadFormat::Dll {
        return Ok(args.export.clone());
    }
    // Only reflective loading maps a DLL and calls an export. Any other
    // execution technique that receives a DLL is a plan error, and that message
    // is more useful than an export-table message; let validation report it.
    let mapped = runtime
        .iter()
        .any(|step| matches!(step.technique, TechniqueKind::ReflectiveLoading { .. }));
    if !mapped {
        return Ok(args.export.clone());
    }
    let bytes = std::fs::read(&args.payload).map_err(|source| PackerError::ReadInput {
        path: args.payload.clone(),
        source,
    })?;
    let audit = pe_info::analyze(&bytes).map_err(|error| {
        PackerError::Usage(format!(
            "could not read the DLL's export table from '{}': {error}; pass --export <name>",
            args.payload.display()
        ))
    })?;
    resolve_export(
        args.export.as_deref(),
        &args.payload,
        &audit.exports,
        warnings,
    )
}

/// Chooses the export from an already parsed table.
///
/// Split from [`resolve_dll_export`] so the selection rules are testable without
/// a binary fixture. `explicit` is checked against the table, so a typo fails
/// before the build instead of at run time in `GetProcAddress`.
fn resolve_export(
    explicit: Option<&str>,
    payload: &Path,
    exports: &[String],
    warnings: &mut Vec<String>,
) -> Result<Option<String>> {
    if let Some(export) = explicit {
        if !exports.iter().any(|name| name == export) {
            let mut available = exports.to_vec();
            available.sort();
            return Err(PackerError::Usage(format!(
                "'{export}' is not exported by '{}'; available: {}",
                payload.display(),
                preview_exports(&available)
            )));
        }
        return Ok(Some(export.to_string()));
    }

    choose_dll_export(payload, exports, warnings)
}

/// Chooses the export when the operator did not name one.
fn choose_dll_export(
    payload: &Path,
    exports: &[String],
    warnings: &mut Vec<String>,
) -> Result<Option<String>> {
    let mut callable: Vec<String> = exports
        .iter()
        .filter(|name| !is_dll_entry_export(name))
        .cloned()
        .collect();
    callable.sort();
    callable.dedup();

    match callable.as_slice() {
        [] => Err(PackerError::Usage(format!(
            "'{}' was detected as a DLL but exposes no callable export besides DllMain; use an \
             executable payload, or pass --export <name> if the entry is exported under another \
             name",
            payload.display()
        ))),
        [only] => {
            warnings.push(format!(
                "DLL payload: using export '{only}' (the only callable export); pass --export to \
                 choose another"
            ));
            Ok(Some(only.clone()))
        }
        many => Err(PackerError::Usage(format!(
            "'{}' exports more than one callable function; choose one with --export <name>: {}",
            payload.display(),
            preview_exports(many)
        ))),
    }
}

/// Whether an export is the DLL entry stub rather than a callable function.
fn is_dll_entry_export(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "dllmain" || lower.starts_with("dllmain@") || lower.starts_with("_dllmaincrtstartup")
}

/// A bounded, comma-separated export list for an error or notice.
fn preview_exports(names: &[String]) -> String {
    const MAX: usize = 12;
    if names.is_empty() {
        return "(none)".to_string();
    }
    let shown = names
        .iter()
        .take(MAX)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let hidden = names.len().saturating_sub(MAX);
    if hidden == 0 {
        shown
    } else {
        format!("{shown} (+{hidden} more)")
    }
}

/// The payload/output choices a composed plan is built from.
struct PlanShape {
    format: PayloadFormat,
    arch: Arch,
    kind: OutputKind,
    artifact_path: PathBuf,
    export: Option<String>,
}

/// Builds the plan document around the runtime chain.
fn compose_plan(
    args: &PackArgs,
    defaults: &Defaults,
    shape: PlanShape,
    runtime: Vec<RuntimeStep>,
) -> Result<Plan> {
    if shape.export.is_some() && shape.format != PayloadFormat::Dll {
        return Err(PackerError::Usage(format!(
            "--export only applies to a DLL payload; '{}' was detected as {}",
            args.payload.display(),
            shape.format.label()
        )));
    }
    if shape.kind == OutputKind::PsModule
        && !runtime
            .iter()
            .any(|step| matches!(step.technique, TechniqueKind::ImportPowermodule { .. }))
    {
        return Err(PackerError::Usage(
            "--kind psmodule needs -t import_powermodule (and a .ps1/.psm1 payload)".to_string(),
        ));
    }

    let stem = payload_stem(&args.payload);
    let mut payloads = BTreeMap::new();
    payloads.insert(
        stem.clone(),
        PayloadPlan {
            source: args.payload.display().to_string(),
            format: shape.format,
            export: shape.export,
            args: None,
            args_mode: ArgsMode::Join,
            crypto: None,
            sha256: None,
        },
    );

    let stub = StubPlan {
        path: None,
        syscalls: syscalls_plan(args, defaults, shape.arch)?,
        api_resolution: None,
        strings: Some(YamlStringsPlan {
            strategy: strings_strategy(args, defaults)?,
            key: "random".to_string(),
        }),
        debug: args.debug,
    };

    let output = OutputPlan {
        path: shape.artifact_path,
        kind: shape.kind,
        entry: parse_entry(args.entry.as_deref())?,
        console: ConsoleMode::Parent,
        arch: shape.arch,
        strip: args.strip.or(defaults.strip).unwrap_or(true),
        trim_paths: TrimPaths::All,
        manifest: true,
        resources: resources_plan(args, defaults)?,
        subsystem: if args.gui.or(defaults.gui).unwrap_or(false) {
            Subsystem::Windows
        } else {
            Subsystem::Console
        },
        sign: sign_plan(args, defaults)?,
    };

    Ok(Plan {
        schema: SUPPORTED_SCHEMA,
        name: stem,
        build: BuildPlan {
            crypto: Some(CryptoPlan {
                algo: CryptoAlgorithm::XChaCha20Poly1305,
                key: KeySource::Random,
            }),
            payloads,
            stub,
            polymorphism: None,
            output,
        },
        runtime,
        reproduce: None,
    })
}

/// Builds `build.stub.syscalls`, applying the `indirect` + `hells_gate` default.
fn syscalls_plan(
    args: &PackArgs,
    defaults: &Defaults,
    arch: Arch,
) -> Result<Option<YamlSyscallsPlan>> {
    let mode_value = args.syscalls.clone().or_else(|| defaults.syscalls.clone());
    let mode = normalize(mode_value.as_deref().unwrap_or("indirect"));

    let resolver_value = args.resolver.clone().or_else(|| defaults.resolver.clone());
    let resolver = normalize(resolver_value.as_deref().unwrap_or("hells_gate"));

    let stack_spoofing = args
        .stack_spoofing
        .or(defaults.stack_spoofing)
        .unwrap_or(false);

    if mode == "none" {
        // The config is a defaults bag: a leftover resolver/stack flag there is
        // harmless when the mode disables them. An explicit CLI flag is a
        // contradiction and gets an error.
        if args.resolver.is_some() || args.stack_spoofing == Some(true) {
            return Err(PackerError::Usage(
                "--resolver and --stack-spoofing need --syscalls indirect".to_string(),
            ));
        }
        return Ok(None);
    }
    if mode != "indirect" {
        return Err(PackerError::Usage(format!(
            "unknown syscalls mode '{mode}'; expected none or indirect"
        )));
    }
    if !matches!(
        resolver.as_str(),
        "hells_gate" | "tartarus_gate" | "api_hash" | "halos_gate"
    ) {
        return Err(PackerError::Usage(format!(
            "unknown resolver '{resolver}'; expected hells_gate, tartarus_gate, api_hash or \
             halos_gate"
        )));
    }
    if arch == Arch::X86 {
        // A silent downgrade keeps `picaro pack app.exe --arch x86` working, even
        // when the config carries the x64 defaults; an explicit CLI request for a
        // x64-only feature is still an error.
        let requested_on_the_cli =
            args.syscalls.is_some() || args.resolver.is_some() || args.stack_spoofing == Some(true);
        if requested_on_the_cli {
            return Err(PackerError::Usage(
                "indirect syscalls and stack spoofing are x64-only; use --arch x64 or \
                 --syscalls none"
                    .to_string(),
            ));
        }
        return Ok(None);
    }

    Ok(Some(YamlSyscallsPlan {
        mode,
        resolver,
        stack_spoofing: stack_spoofing.then(|| YamlStackSpoofing {
            decoy_bytes: crate::engine::syscalls::stack_spoofing::default_decoy_bytes(),
        }),
    }))
}

/// Builds `build.stub.strings` (`xor` + a random key by default).
fn strings_strategy(args: &PackArgs, defaults: &Defaults) -> Result<String> {
    let strategy = normalize(
        args.strings
            .as_deref()
            .or(defaults.strings.as_deref())
            .unwrap_or("xor"),
    );
    if !matches!(strategy.as_str(), "xor" | "stack") {
        return Err(PackerError::Usage(format!(
            "unknown strings strategy '{strategy}'; expected xor or stack"
        )));
    }
    Ok(strategy)
}

/// Builds `build.output.sign`.
fn sign_plan(args: &PackArgs, defaults: &Defaults) -> Result<Option<SignPlan>> {
    let mode = normalize(
        args.sign
            .as_deref()
            .or(defaults.sign.as_deref())
            .unwrap_or("none"),
    );
    let subject = args
        .sign_subject
        .clone()
        .or_else(|| defaults.sign_subject.clone());
    let thumbprint = args
        .sign_thumbprint
        .clone()
        .or_else(|| defaults.sign_thumbprint.clone());
    let file = args
        .sign_file
        .clone()
        .or_else(|| defaults.sign_file.clone());
    let password_env = args
        .sign_password_env
        .clone()
        .or_else(|| defaults.sign_password_env.clone());
    let timestamp_url = args
        .timestamp_url
        .clone()
        .or_else(|| defaults.timestamp_url.clone());

    if mode == "none" {
        let any = subject.is_some()
            || thumbprint.is_some()
            || file.is_some()
            || password_env.is_some()
            || timestamp_url.is_some();
        if any {
            return Err(PackerError::Usage(
                "signing options need --sign lab, store or file".to_string(),
            ));
        }
        return Ok(None);
    }
    if !matches!(mode.as_str(), "lab" | "store" | "file") {
        return Err(PackerError::Usage(format!(
            "unknown signing mode '{mode}'; expected none, lab, store or file"
        )));
    }
    if mode == "store" && subject.is_none() && thumbprint.is_none() {
        return Err(PackerError::Usage(
            "--sign store needs --sign-thumbprint or --sign-subject".to_string(),
        ));
    }
    if mode == "file" && file.is_none() {
        return Err(PackerError::Usage(
            "--sign file needs --sign-file".to_string(),
        ));
    }

    Ok(Some(SignPlan {
        mode,
        subject,
        thumbprint,
        file,
        password_env,
        timestamp_url,
        signtool: None,
    }))
}

/// Builds `build.output.resources` when `--icon` is set.
fn resources_plan(args: &PackArgs, defaults: &Defaults) -> Result<Option<ResourcesPlan>> {
    let Some(value) = args.icon.as_deref().or(defaults.icon.as_deref()) else {
        return Ok(None);
    };
    let icon = value.parse::<IconPlan>().map_err(PackerError::Usage)?;
    Ok(Some(ResourcesPlan {
        icon: Some(icon),
        version_info: None,
        manifest: None,
    }))
}

/// Parses `--entry` (`auto`, `jni_on_load` or `export:<name>`).
fn parse_entry(value: Option<&str>) -> Result<DllEntry> {
    match value {
        Some(value) => value
            .parse::<DllEntry>()
            .map_err(|error| PackerError::Usage(format!("--entry: {error}"))),
        None => Ok(DllEntry::default()),
    }
}

/// Parses `--arch`.
fn parse_arch(value: &str) -> Result<Arch> {
    match normalize(value).as_str() {
        "x64" | "amd64" => Ok(Arch::X64),
        "x86" | "i686" => Ok(Arch::X86),
        other => Err(PackerError::Usage(format!(
            "unknown architecture '{other}'; expected x64 or x86"
        ))),
    }
}

/// Parses `--kind`.
fn parse_kind(value: &str) -> Result<OutputKind> {
    match normalize(value).as_str() {
        "exe" | "executable" => Ok(OutputKind::Exe),
        "dll" | "library" => Ok(OutputKind::Dll),
        "shellcode" | "bin" => Ok(OutputKind::Shellcode),
        "psmodule" | "ps1" => Ok(OutputKind::PsModule),
        other => Err(PackerError::Usage(format!(
            "unknown output kind '{other}'; expected exe, dll, shellcode or psmodule"
        ))),
    }
}

/// The default artifact and plan paths.
fn output_paths(
    payload: &Path,
    dir: &Path,
    kind: OutputKind,
    out: Option<&Path>,
    plan_out: Option<&Path>,
) -> (PathBuf, PathBuf) {
    let stem = payload_stem(payload);
    let artifact = match out {
        Some(path) if path.is_dir() => path.join(format!("{stem}.{}", kind.extension())),
        Some(path) => path.to_path_buf(),
        None => dir.join(&stem).join(format!("{stem}.{}", kind.extension())),
    };
    // One folder per plan is the package root: the plan, the sources and the
    // artifact travel together even when `--out` names a file elsewhere.
    let (package, artifact) = crate::paths::package_paths(&stem, &artifact);
    let plan_path = plan_out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| package.join(PLAN_FILE));
    (artifact, plan_path)
}

/// The payload's file stem, used as both its plan key and its output folder.
fn payload_stem(payload: &Path) -> String {
    payload
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty() && *stem != "." && *stem != "..")
        .unwrap_or("payload")
        .to_string()
}

/// Lowercase, dash-insensitive normalization for CLI values.
fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

/// Whether a value means "let the format decide".
fn is_auto(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("auto")
}

/// The error for an unknown technique name.
fn unknown(name: &str) -> PackerError {
    PackerError::Usage(format!(
        "unknown technique '{name}'; run `picaro techniques list` to see the registry"
    ))
}

#[cfg(test)]
mod tests;
