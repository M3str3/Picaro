//! Technique registry.
//!
//! Every evasion/execution technique lives in its own subdirectory (e.g.
//! [`process_hollowing`]) and is registered in [`all`]. The registry is pure
//! metadata: it feeds the `picaro techniques` CLI, the `validate` CI check
//! and the stub renderer. How to add a technique is documented in
//! `src/techniques/README.md`.

pub mod anti_debug;
pub mod bouncer;
pub mod dll_hollowing;
pub mod dotnet_hosting;
pub mod drop;
pub mod early_bird;
pub mod erase_pe_header;
pub mod execution_callbacks;
pub mod fibers;
pub mod hardware_breakpoints;
pub mod hide_module;
pub mod hide_thread_from_debugger;
pub mod image_path_spoofing;
pub mod import_powermodule;
pub mod killswitch;
pub mod living_off_the_land;
pub mod module_stomping;
pub mod network_stager;
pub mod patch_amsi;
pub mod patch_etw;
pub mod pe_injection;
pub mod powershell_hosting;
pub mod ppid_spoofing;
pub mod process_ghosting;
pub mod process_hollowing;
pub mod process_mitigations;
pub mod reflective_loading;
pub mod self_deletion;
pub mod sleep;
pub mod sleep_obfuscation;
pub mod thread_hijacking;
pub mod timestomping;
pub mod unhook_ntdll;
pub mod veh_execution;

mod presentation;

pub(crate) use presentation::{
    capabilities, column_width, pad, params_markdown, readme_title, short_description,
    stability_label, stability_tone, strip_header, truncate,
};
pub use presentation::{list, readme, show, summary, validate};

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::error::Result;
use crate::ui::{glyph, markdown, Meta, Palette, Tone};

use crate::plan::schema::{PayloadFormat, StepControl};

/// One step of the `runtime` list in the YAML plan.
///
/// A step is a technique call: the technique's `params` plus the loader's own
/// orchestration ([`StepControl`]). The two live in separate namespaces, so a
/// technique parameter can never collide with an orchestration field: the
/// technique interprets `params`, the loader reads the control fields.
///
/// ```yaml
/// runtime:
///   - technique: process_hollowing
///     params:
///       payload: implant
///       target: "C:\\Windows\\System32\\svchost.exe"
///     on_fail: continue
/// ```
///
/// `params` is optional: a technique whose parameters all have defaults (e.g.
/// `patch_amsi`) may omit it entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStep {
    /// The technique the step calls, with its `params`.
    #[serde(flatten)]
    pub technique: TechniqueKind,

    /// How the loader reacts to this step's result.
    #[serde(flatten)]
    pub control: StepControl,
}

impl RuntimeStep {
    /// Builds a step that calls `technique` with default orchestration.
    pub fn new(technique: TechniqueKind) -> Self {
        Self {
            technique,
            control: StepControl::default(),
        }
    }

    /// The technique's YAML key (used by semantic validation and the build log).
    pub fn name(&self) -> &'static str {
        self.technique.name()
    }

    /// The technique's [`Category`] (Preparation, Execution or Control).
    pub fn category(&self) -> Category {
        self.technique.category()
    }
}

/// A technique call: which technique, and the arguments it interprets.
///
/// Internally tagged enum: the step names the technique with `technique: <name>`
/// and passes its parameters under a nested `params:` mapping, so a parameter
/// can never collide with the tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "technique", rename_all = "snake_case")]
pub enum TechniqueKind {
    /// Detect a debugger in the current process, aborting by default
    /// (preparation).
    AntiDebug {
        /// Technique parameters (`action`).
        #[serde(default)]
        params: anti_debug::Params,
    },
    /// Hide the loader's main thread from any debugger (`ThreadHideFromDebugger`)
    /// (preparation).
    HideThreadFromDebugger {
        /// Technique parameters (none).
        #[serde(default)]
        params: hide_thread_from_debugger::Params,
    },
    /// Gate the pipeline on the host environment (preparation).
    Bouncer {
        /// Technique parameters (the declared checks).
        #[serde(default)]
        params: bouncer::Params,
    },
    /// Write an embedded `format: plain` file to a path, before the payload runs
    /// (preparation).
    Drop {
        /// Technique parameters (the destination and the asset).
        #[serde(default)]
        params: drop::Params,
    },
    /// Patch the AMSI scan exports in the current process (preparation).
    PatchAmsi {
        /// Technique parameters (the optional scan variants).
        #[serde(default)]
        params: patch_amsi::Params,
    },
    /// Patch the ETW event-writing exports in the current process
    /// (preparation).
    PatchEtw {
        /// Technique parameters (`full`, `ex`, `nt_trace`).
        #[serde(default)]
        params: patch_etw::Params,
    },
    /// Hardware-breakpoint AMSI/ETW bypass: emulate the watched exports through
    /// the CPU debug registers instead of patching them (preparation).
    HardwareBreakpoints {
        /// Technique parameters (`amsi`, `scan_string`, `open_session`, `etw`).
        #[serde(default)]
        params: hardware_breakpoints::Params,
    },
    /// Process mitigation policies: BlockDLLs, extension-point disable and an
    /// optional Win32k system-call block (preparation).
    ProcessMitigations {
        /// Technique parameters (`block_dlls`, `extension_points`,
        /// `win32k_filter`).
        #[serde(default)]
        params: process_mitigations::Params,
    },
    /// Image path spoofing: repoint the PEB's `ImagePathName` at a decoy path so
    /// the PEB readers report a legitimate image (preparation).
    ImagePathSpoofing {
        /// Technique parameters (`path`).
        #[serde(default)]
        params: image_path_spoofing::Params,
    },
    /// Erase PE header: zero the loader image's in-memory PE header so memory
    /// scanners cannot parse it (preparation).
    ErasePeHeader {
        /// Technique parameters (none).
        #[serde(default)]
        params: erase_pe_header::Params,
    },
    /// Hide module: unlink a module from the PEB's loader lists so userland PEB
    /// walkers cannot see it (preparation).
    HideModule {
        /// Technique parameters (`modules`, `hide_self`).
        #[serde(default)]
        params: hide_module::Params,
    },
    /// ntdll unhooking: restore the loaded ntdll's code section from a clean
    /// copy read from disk (preparation).
    UnhookNtdll {
        /// Technique parameters (none).
        #[serde(default)]
        params: unhook_ntdll::Params,
    },
    /// Process hollowing: run the payload inside a suspended, legitimate
    /// process instead of on disk.
    ProcessHollowing {
        /// Technique parameters (`payload`, `target`).
        #[serde(default)]
        params: process_hollowing::Params,
    },
    /// .NET hosting: start the CLR in the current process and load the managed
    /// payload as an assembly from memory.
    DotnetHosting {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: dotnet_hosting::Params,
    },
    /// PowerShell hosting: run a `.ps1` payload in-process by hosting the
    /// PowerShell engine on the CLR.
    PowershellHosting {
        /// Technique parameters (`payload`, `mode`, `command`, `command_mode`).
        #[serde(default)]
        params: powershell_hosting::Params,
    },
    /// Import a PowerShell module into the caller's session (a `kind: psmodule`
    /// build).
    ImportPowermodule {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: import_powermodule::Params,
    },
    /// Reflective loading: map the payload into the current process and run
    /// its entry point.
    ReflectiveLoading {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: reflective_loading::Params,
    },
    /// Callback execution: run the payload as the callback of a legitimate
    /// Windows enumeration API in the current process.
    ExecutionCallbacks {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: execution_callbacks::Params,
    },
    /// Fiber execution: run the payload on a fiber in the current process.
    Fibers {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: fibers::Params,
    },
    /// Module stomping: overwrite a legitimately loaded module's code with the
    /// payload and run it from there.
    ModuleStomping {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: module_stomping::Params,
    },
    /// Early Bird APC injection: spawn a suspended process, write the payload
    /// and queue an APC before the target runs.
    EarlyBird {
        /// Technique parameters (`payload`, `target`).
        #[serde(default)]
        params: early_bird::Params,
    },
    /// PE injection: map the payload image into a suspended process and start
    /// it at its entry point.
    PeInjection {
        /// Technique parameters (`payload`, `target`).
        #[serde(default)]
        params: pe_injection::Params,
    },
    /// Thread hijacking: suspend a thread that already exists in the target
    /// process, point it at the payload and resume it.
    ThreadHijacking {
        /// Technique parameters (`payload`, `target`, `pid`,
        /// `dedicated_stack`, `wait_ms`).
        #[serde(default)]
        params: thread_hijacking::Params,
    },
    /// Self-deletion: unlink the running artifact's own image (preparation).
    SelfDeletion {
        /// Technique parameters (`mode`).
        #[serde(default)]
        params: self_deletion::Params,
    },
    /// Sleep obfuscation: encrypt the image region during a timer-driven
    /// sleep (preparation).
    SleepObfuscation {
        /// Technique parameters (`variant`, `sleep_ms`, `encrypt_regions`).
        #[serde(default)]
        params: sleep_obfuscation::Params,
    },
    /// Living off the land: launch a process — a signed Microsoft binary
    /// (T1218 proxy execution) or any command (control).
    LivingOffTheLand {
        /// Technique parameters (`binary`, `args`, `window`, `wait`,
        /// `timeout_s`).
        #[serde(default)]
        params: living_off_the_land::Params,
    },
    /// Wait a number of milliseconds (control).
    Sleep {
        /// Technique parameters (`ms`).
        #[serde(default)]
        params: sleep::Params,
    },
    /// Parent-process spoofing: launch a process whose recorded parent is a
    /// different, legitimate process (control).
    PpidSpoofing {
        /// Technique parameters (`binary`, `args`, `parent`, `wait`).
        #[serde(default)]
        params: ppid_spoofing::Params,
    },
    /// Network stager: fetch the payload over the network at run time (control).
    NetworkStager {
        /// Technique parameters (`payload`, `url`, `crypto`, `key`, `nonce`, ...).
        #[serde(default)]
        params: network_stager::Params,
    },
    /// Killswitch: abort the chain past a deadline or run count (preparation).
    ///
    /// The YAML key is `killswitch` rather than the `snake_case` form of the
    /// variant name, which is the spelling the operator-facing vocabulary uses.
    #[serde(rename = "killswitch")]
    KillSwitch {
        /// Technique parameters (`expire_on`, `max_runs`, `run_key`).
        #[serde(default)]
        params: killswitch::Params,
    },
    /// Timestomping: copy a reference file's timestamps onto a target (preparation).
    Timestomping {
        /// Technique parameters (`target`, `reference`).
        #[serde(default)]
        params: timestomping::Params,
    },
    /// DLL hollowing: run the payload from a hollowed signed DLL (execution).
    DllHollowing {
        /// Technique parameters (`payload`, `module`).
        #[serde(default)]
        params: dll_hollowing::Params,
    },
    /// Process ghosting: map the payload from a delete-on-close file (execution).
    ProcessGhosting {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: process_ghosting::Params,
    },
    /// Vectored-exception execution: enter the payload by redirecting a
    /// breakpoint through a vectored handler (execution).
    VehExecution {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: veh_execution::Params,
    },
}

impl TechniqueKind {
    /// Renders the technique's stub fragment for its parameters.
    ///
    /// `strings` is the active string-obfuscation configuration, used to
    /// obfuscate any per-build string literal (e.g. the hollowing target).
    /// `format` and `export` describe the payload the technique loads.
    pub fn render_fragment(
        &self,
        strings: &StringsConfig,
        format: PayloadFormat,
        export: Option<&str>,
    ) -> String {
        match self {
            TechniqueKind::AntiDebug { params } => params.render_fragment(strings),
            TechniqueKind::HideThreadFromDebugger { params } => params.render_fragment(strings),
            TechniqueKind::Bouncer { params } => params.render_fragment(strings),
            TechniqueKind::Drop { params } => params.render_fragment(strings),
            TechniqueKind::PatchAmsi { params } => params.render_fragment(strings),
            TechniqueKind::PatchEtw { params } => params.render_fragment(strings),
            TechniqueKind::HardwareBreakpoints { params } => params.render_fragment(strings),
            TechniqueKind::ProcessMitigations { params } => params.render_fragment(strings),
            TechniqueKind::ImagePathSpoofing { params } => params.render_fragment(strings),
            TechniqueKind::ErasePeHeader { params } => params.render_fragment(strings),
            TechniqueKind::HideModule { params } => params.render_fragment(strings),
            TechniqueKind::DotnetHosting { params } => params.render_fragment(strings),
            TechniqueKind::PowershellHosting { params } => params.render_fragment(strings),
            TechniqueKind::ImportPowermodule { params } => params.render_fragment(strings),
            TechniqueKind::ProcessHollowing { params } => {
                params.render_fragment_for(strings, format)
            }
            TechniqueKind::ReflectiveLoading { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::ExecutionCallbacks { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::Fibers { params } => params.render_fragment_for(strings, format, export),
            TechniqueKind::ModuleStomping { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::SleepObfuscation { params } => params.render_fragment(strings),
            TechniqueKind::UnhookNtdll { params } => params.render_fragment(strings),
            TechniqueKind::EarlyBird { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::PeInjection { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::ThreadHijacking { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::SelfDeletion { params } => params.render_fragment(strings),
            TechniqueKind::PpidSpoofing { params } => params.render_fragment(strings),
            TechniqueKind::LivingOffTheLand { params } => params.render_fragment(strings),
            TechniqueKind::Sleep { params } => params.render_fragment(strings),
            TechniqueKind::NetworkStager { params } => params.render_fragment(strings),
            TechniqueKind::KillSwitch { params } => params.render_fragment(strings),
            TechniqueKind::Timestomping { params } => params.render_fragment(strings),
            TechniqueKind::DllHollowing { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::ProcessGhosting { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::VehExecution { params } => {
                params.render_fragment_for(strings, format, export)
            }
        }
    }

    /// The technique's YAML key (used by semantic validation).
    pub fn name(&self) -> &'static str {
        match self {
            TechniqueKind::AntiDebug { .. } => anti_debug::DEF.name,
            TechniqueKind::HideThreadFromDebugger { .. } => hide_thread_from_debugger::DEF.name,
            TechniqueKind::Bouncer { .. } => bouncer::DEF.name,
            TechniqueKind::Drop { .. } => drop::DEF.name,
            TechniqueKind::PatchAmsi { .. } => patch_amsi::DEF.name,
            TechniqueKind::PatchEtw { .. } => patch_etw::DEF.name,
            TechniqueKind::HardwareBreakpoints { .. } => hardware_breakpoints::DEF.name,
            TechniqueKind::ProcessMitigations { .. } => process_mitigations::DEF.name,
            TechniqueKind::ImagePathSpoofing { .. } => image_path_spoofing::DEF.name,
            TechniqueKind::ErasePeHeader { .. } => erase_pe_header::DEF.name,
            TechniqueKind::HideModule { .. } => hide_module::DEF.name,
            TechniqueKind::DotnetHosting { .. } => dotnet_hosting::DEF.name,
            TechniqueKind::PowershellHosting { .. } => powershell_hosting::DEF.name,
            TechniqueKind::ImportPowermodule { .. } => import_powermodule::DEF.name,
            TechniqueKind::ProcessHollowing { .. } => process_hollowing::DEF.name,
            TechniqueKind::ReflectiveLoading { .. } => reflective_loading::DEF.name,
            TechniqueKind::ExecutionCallbacks { .. } => execution_callbacks::DEF.name,
            TechniqueKind::Fibers { .. } => fibers::DEF.name,
            TechniqueKind::ModuleStomping { .. } => module_stomping::DEF.name,
            TechniqueKind::EarlyBird { .. } => early_bird::DEF.name,
            TechniqueKind::PeInjection { .. } => pe_injection::DEF.name,
            TechniqueKind::ThreadHijacking { .. } => thread_hijacking::DEF.name,
            TechniqueKind::SelfDeletion { .. } => self_deletion::DEF.name,
            TechniqueKind::PpidSpoofing { .. } => ppid_spoofing::DEF.name,
            TechniqueKind::UnhookNtdll { .. } => unhook_ntdll::DEF.name,
            TechniqueKind::SleepObfuscation { .. } => sleep_obfuscation::DEF.name,
            TechniqueKind::LivingOffTheLand { .. } => living_off_the_land::DEF.name,
            TechniqueKind::Sleep { .. } => sleep::DEF.name,
            TechniqueKind::NetworkStager { .. } => network_stager::DEF.name,
            TechniqueKind::KillSwitch { .. } => killswitch::DEF.name,
            TechniqueKind::Timestomping { .. } => timestomping::DEF.name,
            TechniqueKind::DllHollowing { .. } => dll_hollowing::DEF.name,
            TechniqueKind::ProcessGhosting { .. } => process_ghosting::DEF.name,
            TechniqueKind::VehExecution { .. } => veh_execution::DEF.name,
        }
    }

    /// The name of the payload this technique loads, when it loads one.
    ///
    /// Only Execution techniques run a payload; a Preparation or Control step
    /// returns `None`.
    pub fn payload_name(&self) -> Option<&str> {
        match self {
            TechniqueKind::ProcessHollowing { params } => params.payload.as_deref(),
            TechniqueKind::DotnetHosting { params } => params.payload.as_deref(),
            TechniqueKind::PowershellHosting { params } => params.payload.as_deref(),
            TechniqueKind::ImportPowermodule { params } => params.payload.as_deref(),
            TechniqueKind::ReflectiveLoading { params } => params.payload.as_deref(),
            TechniqueKind::ExecutionCallbacks { params } => params.payload.as_deref(),
            TechniqueKind::Fibers { params } => params.payload.as_deref(),
            TechniqueKind::ModuleStomping { params } => params.payload.as_deref(),
            TechniqueKind::EarlyBird { params } => params.payload.as_deref(),
            TechniqueKind::PeInjection { params } => params.payload.as_deref(),
            TechniqueKind::ThreadHijacking { params } => params.payload.as_deref(),
            TechniqueKind::DllHollowing { params } => params.payload.as_deref(),
            TechniqueKind::ProcessGhosting { params } => params.payload.as_deref(),
            TechniqueKind::VehExecution { params } => params.payload.as_deref(),
            _ => None,
        }
    }

    /// The PowerShell-hosting parameters, when this step is one.
    ///
    /// The build reads them to compile the `.ps1` payload into a managed
    /// launcher before it is embedded.
    pub fn powershell_params(&self) -> Option<&powershell_hosting::Params> {
        match self {
            TechniqueKind::PowershellHosting { params } => Some(params),
            _ => None,
        }
    }

    /// The technique's [`Category`] (Preparation, Execution or Control).
    ///
    /// Read from the technique's [`TechniqueDef`] so the registry stays the
    /// single source of truth: a technique cannot disagree with itself.
    pub fn category(&self) -> Category {
        match self {
            TechniqueKind::AntiDebug { .. } => anti_debug::DEF.category,
            TechniqueKind::HideThreadFromDebugger { .. } => hide_thread_from_debugger::DEF.category,
            TechniqueKind::Bouncer { .. } => bouncer::DEF.category,
            TechniqueKind::Drop { .. } => drop::DEF.category,
            TechniqueKind::PatchAmsi { .. } => patch_amsi::DEF.category,
            TechniqueKind::PatchEtw { .. } => patch_etw::DEF.category,
            TechniqueKind::HardwareBreakpoints { .. } => hardware_breakpoints::DEF.category,
            TechniqueKind::ProcessMitigations { .. } => process_mitigations::DEF.category,
            TechniqueKind::ImagePathSpoofing { .. } => image_path_spoofing::DEF.category,
            TechniqueKind::ErasePeHeader { .. } => erase_pe_header::DEF.category,
            TechniqueKind::HideModule { .. } => hide_module::DEF.category,
            TechniqueKind::DotnetHosting { .. } => dotnet_hosting::DEF.category,
            TechniqueKind::PowershellHosting { .. } => powershell_hosting::DEF.category,
            TechniqueKind::ImportPowermodule { .. } => import_powermodule::DEF.category,
            TechniqueKind::ProcessHollowing { .. } => process_hollowing::DEF.category,
            TechniqueKind::ReflectiveLoading { .. } => reflective_loading::DEF.category,
            TechniqueKind::ExecutionCallbacks { .. } => execution_callbacks::DEF.category,
            TechniqueKind::Fibers { .. } => fibers::DEF.category,
            TechniqueKind::ModuleStomping { .. } => module_stomping::DEF.category,
            TechniqueKind::EarlyBird { .. } => early_bird::DEF.category,
            TechniqueKind::PeInjection { .. } => pe_injection::DEF.category,
            TechniqueKind::ThreadHijacking { .. } => thread_hijacking::DEF.category,
            TechniqueKind::SelfDeletion { .. } => self_deletion::DEF.category,
            TechniqueKind::PpidSpoofing { .. } => ppid_spoofing::DEF.category,
            TechniqueKind::UnhookNtdll { .. } => unhook_ntdll::DEF.category,
            TechniqueKind::SleepObfuscation { .. } => sleep_obfuscation::DEF.category,
            TechniqueKind::LivingOffTheLand { .. } => living_off_the_land::DEF.category,
            TechniqueKind::Sleep { .. } => sleep::DEF.category,
            TechniqueKind::NetworkStager { .. } => network_stager::DEF.category,
            TechniqueKind::KillSwitch { .. } => killswitch::DEF.category,
            TechniqueKind::Timestomping { .. } => timestomping::DEF.category,
            TechniqueKind::DllHollowing { .. } => dll_hollowing::DEF.category,
            TechniqueKind::ProcessGhosting { .. } => process_ghosting::DEF.category,
            TechniqueKind::VehExecution { .. } => veh_execution::DEF.category,
        }
    }
}

/// Which role a technique plays in the pipeline.
///
/// Variant order is meaningful: it defines the sort key used by
/// [`list`] (Preparation before Execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    /// Modifies the current process state (e.g. patches AMSI) but never runs
    /// the payload.
    Preparation,
    /// Executes the decrypted payload.
    Execution,
    /// Neither prepares state nor runs the payload: it orchestrates the chain
    /// (launch a process, wait). `living_off_the_land` and `sleep`.
    Control,
}

impl Category {
    /// Lowercase label used by `picaro techniques list`.
    pub fn label(self) -> &'static str {
        match self {
            Category::Preparation => "preparation",
            Category::Execution => "execution",
            Category::Control => "control",
        }
    }
}

/// Maturity of a technique.
///
/// Variants are part of the metadata vocabulary; only the ones used by the
/// currently-registered techniques are constructed.
///
/// Variant order is meaningful: it defines the sort key used by [`list`]
/// (Stable before Experimental before Unimplemented before Deprecated).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stability {
    /// Complete and verified: a measurement baseline or passing runtime checks.
    Stable,
    /// Works, but a gap or a caveat remains (see the technique's README).
    Experimental,
    /// Registered and wired (registry arm, metadata, docs, tests) but **not
    /// finished**: either the stub fragment is a placeholder or a required part
    /// of the loader contract is missing, so it must not be shipped as-is.
    /// `plan::validate::advisories` warns when a runtime selects one.
    Unimplemented,
    /// Superseded by a better technique; kept for old plans.
    Deprecated,
}

impl Stability {
    /// Lowercase label used by `picaro techniques list`.
    pub fn label(self) -> &'static str {
        match self {
            Stability::Stable => "stable",
            Stability::Experimental => "experimental",
            Stability::Unimplemented => "unimplemented",
            Stability::Deprecated => "deprecated",
        }
    }
}

/// A capability the build host must provide for a technique.
///
/// The architecture variants (`WindowsX64` / `WindowsX86`) gate which
/// `build.output.arch` a technique can run under; `plan::validate` checks them
/// against the plan. Variants are part of the metadata vocabulary; only the ones
/// used by the currently-registered techniques are constructed.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    WindowsX64,
    WindowsX86,
    KernelAccess,
    AdminRequired,
}

impl Capability {
    /// Lowercase label used by `picaro techniques show`.
    pub fn label(self) -> &'static str {
        match self {
            Capability::WindowsX64 => "windows-x64",
            Capability::WindowsX86 => "windows-x86",
            Capability::KernelAccess => "kernel-access",
            Capability::AdminRequired => "admin-required",
        }
    }
}

/// One YAML parameter of a registry item.
///
/// The shared vocabulary for the catalog: a technique derives its parameters
/// from its `Params` struct at docs-build time, while a loader feature declares
/// them here directly (it has no `Params` struct). Both render as the same
/// `Parameter | Type | Required | Default | Description` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamDef {
    /// Key as it appears under `params:` (or in the feature's YAML block).
    pub key: &'static str,
    /// One sentence shown to the reader.
    pub description: &'static str,
    /// Whether omitting it is an error (as opposed to falling back to `default`).
    pub required: bool,
    /// Default value as written in YAML (e.g. `0x1000`, `wininet.dll`).
    pub default: Option<&'static str>,
    /// The value's shape.
    pub kind: ParamKind,
}

/// The shape of a [`ParamDef`] value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// A string.
    Str,
    /// A YAML sequence.
    List,
    /// One of a fixed set of strings.
    Enum(&'static [&'static str]),
}

impl ParamKind {
    /// The YAML type label shown in `techniques show` and the docs table.
    pub fn label(self) -> &'static str {
        match self {
            ParamKind::Str | ParamKind::Enum(_) => "string",
            ParamKind::List => "list",
        }
    }
}

/// Static metadata describing one technique.
///
/// No logic here — only data consumed by the `techniques` CLI, the `validate`
/// check and the stub renderer.
pub struct TechniqueDef {
    /// YAML key (`technique: <name>`).
    pub name: &'static str,
    /// MITRE ATT&CK technique IDs.
    pub attck: &'static [&'static str],
    /// Maturity.
    pub stability: Stability,
    /// Capabilities the build host must provide.
    pub requires: &'static [Capability],
    /// Names of techniques this one conflicts with.
    pub conflicts: &'static [&'static str],
    /// Pipeline role: Preparation (modifies state) or Execution (runs payload).
    pub category: Category,
    /// Payload formats this Execution technique accepts (`&[]` for a
    /// Preparation/Control step, which runs no payload). `plan::validate` reads
    /// it, and the docs derive the plan builder's accepted formats from it — so
    /// the accepted formats live here, once.
    pub formats: &'static [PayloadFormat],
    /// Whether the technique only works with `build.stub.syscalls.mode: indirect`
    /// (the renderer skips its step; `advisories` warns otherwise).
    pub requires_indirect_syscalls: bool,
    /// Path to the human-readable README (relative to the repo root).
    pub doc_path: &'static str,
    /// The technique's stub fragment source (embedded via `include_str!`).
    pub stub_fragment: &'static str,
    /// A YAML snippet (parseable as a [`RuntimeStep`]) documenting the params.
    pub params_example: &'static str,
    /// The technique's README, embedded via `include_str!` for `techniques show`.
    pub readme: &'static str,
    /// Nt* functions this technique invokes through the syscall layer when
    /// `build.stub.syscalls.mode: indirect` is active. The packer resolves only
    /// the union of the active techniques' requirements (see
    /// `engine::syscalls::required`).
    pub syscalls: &'static [&'static str],
    /// Whether the technique needs the shared payload import resolver
    /// (`engine::imports`) rendered into the stub. The resolver is emitted only
    /// when an active technique declares it, so no unused code is injected.
    pub resolves_imports: bool,
}

/// All registered techniques.
pub fn all() -> &'static [TechniqueDef] {
    &[
        dotnet_hosting::DEF,
        powershell_hosting::DEF,
        import_powermodule::DEF,
        process_hollowing::DEF,
        reflective_loading::DEF,
        execution_callbacks::DEF,
        fibers::DEF,
        module_stomping::DEF,
        early_bird::DEF,
        pe_injection::DEF,
        thread_hijacking::DEF,
        ppid_spoofing::DEF,
        self_deletion::DEF,
        unhook_ntdll::DEF,
        patch_amsi::DEF,
        anti_debug::DEF,
        hide_thread_from_debugger::DEF,
        patch_etw::DEF,
        hardware_breakpoints::DEF,
        process_mitigations::DEF,
        sleep_obfuscation::DEF,
        bouncer::DEF,
        drop::DEF,
        living_off_the_land::DEF,
        sleep::DEF,
        network_stager::DEF,
        killswitch::DEF,
        timestomping::DEF,
        image_path_spoofing::DEF,
        erase_pe_header::DEF,
        hide_module::DEF,
        dll_hollowing::DEF,
        process_ghosting::DEF,
        veh_execution::DEF,
    ]
}

/// Looks up a technique by its YAML key.
///
/// The lookup ignores case and underscores (see [`canonical_name`]), so the CLI
/// and the plan loader agree on what a name means.
pub fn find(name: &str) -> Option<&'static TechniqueDef> {
    let canonical = canonical_name(name)?;
    all().iter().find(|def| def.name == canonical)
}

/// The registry's canonical key for `name`, ignoring case and underscores.
///
/// Both sides are normalized before matching, so a plan may write
/// `reflective_loading`, `ReflectiveLoading`, `REFLECTIVElOADING` or
/// `reflectiveloading` interchangeably. This is the compatibility layer for the
/// eventual migration to CamelCase keys: the canonical names in `DEF` stay the
/// source of truth, and the parser does not need to change.
pub fn canonical_name(name: &str) -> Option<&'static str> {
    let wanted = normalize_key(name);
    all()
        .iter()
        .map(|def| def.name)
        .find(|candidate| normalize_key(candidate) == wanted)
}

/// Lowercases `name` and drops underscores.
fn normalize_key(name: &str) -> String {
    name.chars()
        .filter(|character| *character != '_')
        .collect::<String>()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests;
