// --- Process mitigation policies (technique fragment) ---

use windows::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_0,
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_0,
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_0,
};
use windows::Win32::System::Threading::{
    ProcessExtensionPointDisablePolicy, ProcessSignaturePolicy, ProcessSystemCallDisablePolicy,
    SetProcessMitigationPolicy,
};

/// Whether to block DLLs not signed by Microsoft (the "BlockDLLs" mitigation).
const BLOCK_DLLS: bool = $BLOCK_DLLS$;

/// Whether to disable extension points (`AppInit_DLLs`, legacy global hooks).
const EXTENSION_POINTS: bool = $EXTENSION_POINTS$;

/// Whether to block Win32k system calls.
const WIN32K_FILTER: bool = $WIN32K_FILTER$;

/// Hardens the process with documented mitigation policies.
///
/// `block_dlls` is load-bearing: the whole point is that an unsigned userland
/// EDR DLL can no longer map into the process. The other two policies are best
/// effort, because a build or OS that lacks one still benefits from the rest.
pub fn process_mitigations() -> Result<bool, String> {
    if BLOCK_DLLS {
        // Bit 0 = `MicrosoftSignedOnly`: only Microsoft-signed images may load.
        let policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
            Anonymous: PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_0 { Flags: 1 },
        };
        let applied = unsafe {
            SetProcessMitigationPolicy(
                ProcessSignaturePolicy,
                &policy as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY>(),
            )
        };
        if applied.is_err() {
            return Err($MSG_BLOCK_DLLS_FAILED$);
        }
        crate::tech_dbg!("process_mitigations", "non-Microsoft DLLs are now blocked");
    }

    if EXTENSION_POINTS {
        // Bit 0 = `DisableExtensionPoints`.
        let policy = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY {
            Anonymous: PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_0 { Flags: 1 },
        };
        let applied = unsafe {
            SetProcessMitigationPolicy(
                ProcessExtensionPointDisablePolicy,
                &policy as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>(),
            )
        };
        if applied.is_err() {
            crate::tech_dbg!("process_mitigations", "extension-point disable was refused");
        }
    }

    if WIN32K_FILTER {
        // Bit 0 = `DisableWin32kSystemCalls`.
        let policy = PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY {
            Anonymous: PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_0 { Flags: 1 },
        };
        let applied = unsafe {
            SetProcessMitigationPolicy(
                ProcessSystemCallDisablePolicy,
                &policy as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY>(),
            )
        };
        if applied.is_err() {
            crate::tech_dbg!("process_mitigations", "Win32k system-call block was refused");
        }
    }

    // A Preparation always continues the pipeline when it does not error.
    Ok(true)
}
