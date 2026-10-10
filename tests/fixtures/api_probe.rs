//! API-resolution probe payload.
//!
//! Exercises every catalogue entry through its IAT (`ReadProcessMemory`,
//! `NtReadVirtualMemory`, `OpenProcess`, `NtOpenProcess`, `GetProcAddress`) plus
//! the dynamic path (`GetProcAddress` by name and by ordinal) and prints the
//! results. The (ignored) `api_resolution` tests pack it and check the output.
//!
//! With the `--threads` argument it runs the same calls from several threads at
//! once, so the proxies' reentrancy is exercised.
//!
//! Compiled by the test with a single `rustc` (no external dependencies).

use std::io::Write;

type Bool = i32;
type Handle = isize;

/// `PROCESS_QUERY_LIMITED_INFORMATION`.
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
/// `PROCESS_VM_READ` (needed to use the handle with `ReadProcessMemory`).
const PROCESS_VM_READ: u32 = 0x0010;
/// The access mask the probe asks `OpenProcess` for.
const PROBE_ACCESS: u32 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
/// A process id that cannot exist (the value is reserved and never handed out).
const BOGUS_PID: u32 = 0xFFFF_FFFE;

/// The 8 bytes the probe reads back: `0x1122_3344_5566_7788` little-endian.
const VALUE: u64 = 0x1122_3344_5566_7788;
/// The bytes `VALUE` decomposes into.
const VALUE_BYTES: [u8; 8] = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> u32;
    fn GetLastError() -> u32;
    fn SetLastError(code: u32);
    fn ReadProcessMemory(
        h: Handle,
        base: *const u8,
        buf: *mut u8,
        size: usize,
        read: *mut usize,
    ) -> Bool;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn GetModuleHandleA(name: *const u8) -> isize;
    fn GetProcAddress(module: isize, name: *const u8) -> isize;
    fn CreateThread(
        attributes: *const core::ffi::c_void,
        stack_size: usize,
        start: Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>,
        parameter: *mut core::ffi::c_void,
        flags: u32,
        thread_id: *mut u32,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn CloseHandle(handle: Handle) -> Bool;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtReadVirtualMemory(
        h: Handle,
        base: *const u8,
        buf: *mut u8,
        size: usize,
        read: *mut usize,
    ) -> i32;
    fn NtOpenProcess(
        handle: *mut Handle,
        access: u32,
        attributes: *const u8,
        client_id: *const u8,
    ) -> i32;
    fn NtClose(handle: Handle) -> i32;
    fn NtWaitForSingleObject(handle: Handle, alertable: u8, timeout: *const i64) -> i32;
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut u8,
    object_name: *const u8,
    attributes: u32,
    security_descriptor: *const u8,
    security_quality_of_service: *const u8,
}

#[repr(C)]
struct ClientId {
    unique_process: *mut u8,
    unique_thread: *mut u8,
}

/// Signature of the real `OpenProcess` export.
type OpenProcessFn = extern "system" fn(u32, i32, u32) -> Handle;

/// Resolves the *real* `OpenProcess` without the proxy: `kernelbase.dll`
/// exports the same function and is not in the catalogue, so `GetProcAddress`
/// returns the genuine export even when the payload's `OpenProcess` slot is a
/// proxy.
fn real_openprocess() -> Option<OpenProcessFn> {
    let module = unsafe { GetModuleHandleA(b"kernelbase.dll\0".as_ptr()) };
    if module == 0 {
        return None;
    }
    let address = unsafe { GetProcAddress(module, b"OpenProcess\0".as_ptr()) };
    if address == 0 {
        None
    } else {
        Some(unsafe { core::mem::transmute(address) })
    }
}

/// Reads 8 bytes through `ReadProcessMemory` and returns `(bool, bytes)`.
fn rpm_self(src: *const u8, handle: Handle) -> (Bool, usize, [u8; 8]) {
    let mut buf = [0u8; 8];
    let mut read = 0usize;
    let rc = unsafe { ReadProcessMemory(handle, src, buf.as_mut_ptr(), 8, &mut read) };
    (rc, read, buf)
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--threads") {
        run_threads();
    } else {
        run_probe();
    }
}

fn run_probe() {
    let value = VALUE;
    let src = &value as *const u64 as *const u8;
    let pid = unsafe { GetCurrentProcessId() };

    // IAT: ReadProcessMemory.
    let (rpm, rpm_read, rpm_buf) = rpm_self(src, unsafe { GetCurrentProcess() });

    // IAT: NtReadVirtualMemory.
    let mut ntrvm_buf = [0u8; 8];
    let mut ntrvm_read = 0usize;
    let ntrvm = unsafe {
        NtReadVirtualMemory(
            GetCurrentProcess(),
            src,
            ntrvm_buf.as_mut_ptr(),
            8,
            &mut ntrvm_read,
        )
    };

    // IAT: OpenProcess, then use the returned handle with ReadProcessMemory.
    let handle = unsafe { OpenProcess(PROBE_ACCESS, 0, pid) };
    let (via_handle, _via_handle_read, via_handle_buf) = rpm_self(src, handle);

    // IAT: OpenProcess with `inherit` set (maps to `OBJ_INHERIT`).
    let inherit_handle = unsafe { OpenProcess(PROBE_ACCESS, 1, pid) };
    let (inherit_rc, inherit_read, _) = rpm_self(src, inherit_handle);

    // Fidelity: the proxy's `OpenProcess` must answer like the real export for
    // the same inputs (null-or-not, and the error code when null).
    let real_open = real_openprocess();
    let cases: [(&str, u32, i32, u32); 4] = [
        ("zero", 0, 0, pid),
        ("bogus", PROBE_ACCESS, 0, BOGUS_PID),
        ("valid", PROBE_ACCESS, 0, pid),
        ("inherit", PROBE_ACCESS, 1, pid),
    ];
    let mut agree = 0usize;
    let total = cases.len();
    for (label, access, inherit, want_pid) in cases {
        unsafe { SetLastError(0) };
        let proxy_handle = unsafe { OpenProcess(access, inherit, want_pid) };
        let proxy_err = unsafe { GetLastError() };
        let (real_null, real_err) = match real_open {
            Some(real) => {
                unsafe { SetLastError(0) };
                let real_handle = real(access, inherit, want_pid);
                (((real_handle == 0) as i32), unsafe { GetLastError() })
            }
            None => (-1, 0),
        };
        let proxy_null = (proxy_handle == 0) as i32;
        // `GetLastError` is only meaningful after a failure, so it is compared
        // only when both calls returned null.
        if real_null >= 0 && proxy_null == real_null && (proxy_null == 0 || proxy_err == real_err) {
            agree += 1;
        }
        let mut out = std::io::stdout();
        let _ = writeln!(
            out,
            "API_PROBE cmp {label} proxy_null={proxy_null} proxy_err={proxy_err} real_null={real_null} real_err={real_err}"
        );
        let _ = out.flush();
    }

    // IAT: NtOpenProcess.
    let mut nt_handle: Handle = 0;
    let oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: core::ptr::null(),
        attributes: 0,
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };
    let cid = ClientId {
        unique_process: pid as usize as *mut u8,
        unique_thread: core::ptr::null_mut(),
    };
    let nt_open = unsafe {
        NtOpenProcess(
            &mut nt_handle,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &oa as *const ObjectAttributes as *const u8,
            &cid as *const ClientId as *const u8,
        )
    };

    // IAT: NtClose (a plain direct Nt* route).
    let nt_close = unsafe { NtClose(nt_handle) };

    // IAT: NtWaitForSingleObject with the native argument list (alertable = 0,
    // zero relative timeout -> STATUS_TIMEOUT). This one is served by a
    // native-signature proxy helper.
    let zero_timeout: i64 = 0;
    let nt_wait = unsafe { NtWaitForSingleObject(GetCurrentProcess(), 0, &zero_timeout) };

    // Dynamic: GetProcAddress by name, then by ordinal.
    let module = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    let gpa_read = unsafe { GetProcAddress(module, b"ReadProcessMemory\0".as_ptr()) };
    let mut gpa_buf = [0u8; 8];
    let mut gpa_read_bytes = 0usize;
    let gpa_rc = if gpa_read != 0 {
        let f: extern "system" fn(Handle, *const u8, *mut u8, usize, *mut usize) -> Bool =
            unsafe { core::mem::transmute(gpa_read) };
        unsafe {
            f(
                GetCurrentProcess(),
                src,
                gpa_buf.as_mut_ptr(),
                8,
                &mut gpa_read_bytes,
            )
        }
    } else {
        -1
    };
    let gpa_ordinal = unsafe { GetProcAddress(module, 1usize as *const u8) };

    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "API_PROBE rpm={rpm} read={rpm_read} bytes={rpm_buf:02x?}"
    );
    let _ = writeln!(
        out,
        "API_PROBE ntrvm=0x{ntrvm:08x} read={ntrvm_read} bytes={ntrvm_buf:02x?}"
    );
    let _ = writeln!(
        out,
        "API_PROBE open=0x{handle:x} via_handle={via_handle} bytes={via_handle_buf:02x?}"
    );
    let _ = writeln!(
        out,
        "API_PROBE inherit=0x{inherit_handle:x} rc={inherit_rc} read={inherit_read}"
    );
    let _ = writeln!(out, "API_PROBE open_fidelity agree={agree}/{total}");
    let _ = writeln!(
        out,
        "API_PROBE ntopen=0x{nt_open:08x} handle=0x{nt_handle:x}"
    );
    let _ = writeln!(out, "API_PROBE ntclose=0x{nt_close:08x}");
    let _ = writeln!(out, "API_PROBE ntwait=0x{nt_wait:08x}");
    let _ = writeln!(
        out,
        "API_PROBE gpa_read=0x{gpa_read:x} rc={gpa_rc} bytes={gpa_buf:02x?}"
    );
    let _ = writeln!(out, "API_PROBE gpa_ordinal=0x{gpa_ordinal:x}");
    let _ = out.flush();
}

/// Per-thread results for the concurrency probe.
#[repr(C)]
struct WorkerCtx {
    addr: usize,
    pid: u32,
    rpm_ok: std::sync::atomic::AtomicI32,
    open_ok: std::sync::atomic::AtomicI32,
    gpa_ok: std::sync::atomic::AtomicI32,
}

/// Runs on a raw OS thread (no `std::thread`, so no Rust thread-locals): reads
/// through `ReadProcessMemory`, opens the process with `OpenProcess` and reads
/// through that handle, and resolves `ReadProcessMemory` via the
/// `GetProcAddress` handler.
extern "system" fn worker_fn(param: *mut core::ffi::c_void) -> u32 {
    use std::sync::atomic::Ordering;
    let ctx = unsafe { &*(param as *const WorkerCtx) };
    let src = ctx.addr as *const u8;

    let (rpm, rpm_read, rpm_buf) = rpm_self(src, unsafe { GetCurrentProcess() });
    ctx.rpm_ok.store(
        (rpm == 1 && rpm_read == 8 && rpm_buf == VALUE_BYTES) as i32,
        Ordering::Relaxed,
    );

    let handle = unsafe { OpenProcess(PROBE_ACCESS, 0, ctx.pid) };
    let (via, via_read, via_buf) = rpm_self(src, handle);
    ctx.open_ok.store(
        (handle > 0 && via == 1 && via_read == 8 && via_buf == VALUE_BYTES) as i32,
        Ordering::Relaxed,
    );

    let module = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    let resolved = unsafe { GetProcAddress(module, b"ReadProcessMemory\0".as_ptr()) };
    let gpa_ok = if resolved != 0 {
        let f: extern "system" fn(Handle, *const u8, *mut u8, usize, *mut usize) -> Bool =
            unsafe { core::mem::transmute(resolved) };
        let mut buf = [0u8; 8];
        let mut read = 0usize;
        let rc = unsafe { f(GetCurrentProcess(), src, buf.as_mut_ptr(), 8, &mut read) };
        rc == 1 && read == 8 && buf == VALUE_BYTES
    } else {
        false
    };
    ctx.gpa_ok.store(gpa_ok as i32, Ordering::Relaxed);
    0
}

/// Exercises the proxies from several raw OS threads at once.
///
/// Each thread reads its own buffer through `ReadProcessMemory` (routed on
/// `NtReadVirtualMemory`), opens the current process with `OpenProcess`
/// (rebuilt on `NtOpenProcess`) and reads again through that handle, and
/// resolves `ReadProcessMemory` dynamically through the `GetProcAddress`
/// handler. If every thread sees the right bytes, the proxies are reentrant.
///
/// Raw `CreateThread` is used rather than `std::thread` on purpose: the mapped
/// image shares a TLS index with a loaded module (a `reflective_loading`
/// limitation), and `std`'s thread machinery trips over it.
fn run_threads() {
    use std::sync::atomic::{AtomicI32, Ordering};
    const THREADS: usize = 8;

    let value = VALUE;
    let pid = unsafe { GetCurrentProcessId() };
    let mut ctxs: Vec<WorkerCtx> = (0..THREADS)
        .map(|_| WorkerCtx {
            addr: &value as *const u64 as usize,
            pid,
            rpm_ok: AtomicI32::new(0),
            open_ok: AtomicI32::new(0),
            gpa_ok: AtomicI32::new(0),
        })
        .collect();

    let base = ctxs.as_mut_ptr();
    let mut threads: Vec<Handle> = Vec::with_capacity(THREADS);
    for i in 0..THREADS {
        let param = unsafe { base.add(i) } as *mut core::ffi::c_void;
        let handle = unsafe {
            CreateThread(
                core::ptr::null(),
                0,
                Some(worker_fn),
                param,
                0,
                core::ptr::null_mut(),
            )
        };
        threads.push(handle);
    }
    for handle in threads {
        unsafe {
            WaitForSingleObject(handle, 0xFFFF_FFFF);
            CloseHandle(handle);
        }
    }

    let mut rpm_good = 0usize;
    let mut open_good = 0usize;
    let mut gpa_good = 0usize;
    for ctx in &ctxs {
        rpm_good += (ctx.rpm_ok.load(Ordering::Relaxed) == 1) as usize;
        open_good += (ctx.open_ok.load(Ordering::Relaxed) == 1) as usize;
        gpa_good += (ctx.gpa_ok.load(Ordering::Relaxed) == 1) as usize;
    }

    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "API_PROBE threads={THREADS} rpm={rpm_good} open={open_good} gpa={gpa_good}"
    );
    let _ = out.flush();
}
