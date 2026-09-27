//! API-resolution probe payload.
//!
//! Exercises every catalogue entry through its IAT (`ReadProcessMemory`,
//! `NtReadVirtualMemory`, `OpenProcess`, `NtOpenProcess`, `GetProcAddress`) plus
//! the dynamic path (`GetProcAddress` by name and by ordinal) and prints the
//! results. The (ignored) `api_resolution` tests pack it and check the output.
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

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> u32;
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

fn main() {
    let value: u64 = 0x1122_3344_5566_7788;
    let src = &value as *const u64 as *const u8;
    let pid = unsafe { GetCurrentProcessId() };

    // IAT: ReadProcessMemory.
    let mut rpm_buf = [0u8; 8];
    let mut rpm_read = 0usize;
    let rpm = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            src,
            rpm_buf.as_mut_ptr(),
            8,
            &mut rpm_read,
        )
    };

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
    let mut via_handle_buf = [0u8; 8];
    let mut via_handle_read = 0usize;
    let via_handle = unsafe {
        ReadProcessMemory(
            handle,
            src,
            via_handle_buf.as_mut_ptr(),
            8,
            &mut via_handle_read,
        )
    };

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
    let _ = writeln!(out, "API_PROBE rpm={rpm} read={rpm_read} bytes={rpm_buf:02x?}");
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
        "API_PROBE ntopen=0x{nt_open:08x} handle=0x{nt_handle:x}"
    );
    let _ = writeln!(
        out,
        "API_PROBE gpa_read=0x{gpa_read:x} rc={gpa_rc} bytes={gpa_buf:02x?}"
    );
    let _ = writeln!(out, "API_PROBE gpa_ordinal=0x{gpa_ordinal:x}");
    let _ = out.flush();
}
