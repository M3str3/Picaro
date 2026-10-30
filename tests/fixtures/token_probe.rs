//! Token-proxy probe payload.
//!
//! Duplicates the process token as an impersonation token at
//! `SecurityImpersonation` through the `advapi32!DuplicateTokenEx` slot (which
//! the stub may replace with its generated proxy) and prints the level the
//! kernel reports for the duplicate. `docs/bugs.md` #3: the proxy must apply
//! the requested level instead of keeping the source token's.
//!
//! Compiled by the test with a single `rustc` (no external dependencies).

use std::io::Write;

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_IMPERSONATE: u32 = 0x0004;
const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;

const SECURITY_IMPERSONATION: i32 = 2;
const TOKEN_IMPERSONATION: i32 = 2;
const TOKEN_IMPERSONATION_LEVEL_CLASS: i32 = 9;

type Handle = *mut core::ffi::c_void;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: Handle) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, desired_access: u32, token: *mut Handle) -> i32;
    fn DuplicateTokenEx(
        existing_token: Handle,
        desired_access: u32,
        token_attributes: *const core::ffi::c_void,
        impersonation_level: i32,
        token_type: i32,
        new_token: *mut Handle,
    ) -> i32;
    fn GetTokenInformation(
        token: Handle,
        information_class: i32,
        information: *mut core::ffi::c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

fn main() {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "TOKEN_PROBE start");
    let _ = out.flush();

    let mut token: Handle = core::ptr::null_mut();
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT,
            &mut token,
        )
    };
    if opened == 0 {
        let _ = writeln!(out, "TOKEN open failed");
        return;
    }

    let mut duplicate: Handle = core::ptr::null_mut();
    let duplicated = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
            core::ptr::null(),
            SECURITY_IMPERSONATION,
            TOKEN_IMPERSONATION,
            &mut duplicate,
        )
    };
    let _ = unsafe { CloseHandle(token) };
    if duplicated == 0 {
        let error = unsafe { GetLastError() };
        let _ = writeln!(out, "TOKEN duplicate failed error={error}");
        return;
    }

    let mut level: i32 = -1;
    let mut returned: u32 = 0;
    let queried = unsafe {
        GetTokenInformation(
            duplicate,
            TOKEN_IMPERSONATION_LEVEL_CLASS,
            &mut level as *mut i32 as *mut core::ffi::c_void,
            core::mem::size_of::<i32>() as u32,
            &mut returned,
        )
    };
    let _ = unsafe { CloseHandle(duplicate) };

    if queried == 0 {
        let _ = writeln!(out, "TOKEN query failed");
        return;
    }
    let _ = writeln!(out, "TOKEN level={level}");
    let _ = out.flush();
}
