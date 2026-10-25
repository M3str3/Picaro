//! Generated stub helper bodies for the syscall layer.
//!
//! Each constant is Rust source injected into the generated stub: the `none`
//! variant maps the `nt_*` helper to the plain Win32 API, the `indirect`
//! variant resolves the SSN and goes through the `syscall; ret` gadget. They
//! live in their own file because the table (`NT_FUNCTIONS`) and the renderer
//! are the only consumers and would otherwise drown in raw string literals.

// --- Generated helper bodies -------------------------------------------------
//
// Each helper documents its Nt* signature in a comment (comments never reach
// the binary). The bodies are plain text injected into the generated stub;
// see the fragment contract in the module docs above.

/// `nt_alloc_vm`, mode none: VirtualAllocEx mapped to an NTSTATUS.
pub(super) const ALLOC_VM_NONE: &str = r#"    /// NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, ZeroBits,
    /// &RegionSize, AllocationType, Protect). None mode: VirtualAllocEx with
    /// the result mapped to an NTSTATUS. The actual base comes back through
    /// `base`, the actual size through `size`.
    pub fn nt_alloc_vm(
        process: HANDLE,
        base: *mut *mut core::ffi::c_void,
        _zero_bits: usize,
        size: *mut usize,
        alloc_type: u32,
        protect: u32,
    ) -> i32 {
        unsafe {
            let requested = if (*base).is_null() {
                None
            } else {
                Some(*base as *const core::ffi::c_void)
            };
            let address = VirtualAllocEx(
                process,
                requested,
                *size,
                VIRTUAL_ALLOCATION_TYPE(alloc_type),
                PAGE_PROTECTION_FLAGS(protect),
            );
            if address.is_null() {
                return STATUS_UNSUCCESSFUL;
            }
            *base = address;
            STATUS_SUCCESS
        }
    }
"#;

/// `nt_alloc_vm`, mode indirect: syscall with the resolved SSN.
pub(super) const ALLOC_VM_INDIRECT: &str = r#"    /// NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, ZeroBits,
    /// &RegionSize, AllocationType, Protect). BaseAddress/RegionSize are
    /// in-out pointers: the actual base/size come back through them.
    pub fn nt_alloc_vm(
        process: HANDLE,
        base: *mut *mut core::ffi::c_void,
        zero_bits: usize,
        size: *mut usize,
        alloc_type: u32,
        protect: u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                zero_bits,
                size as usize,
                alloc_type as usize,
                protect as usize,
                0,
                0,
                0,
                0,
                0,
                ssns.alloc_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_write_vm`, mode none.
pub(super) const WRITE_VM_NONE: &str = r#"    /// NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToWrite, &NumberOfBytesWritten). None mode:
    /// WriteProcessMemory mapped to an NTSTATUS (the HRESULT carries the Win32
    /// error, so a failure is diagnosable).
    pub fn nt_write_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        size: usize,
        written: *mut usize,
    ) -> i32 {
        unsafe {
            match WriteProcessMemory(process, base, buffer, size, Some(written)) {
                Ok(()) => STATUS_SUCCESS,
                Err(e) => e.code().0,
            }
        }
    }
"#;

/// `nt_write_vm`, mode indirect.
pub(super) const WRITE_VM_INDIRECT: &str = r#"    /// NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToWrite, &NumberOfBytesWritten).
    pub fn nt_write_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        size: usize,
        written: *mut usize,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                buffer as usize,
                size,
                written as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.write_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_read_vm`, mode none.
pub(super) const READ_VM_NONE: &str = r#"    /// NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToRead, &NumberOfBytesRead). None mode: ReadProcessMemory
    /// mapped to an NTSTATUS (the HRESULT carries the Win32 error).
    pub fn nt_read_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32 {
        unsafe {
            match ReadProcessMemory(process, base, buffer, size, Some(read)) {
                Ok(()) => STATUS_SUCCESS,
                Err(e) => e.code().0,
            }
        }
    }
"#;

/// `nt_read_vm`, mode indirect.
pub(super) const READ_VM_INDIRECT: &str = r#"    /// NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToRead, &NumberOfBytesRead).
    pub fn nt_read_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                buffer as usize,
                size,
                read as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.read_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_resume_thread`, mode none.
pub(super) const RESUME_THREAD_NONE: &str = r#"    /// NtResumeThread(ThreadHandle, &PreviousSuspendCount). None mode:
    /// ResumeThread mapped to an NTSTATUS.
    pub fn nt_resume_thread(thread: HANDLE, previous: *mut u32) -> i32 {
        unsafe {
            let count = ResumeThread(thread);
            if count == u32::MAX {
                return STATUS_UNSUCCESSFUL;
            }
            if !previous.is_null() {
                *previous = count;
            }
            STATUS_SUCCESS
        }
    }
"#;

/// `nt_resume_thread`, mode indirect.
pub(super) const RESUME_THREAD_INDIRECT: &str = r#"    /// NtResumeThread(ThreadHandle, &PreviousSuspendCount).
    pub fn nt_resume_thread(thread: HANDLE, previous: *mut u32) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                previous as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.resume_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_unmap_view`, mode none: windows-rs does not declare
/// `NtUnmapViewOfSection`, so it is resolved dynamically (as before phase 6a).
/// `$NTDLL_DEF$` / `$UNMAP_FUNC_DEF$` are substituted by the renderer with
/// runtime-reconstructed (obfuscated) strings.
pub(super) const UNMAP_VIEW_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type UnmapViewFn = unsafe extern "system" fn(HANDLE, *const core::ffi::c_void) -> i32;

    /// NtUnmapViewOfSection(ProcessHandle, BaseAddress). None mode: resolve
    /// the export dynamically (windows-rs does not declare it) and call it.
    pub fn nt_unmap_view(process: HANDLE, base: *mut core::ffi::c_void) -> i32 {
        let address = resolve_nt_export(&$UNMAP_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let unmap: UnmapViewFn = unsafe { std::mem::transmute(address) };
        unsafe { unmap(process, base) }
    }
"#;

/// `nt_unmap_view`, mode indirect.
pub(super) const UNMAP_VIEW_INDIRECT: &str = r#"    /// NtUnmapViewOfSection(ProcessHandle, BaseAddress).
    pub fn nt_unmap_view(process: HANDLE, base: *mut core::ffi::c_void) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.unmap_view,
                *gadget,
            )
        }
    }
"#;

/// `nt_protect_vm`, mode none: VirtualProtectEx mapped to an NTSTATUS.
pub(super) const PROTECT_VM_NONE: &str = r#"    /// NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize,
    /// NewProtect, &OldProtect). None mode: VirtualProtectEx mapped to an
    /// NTSTATUS. The address and size are passed by value (the caller does
    /// not need the in-out results).
    pub fn nt_protect_vm(
        process: HANDLE,
        base: *mut core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        unsafe {
            match VirtualProtectEx(
                process,
                base,
                size,
                PAGE_PROTECTION_FLAGS(new_protect),
                old_protect as *mut PAGE_PROTECTION_FLAGS,
            ) {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_protect_vm`, mode indirect: syscall with the resolved SSN.
pub(super) const PROTECT_VM_INDIRECT: &str = r#"    /// NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize,
    /// NewProtect, &OldProtect). BaseAddress/RegionSize are in-out pointers;
    /// the helpers expose them by value so the caller can ignore the results.
    pub fn nt_protect_vm(
        process: HANDLE,
        base: *mut core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let mut base_addr = base;
        let mut region = size;
        unsafe {
            nt_invoke(
                process.0 as usize,
                &mut base_addr as *mut _ as usize,
                &mut region as *mut _ as usize,
                new_protect as usize,
                old_protect as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.protect_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_free_vm`, mode none: `VirtualFree` mapped to an NTSTATUS.
///
/// `VirtualFree` only releases the calling process, so the process handle is
/// ignored; `MEM_RELEASE` requires `size` to be zero, exactly as the Win32 API
/// documents.
pub(super) const FREE_VM_NONE: &str = r#"    /// NtFreeVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize, FreeType).
    /// None mode: VirtualFree mapped to an NTSTATUS (current process only).
    pub fn nt_free_vm(
        _process: HANDLE,
        base: *mut *mut core::ffi::c_void,
        size: *mut usize,
        free_type: u32,
    ) -> i32 {
        let address = unsafe { *base };
        let region = unsafe { *size };
        unsafe {
            match VirtualFree(address, region, VIRTUAL_FREE_TYPE(free_type)) {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_free_vm`, mode indirect: syscall with the resolved SSN.
pub(super) const FREE_VM_INDIRECT: &str = r#"    /// NtFreeVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize, FreeType).
    pub fn nt_free_vm(
        process: HANDLE,
        base: *mut *mut core::ffi::c_void,
        size: *mut usize,
        free_type: u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                size as usize,
                free_type as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.free_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_suspend_thread`, mode none: SuspendThread mapped to an NTSTATUS.
pub(super) const SUSPEND_THREAD_NONE: &str = r#"    /// NtSuspendThread(ThreadHandle, &PreviousSuspendCount). None mode:
    /// SuspendThread mapped to an NTSTATUS.
    pub fn nt_suspend_thread(thread: HANDLE, previous: *mut u32) -> i32 {
        unsafe {
            let count = SuspendThread(thread);
            if count == u32::MAX {
                return STATUS_UNSUCCESSFUL;
            }
            if !previous.is_null() {
                *previous = count;
            }
            STATUS_SUCCESS
        }
    }
"#;

/// `nt_suspend_thread`, mode indirect.
pub(super) const SUSPEND_THREAD_INDIRECT: &str = r#"    /// NtSuspendThread(ThreadHandle, &PreviousSuspendCount).
    pub fn nt_suspend_thread(thread: HANDLE, previous: *mut u32) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                previous as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.suspend_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_query_info_process`, mode none: windows-rs does not declare
/// `NtQueryInformationProcess`, so it is resolved dynamically (like
/// `nt_unmap_view`). `$QUERY_FUNC_DEF$` is substituted by the renderer with a
/// runtime-reconstructed (obfuscated) string.
pub(super) const QUERY_INFO_PROCESS_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type QueryInfoFn = unsafe extern "system" fn(
        HANDLE,
        i32,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32;

    /// NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
    /// ProcessInformation, ProcessInformationLength, ReturnLength). None mode:
    /// resolve the export dynamically (windows-rs does not declare it).
    pub fn nt_query_info_process(
        process: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32 {
        let address = resolve_nt_export(&$QUERY_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let query: QueryInfoFn = unsafe { std::mem::transmute(address) };
        unsafe { query(process, info_class, info, info_len, return_len) }
    }
"#;

/// `nt_query_info_process`, mode indirect.
pub(super) const QUERY_INFO_PROCESS_INDIRECT: &str = r#"    /// NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
    /// ProcessInformation, ProcessInformationLength, ReturnLength).
    pub fn nt_query_info_process(
        process: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                info_class as usize,
                info as usize,
                info_len as usize,
                return_len as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.query_info_process,
                *gadget,
            )
        }
    }
"#;

/// `nt_get_context_thread`, mode none: windows-rs does not declare
/// `NtGetContextThread`, so it is resolved dynamically. `$GET_CONTEXT_FUNC_DEF$`
/// is substituted by the renderer with a runtime-reconstructed (obfuscated)
/// string.
pub(super) const GET_CONTEXT_THREAD_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type GetContextFn = unsafe extern "system" fn(HANDLE, *mut core::ffi::c_void) -> i32;

    /// NtGetContextThread(ThreadHandle, &Context). None mode: resolve the
    /// export dynamically (windows-rs does not declare it).
    pub fn nt_get_context_thread(thread: HANDLE, context: *mut core::ffi::c_void) -> i32 {
        let address = resolve_nt_export(&$GET_CONTEXT_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let get_context: GetContextFn = unsafe { std::mem::transmute(address) };
        unsafe { get_context(thread, context) }
    }
"#;

/// `nt_get_context_thread`, mode indirect.
pub(super) const GET_CONTEXT_THREAD_INDIRECT: &str = r#"    /// NtGetContextThread(ThreadHandle, &Context).
    pub fn nt_get_context_thread(thread: HANDLE, context: *mut core::ffi::c_void) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                context as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.get_context_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_set_context_thread`, mode none: windows-rs does not declare
/// `NtSetContextThread`, so it is resolved dynamically (like `nt_get_context_thread`).
/// `$SET_CONTEXT_FUNC_DEF$` is substituted by the renderer with a
/// runtime-reconstructed (obfuscated) string.
pub(super) const SET_CONTEXT_THREAD_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type SetContextFn = unsafe extern "system" fn(HANDLE, *mut core::ffi::c_void) -> i32;

    /// NtSetContextThread(ThreadHandle, &Context). None mode: resolve the
    /// export dynamically (windows-rs does not declare it).
    pub fn nt_set_context_thread(thread: HANDLE, context: *mut core::ffi::c_void) -> i32 {
        let address = resolve_nt_export(&$SET_CONTEXT_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let set_context: SetContextFn = unsafe { std::mem::transmute(address) };
        unsafe { set_context(thread, context) }
    }
"#;

/// `nt_set_context_thread`, mode indirect.
pub(super) const SET_CONTEXT_THREAD_INDIRECT: &str = r#"    /// NtSetContextThread(ThreadHandle, &Context).
    pub fn nt_set_context_thread(thread: HANDLE, context: *mut core::ffi::c_void) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                context as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.set_context_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_create_thread_ex`, mode none: `CreateRemoteThread` (which also takes the
/// current process handle), mapped to an NTSTATUS. The Win32 flag values differ
/// from the native ones, so only the create-suspended bit is translated.
pub(super) const CREATE_THREAD_EX_NONE: &str = r#"    /// Signature of a thread start routine (one pointer argument).
    type ThreadStartFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;

    /// Native `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`; Win32 spells the same idea
    /// `CREATE_SUSPENDED` with a different value (4), so the helper translates.
    const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;
    const WIN32_CREATE_SUSPENDED: u32 = 0x0000_0004;

    /// NtCreateThreadEx(&ThreadHandle, DesiredAccess, &ObjectAttributes,
    /// ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
    /// MaximumStackSize, &AttributeList). None mode: `CreateRemoteThread` on
    /// `process` (the current process handle works too).
    pub fn nt_create_thread_ex(
        process: HANDLE,
        thread: *mut HANDLE,
        start: usize,
        argument: usize,
        create_flags: u32,
    ) -> i32 {
        if start == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let flags = if create_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED != 0 {
            WIN32_CREATE_SUSPENDED
        } else {
            0
        };
        let start: ThreadStartFn = unsafe { std::mem::transmute(start) };
        unsafe {
            match CreateRemoteThread(
                process,
                None,
                0,
                Some(start),
                Some(argument as *const core::ffi::c_void),
                flags,
                None,
            ) {
                Ok(handle) => {
                    if !thread.is_null() {
                        *thread = handle;
                    }
                    STATUS_SUCCESS
                }
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_create_thread_ex`, mode indirect.
pub(super) const CREATE_THREAD_EX_INDIRECT: &str = r#"    /// Native `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` (accepted by
    /// `NtCreateThreadEx` as-is).
    const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

    /// `THREAD_ALL_ACCESS`; the native bitmask (not the Win32 constant, which
    /// only matches on Vista+).
    const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

    /// NtCreateThreadEx(&ThreadHandle, DesiredAccess, &ObjectAttributes,
    /// ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
    /// MaximumStackSize, &AttributeList). Eleven arguments — the widest call the
    /// trampoline carries.
    pub fn nt_create_thread_ex(
        process: HANDLE,
        thread: *mut HANDLE,
        start: usize,
        argument: usize,
        create_flags: u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread as usize,
                THREAD_ALL_ACCESS as usize,
                0,
                process.0 as usize,
                start,
                argument,
                create_flags as usize,
                0,
                0,
                0,
                0,
                ssns.create_thread_ex,
                *gadget,
            )
        }
    }
"#;

/// `nt_wait_for_single_object`, mode none: `WaitForSingleObject` already returns
/// the NTSTATUS-compatible `WAIT_*` values (`WAIT_OBJECT_0` = `STATUS_SUCCESS`,
/// `WAIT_TIMEOUT` = `STATUS_TIMEOUT`, `WAIT_FAILED` = `0xFFFFFFFF`).
pub(super) const WAIT_FOR_SINGLE_OBJECT_NONE: &str = r#"    /// NtWaitForSingleObject(Handle, Alertable, &Timeout). None mode:
    /// `WaitForSingleObject` in milliseconds (`u32::MAX` = infinite).
    pub fn nt_wait_for_single_object(handle: HANDLE, timeout_ms: u32) -> i32 {
        unsafe { WaitForSingleObject(handle, timeout_ms).0 as i32 }
    }
"#;

/// `nt_wait_for_single_object`, mode indirect. The 100 ns relative timeout is
/// derived from the millisecond value the callers use.
pub(super) const WAIT_FOR_SINGLE_OBJECT_INDIRECT: &str = r#"    /// NtWaitForSingleObject(Handle, Alertable, &Timeout).
    pub fn nt_wait_for_single_object(handle: HANDLE, timeout_ms: u32) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        // A relative timeout is negative and in 100 ns units; an infinite wait
        // passes a null pointer.
        let mut timeout: i64 = 0;
        let timeout_ptr = if timeout_ms == u32::MAX {
            std::ptr::null_mut()
        } else {
            timeout = -i64::from(timeout_ms) * 10_000;
            &mut timeout
        };
        unsafe {
            nt_invoke(
                handle.0 as usize,
                0,
                timeout_ptr as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.wait_for_single_object,
                *gadget,
            )
        }
    }
"#;

/// `nt_query_info_thread`, mode none: windows-rs does not declare
/// `NtQueryInformationThread`, so it is resolved dynamically (like
/// `nt_query_info_process`). `$QUERY_THREAD_FUNC_DEF$` is substituted by the
/// renderer with a runtime-reconstructed (obfuscated) string.
pub(super) const QUERY_INFO_THREAD_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type QueryThreadFn = unsafe extern "system" fn(
        HANDLE,
        i32,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32;

    /// NtQueryInformationThread(ThreadHandle, ThreadInformationClass,
    /// ThreadInformation, ThreadInformationLength, ReturnLength). None mode:
    /// resolve the export dynamically (windows-rs does not declare it).
    pub fn nt_query_info_thread(
        thread: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32 {
        let address = resolve_nt_export(&$QUERY_THREAD_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let query: QueryThreadFn = unsafe { std::mem::transmute(address) };
        unsafe { query(thread, info_class, info, info_len, return_len) }
    }
"#;

/// `nt_query_info_thread`, mode indirect.
pub(super) const QUERY_INFO_THREAD_INDIRECT: &str = r#"    /// NtQueryInformationThread(ThreadHandle, ThreadInformationClass,
    /// ThreadInformation, ThreadInformationLength, ReturnLength).
    pub fn nt_query_info_thread(
        thread: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                info_class as usize,
                info as usize,
                info_len as usize,
                return_len as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.query_info_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_close`, mode none.
pub(super) const CLOSE_NONE: &str = r#"    /// NtClose(Handle). None mode: CloseHandle mapped to an NTSTATUS.
    pub fn nt_close(handle: HANDLE) -> i32 {
        unsafe {
            match CloseHandle(handle) {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_delay_execution`, mode none: resolve the export dynamically.
pub(super) const DELAY_EXECUTION_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type DelayExecutionFn = unsafe extern "system" fn(u8, *const i64) -> i32;

    /// NtDelayExecution(Alertable, &DelayInterval). None mode: resolve the
    /// export dynamically (windows-rs does not declare it).
    pub fn nt_delay_execution(alertable: u8, interval: *const i64) -> i32 {
        let address = resolve_nt_export(&$DELAY_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let delay: DelayExecutionFn = unsafe { std::mem::transmute(address) };
        unsafe { delay(alertable, interval) }
    }
"#;

/// `nt_delay_execution`, mode indirect: syscall with the resolved SSN.
pub(super) const DELAY_EXECUTION_INDIRECT: &str = r#"    /// NtDelayExecution(Alertable, &DelayInterval).
    pub fn nt_delay_execution(alertable: u8, interval: *const i64) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                alertable as usize,
                interval as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.delay_execution,
                *gadget,
            )
        }
    }
"#;

/// `nt_close`, mode indirect.
/// `nt_query_vm`, mode none: resolve the export dynamically.
pub(super) const QUERY_VM_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type QueryVmFn = unsafe extern "system" fn(
        HANDLE,
        *const core::ffi::c_void,
        u32,
        *mut core::ffi::c_void,
        usize,
        *mut usize,
    ) -> i32;

    /// NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
    /// MemoryInformation, MemoryInformationLength, ReturnLength). None mode:
    /// resolve the export dynamically (windows-rs does not declare it).
    pub fn nt_query_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        class: u32,
        info: *mut core::ffi::c_void,
        info_len: usize,
        return_len: *mut usize,
    ) -> i32 {
        let address = resolve_nt_export(&$QUERY_VM_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let query: QueryVmFn = unsafe { std::mem::transmute(address) };
        unsafe { query(process, base, class, info, info_len, return_len) }
    }
"#;

/// `nt_query_vm`, mode indirect: syscall with the resolved SSN.
pub(super) const QUERY_VM_INDIRECT: &str = r#"    /// NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
    /// MemoryInformation, MemoryInformationLength, ReturnLength).
    pub fn nt_query_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        class: u32,
        info: *mut core::ffi::c_void,
        info_len: usize,
        return_len: *mut usize,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                class as usize,
                info as usize,
                info_len,
                return_len as usize,
                0,
                0,
                0,
                0,
                0,
                ssns.query_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_open_thread_token`, mode none: the advapi32 wrapper mapped to an
/// NTSTATUS.
pub(super) const OPEN_THREAD_TOKEN_NONE: &str = r#"    /// NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, &TokenHandle).
    /// None mode: OpenThreadToken mapped to an NTSTATUS.
    pub fn nt_open_thread_token(
        thread: HANDLE,
        access: u32,
        open_as_self: u8,
        token: *mut core::ffi::c_void,
    ) -> i32 {
        unsafe {
            match OpenThreadToken(
                thread,
                TOKEN_ACCESS_MASK(access),
                windows::Win32::Foundation::BOOL(open_as_self as i32),
                token as *mut HANDLE,
            ) {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_open_thread_token`, mode indirect: syscall with the resolved SSN.
pub(super) const OPEN_THREAD_TOKEN_INDIRECT: &str = r#"    /// NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, &TokenHandle).
    pub fn nt_open_thread_token(
        thread: HANDLE,
        access: u32,
        open_as_self: u8,
        token: *mut core::ffi::c_void,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                access as usize,
                open_as_self as usize,
                token as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.open_thread_token,
                *gadget,
            )
        }
    }
"#;

pub(super) const CLOSE_INDIRECT: &str = r#"    /// NtClose(Handle).
    pub fn nt_close(handle: HANDLE) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                handle.0 as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.close,
                *gadget,
            )
        }
    }
"#;

/// Every Nt* function the stub can invoke, in canonical (rendering) order.
/// `nt_open_process`, mode none.
pub(super) const OPEN_PROCESS_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type OpenProcessFn = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        u32,
        *const core::ffi::c_void,
        *const core::ffi::c_void,
    ) -> i32;

    /// NtOpenProcess(&Handle, DesiredAccess, &ObjectAttributes, &ClientId). None
    /// mode: resolve the export dynamically (windows-rs does not declare it) and
    /// call it. `attributes` and `client_id` are opaque here.
    pub fn nt_open_process(
        handle: *mut core::ffi::c_void,
        access: u32,
        attributes: *const core::ffi::c_void,
        client_id: *const core::ffi::c_void,
    ) -> i32 {
        let address = resolve_nt_export(&$OPEN_PROCESS_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let open: OpenProcessFn = unsafe { std::mem::transmute(address) };
        unsafe { open(handle, access, attributes, client_id) }
    }
"#;

/// `nt_open_process`, mode indirect.
pub(super) const OPEN_PROCESS_INDIRECT: &str = r#"    /// NtOpenProcess(&Handle, DesiredAccess, &ObjectAttributes, &ClientId).
    pub fn nt_open_process(
        handle: *mut core::ffi::c_void,
        access: u32,
        attributes: *const core::ffi::c_void,
        client_id: *const core::ffi::c_void,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                handle as usize,
                access as usize,
                attributes as usize,
                client_id as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.open_process,
                *gadget,
            )
        }
    }
"#;

/// `nt_open_process_token`, mode none: the ntdll export resolved dynamically
/// (windows-rs does not declare it).
pub(super) const OPEN_PROCESS_TOKEN_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type OpenProcessTokenFn = unsafe extern "system" fn(
        HANDLE,
        u32,
        *mut core::ffi::c_void,
    ) -> i32;

    /// NtOpenProcessToken(ProcessHandle, DesiredAccess, &TokenHandle). None mode:
    /// resolve the export dynamically (windows-rs does not declare it) and call
    /// it.
    pub fn nt_open_process_token(
        process: HANDLE,
        access: u32,
        token: *mut core::ffi::c_void,
    ) -> i32 {
        let address = resolve_nt_export(&$OPEN_PROCESS_TOKEN_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let open: OpenProcessTokenFn = unsafe { std::mem::transmute(address) };
        unsafe { open(process, access, token) }
    }
"#;

/// `nt_open_process_token`, mode indirect.
pub(super) const OPEN_PROCESS_TOKEN_INDIRECT: &str = r#"    /// NtOpenProcessToken(ProcessHandle, DesiredAccess, &TokenHandle).
    pub fn nt_open_process_token(
        process: HANDLE,
        access: u32,
        token: *mut core::ffi::c_void,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                access as usize,
                token as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.open_process_token,
                *gadget,
            )
        }
    }
"#;

/// `nt_duplicate_token`, mode none: the ntdll export resolved dynamically
/// (windows-rs does not declare it).
pub(super) const DUPLICATE_TOKEN_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type DuplicateTokenFn = unsafe extern "system" fn(
        HANDLE,
        u32,
        *const core::ffi::c_void,
        u8,
        i32,
        *mut core::ffi::c_void,
    ) -> i32;

    /// NtDuplicateToken(ExistingTokenHandle, DesiredAccess, &ObjectAttributes,
    /// EffectiveOnly, TokenType, &NewTokenHandle). None mode: resolve the export
    /// dynamically (windows-rs does not declare it) and call it.
    pub fn nt_duplicate_token(
        existing: HANDLE,
        access: u32,
        attributes: *const core::ffi::c_void,
        effective_only: u8,
        token_type: i32,
        new_token: *mut core::ffi::c_void,
    ) -> i32 {
        let address = resolve_nt_export(&$DUPLICATE_TOKEN_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let duplicate: DuplicateTokenFn = unsafe { std::mem::transmute(address) };
        unsafe { duplicate(existing, access, attributes, effective_only, token_type, new_token) }
    }
"#;

/// `nt_duplicate_token`, mode indirect.
pub(super) const DUPLICATE_TOKEN_INDIRECT: &str = r#"    /// NtDuplicateToken(ExistingTokenHandle, DesiredAccess, &ObjectAttributes,
    /// EffectiveOnly, TokenType, &NewTokenHandle).
    pub fn nt_duplicate_token(
        existing: HANDLE,
        access: u32,
        attributes: *const core::ffi::c_void,
        effective_only: u8,
        token_type: i32,
        new_token: *mut core::ffi::c_void,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                existing.0 as usize,
                access as usize,
                attributes as usize,
                effective_only as usize,
                token_type as usize,
                new_token as usize,
                0,
                0,
                0,
                0,
                0,
                ssns.duplicate_token,
                *gadget,
            )
        }
    }
"#;

/// `nt_queue_apc`, mode none: `QueueUserAPC` mapped to an NTSTATUS.
///
/// The native call carries three APC arguments; the Win32 one carries a single
/// pointer-sized value, so only `argument1` survives the mapping. The Win32
/// error is mapped to an HRESULT so a failure names the real reason.
pub(super) const QUEUE_APC_NONE: &str = r#"    /// Signature of a user APC routine (one pointer-sized argument).
    type ApcRoutineFn = unsafe extern "system" fn(usize);

    /// NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2,
    /// ApcArgument3). None mode: `QueueUserAPC`.
    pub fn nt_queue_apc(
        thread: HANDLE,
        routine: *const core::ffi::c_void,
        argument1: *mut core::ffi::c_void,
        _argument2: *mut core::ffi::c_void,
        _argument3: *mut core::ffi::c_void,
    ) -> i32 {
        let routine: ApcRoutineFn = unsafe { std::mem::transmute(routine) };
        let queued = unsafe { QueueUserAPC(Some(routine), thread, argument1 as usize) };
        if queued == 0 {
            let error = unsafe { GetLastError() };
            if error.0 == 0 {
                return STATUS_UNSUCCESSFUL;
            }
            return windows::core::HRESULT::from_win32(error.0).0;
        }
        STATUS_SUCCESS
    }
"#;

/// `nt_queue_apc`, mode indirect.
pub(super) const QUEUE_APC_INDIRECT: &str = r#"    /// NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2,
    /// ApcArgument3).
    pub fn nt_queue_apc(
        thread: HANDLE,
        routine: *const core::ffi::c_void,
        argument1: *mut core::ffi::c_void,
        argument2: *mut core::ffi::c_void,
        argument3: *mut core::ffi::c_void,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                routine as usize,
                argument1 as usize,
                argument2 as usize,
                argument3 as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.queue_apc,
                *gadget,
            )
        }
    }
"#;

/// `nt_set_info_file`, mode none: the ntdll export resolved dynamically.
///
/// The Win32 equivalent (`SetFileInformationByHandle`) takes a different class
/// enumeration, so the native call is used verbatim in both modes.
pub(super) const SET_INFO_FILE_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type SetInfoFileFn = unsafe extern "system" fn(
        HANDLE,
        *mut core::ffi::c_void,
        *const core::ffi::c_void,
        u32,
        i32,
    ) -> i32;

    /// NtSetInformationFile(FileHandle, &IoStatusBlock, FileInformation,
    /// Length, FileInformationClass). None mode: resolve the export dynamically
    /// (windows-rs does not declare it) and call it.
    pub fn nt_set_info_file(
        file: HANDLE,
        io_status: *mut core::ffi::c_void,
        info: *const core::ffi::c_void,
        length: u32,
        class: i32,
    ) -> i32 {
        let address = resolve_nt_export(&$SET_INFO_FILE_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let set_info: SetInfoFileFn = unsafe { std::mem::transmute(address) };
        unsafe { set_info(file, io_status, info, length, class) }
    }
"#;

/// `nt_set_info_thread`, mode none: the ntdll export resolved dynamically.
///
/// The Win32 wrapper (`SetThreadInformation`) rejects `ThreadHideFromDebugger`
/// with `ERROR_INVALID_PARAMETER` on Windows 11 26200 (measured: the same call
/// against `NtSetInformationThread` returns `STATUS_SUCCESS`), so the native
/// call is used verbatim in both modes.
pub(super) const SET_INFO_THREAD_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type SetInfoThreadFn = unsafe extern "system" fn(
        HANDLE,
        i32,
        *const core::ffi::c_void,
        u32,
    ) -> i32;

    /// NtSetInformationThread(ThreadHandle, ThreadInformationClass,
    /// ThreadInformation, ThreadInformationLength). None mode: resolve the
    /// export dynamically (the Win32 wrapper does not support every class) and
    /// call it.
    pub fn nt_set_info_thread(
        thread: HANDLE,
        class: i32,
        info: *const core::ffi::c_void,
        length: u32,
    ) -> i32 {
        let address = resolve_nt_export(&$SET_INFO_THREAD_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let set_info: SetInfoThreadFn = unsafe { std::mem::transmute(address) };
        unsafe { set_info(thread, class, info, length) }
    }
"#;

/// `nt_set_info_thread`, mode indirect.
pub(super) const SET_INFO_THREAD_INDIRECT: &str = r#"    /// NtSetInformationThread(ThreadHandle, ThreadInformationClass,
    /// ThreadInformation, ThreadInformationLength).
    pub fn nt_set_info_thread(
        thread: HANDLE,
        class: i32,
        info: *const core::ffi::c_void,
        length: u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                class as usize,
                info as usize,
                length as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.set_info_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_set_info_file`, mode indirect.
pub(super) const SET_INFO_FILE_INDIRECT: &str = r#"    /// NtSetInformationFile(FileHandle, &IoStatusBlock, FileInformation,
    /// Length, FileInformationClass).
    pub fn nt_set_info_file(
        file: HANDLE,
        io_status: *mut core::ffi::c_void,
        info: *const core::ffi::c_void,
        length: u32,
        class: i32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                file.0 as usize,
                io_status as usize,
                info as usize,
                length as usize,
                class as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.set_info_file,
                *gadget,
            )
        }
    }
"#;

/// `HANDLE` (full path) as spelled in a generated proxy parameter.
pub(super) const P_HANDLE: &str = "windows::Win32::Foundation::HANDLE";
/// `void*` as spelled in a generated proxy parameter.
pub(super) const P_PVOID: &str = "*mut core::ffi::c_void";
/// `const void*` as spelled in a generated proxy parameter.
pub(super) const P_CVOID: &str = "*const core::ffi::c_void";

/// `NtCreateThreadEx` with its native eleven-argument list, rendered only for a
/// generated direct proxy. The technique helper (`nt_create_thread_ex`) is a
/// five-argument convenience, so it cannot back the proxy itself.
pub(super) const CREATE_THREAD_EX_NATIVE_INDIRECT: &str = r#"    /// NtCreateThreadEx(&ThreadHandle, DesiredAccess, &ObjectAttributes,
    /// ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
    /// MaximumStackSize, &AttributeList). The native argument list, for the
    /// generated direct proxy.
    #[allow(clippy::too_many_arguments)]
    pub fn nt_create_thread_ex_native(
        thread: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const core::ffi::c_void,
        process: HANDLE,
        start: *mut core::ffi::c_void,
        argument: *mut core::ffi::c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *const core::ffi::c_void,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread as usize,
                desired_access as usize,
                object_attributes as usize,
                process.0 as usize,
                start as usize,
                argument as usize,
                create_flags as usize,
                zero_bits,
                stack_size,
                maximum_stack_size,
                attribute_list as usize,
                ssns.create_thread_ex,
                *gadget,
            )
        }
    }
"#;

/// `NtWaitForSingleObject` with its native argument list, rendered only for a
/// generated direct proxy. The technique helper takes milliseconds, so it
/// cannot back the proxy itself.
pub(super) const WAIT_FOR_SINGLE_OBJECT_NATIVE_INDIRECT: &str = r#"    /// NtWaitForSingleObject(Handle, Alertable, &Timeout). The native argument
    /// list, for the generated direct proxy.
    pub fn nt_wait_for_single_object_native(
        handle: HANDLE,
        alertable: u8,
        timeout: *const i64,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                handle.0 as usize,
                alertable as usize,
                timeout as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.wait_for_single_object,
                *gadget,
            )
        }
    }
"#;

/// Native-signature helpers that back a direct proxy for the few functions
/// whose technique helper is a lossy convenience wrapper: `(Nt* name, helper
/// name, indirect body)`. Rendered and re-exported only in `mode: indirect`,
/// where proxies exist.
pub(super) const NATIVE_PROXY_HELPERS: &[(&str, &str, &str)] = &[
    (
        "NtCreateThreadEx",
        "nt_create_thread_ex_native",
        CREATE_THREAD_EX_NATIVE_INDIRECT,
    ),
    (
        "NtWaitForSingleObject",
        "nt_wait_for_single_object_native",
        WAIT_FOR_SINGLE_OBJECT_NATIVE_INDIRECT,
    ),
];

/// The native proxy helper `(helper_name, body)` for a function, if any.
pub(super) fn native_proxy_helper(function: &str) -> Option<(&'static str, &'static str)> {
    NATIVE_PROXY_HELPERS
        .iter()
        .find(|(name, _, _)| *name == function)
        .map(|(_, helper, body)| (*helper, *body))
}
