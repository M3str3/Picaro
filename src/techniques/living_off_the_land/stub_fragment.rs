// --- Living off the land (control technique fragment) ---
    use windows::core::{PCSTR, PSTR};
    use windows::Win32::Foundation::{BOOL, CloseHandle};
    use windows::Win32::System::Threading::{
        CreateProcessA, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW, INFINITE,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOA,
    };

    /// Resolves a bare binary name against `System32` (a path is used as is).
    fn resolve_binary(name: &str) -> String {
        if name.contains('\\') || name.contains('/') {
            return name.to_string();
        }
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        format!("{root}\\System32\\{name}")
    }

    /// Quotes one argument for a Windows command line (the `CommandLineToArgvW`
    /// rules: backslash and quote handling).
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

    /// Launches the configured process and returns its exit code (0 when
    /// detached).
    pub fn run_exec() -> Result<i32, String> {
        let binary: String = $BINARY_DEF$;
        let args: Vec<String> = $ARGS_DEF$;
        let exe = resolve_binary(&binary);
        let mut command = quote_arg(&exe);
        for arg in &args {
            command.push(' ');
            command.push_str(&quote_arg(arg));
        }
        let mut app = exe.as_bytes().to_vec();
        app.push(0);
        let mut cmd = command.into_bytes();
        cmd.push(0);

        let mut startup: STARTUPINFOA = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        unsafe {
            CreateProcessA(
                PCSTR(app.as_ptr()),
                PSTR(cmd.as_mut_ptr()),
                None,
                None,
                BOOL(0),
                $FLAGS$,
                None,
                PCSTR::null(),
                &startup,
                &mut pi,
            )
            .map_err(|e| format!("could not launch the stage binary: {e}"))?;
        }

        let code = if $WAIT$ {
            let timeout = if $TIMEOUT_MS$ == 0u32 { INFINITE } else { $TIMEOUT_MS$ };
            let _ = unsafe { WaitForSingleObject(pi.hProcess, timeout) };
            let mut code = 0u32;
            let _ = unsafe { GetExitCodeProcess(pi.hProcess, &mut code) };
            code as i32
        } else {
            0
        };

        let _ = unsafe { CloseHandle(pi.hThread) };
        let _ = unsafe { CloseHandle(pi.hProcess) };
        Ok(code)
    }
