// --- Sleep (control technique fragment) ---

/// Waits `$MS$` milliseconds. A Control technique never touches the payload.
pub fn run_sleep() -> Result<i32, String> {
    std::thread::sleep(std::time::Duration::from_millis($MS$));
    Ok(0)
}
