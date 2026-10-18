// --- Drop (technique fragment) ---

/// Writes the embedded asset to the configured path.
///
/// Runs unconditionally: the step always continues (`Ok(true)`). A failed write
/// is an error, not a policy decision, so it propagates and the runner takes the
/// step's `on_fail` action. The asset itself (`asset_bytes()`) and its
/// ciphertext constants are injected into this step's module by the engine.
pub fn drop() -> Result<bool, String> {
    let path: String = $DROP_PATH_DEF$;
    let path = crate::expand_env(&path);
    let bytes = asset_bytes()?;
    std::fs::write(&path, &bytes).map_err(|_| $MSG_DROP_WRITE_FAILED$)?;
    crate::tech_dbg!("drop", "file written");
    Ok(true)
}
