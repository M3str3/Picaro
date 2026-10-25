use super::*;

fn yaml(s: &str) -> YamlApiResolutionPlan {
    serde_yml::from_str(s).expect("valid YAML")
}

#[test]
fn absent_block_defaults_to_none_and_is_a_noop() {
    let config = ApiResolutionConfig::from_yaml(None).expect("defaults");
    assert_eq!(config.mode, ApiResolutionMode::None);
    assert_eq!(config.unmatched, Unmatched::Forward);
    assert!(config.apis.is_empty());
    assert!(config.is_noop());
}

#[test]
fn yaml_defaults_are_none_and_forward() {
    let config = ApiResolutionConfig::from_yaml(Some(&yaml("{}"))).expect("defaults");
    assert_eq!(config.mode, ApiResolutionMode::None);
    assert_eq!(config.unmatched, Unmatched::Forward);
}

#[test]
fn parses_proxy_with_catalogue_apis() {
    let y = yaml(
            "mode: proxy\napis:\n  - \"kernel32!ReadProcessMemory\"\n  - \"ntdll!NtOpenProcess\"\nunmatched: abort\n",
        );
    let config = ApiResolutionConfig::from_yaml(Some(&y)).expect("valid");
    assert_eq!(config.mode, ApiResolutionMode::Proxy);
    assert_eq!(config.unmatched, Unmatched::Abort);
    assert_eq!(config.apis.len(), 2);
    assert_eq!(config.apis[0].func, "ReadProcessMemory");
    assert_eq!(config.apis[1].func, "NtOpenProcess");
    assert!(!config.is_noop());
}

#[test]
fn apis_all_selects_the_catalogue_and_every_direct_nt_route() {
    // Bare scalar form.
    let config =
        ApiResolutionConfig::from_yaml(Some(&yaml("mode: proxy\napis: all\n"))).expect("valid");
    for entry in CATALOGUE {
        assert!(
            config.apis.iter().any(|e| e == entry),
            "missing {}",
            entry.selector()
        );
    }
    for name in crate::engine::syscalls::nt_proxy_names() {
        assert!(
            config
                .apis
                .iter()
                .any(|e| e.dll == "ntdll" && e.func == name),
            "missing ntdll!{name}"
        );
    }
    // Deduplicated: the two Nt* the catalogue already lists appear once.
    let mut expected: Vec<String> = CATALOGUE.iter().map(ApiEntry::selector).collect();
    for name in crate::engine::syscalls::nt_proxy_names() {
        let selector = format!("ntdll!{name}");
        if !expected.contains(&selector) {
            expected.push(selector);
        }
    }
    assert_eq!(config.apis.len(), expected.len());
    assert!(!config.is_noop());

    // List form is equivalent.
    let config = ApiResolutionConfig::from_yaml(Some(&yaml("mode: proxy\napis:\n  - all\n")))
        .expect("valid");
    assert_eq!(config.apis.len(), expected.len());
}

/// `ntdll:*` selects every direct `Nt*` route the syscall layer can serve,
/// and only those (the helper-backed ones).
#[test]
fn ntdll_wildcard_selects_every_direct_route() {
    let direct = crate::engine::syscalls::nt_proxy_names();
    let config = ApiResolutionConfig::from_yaml(Some(&yaml("mode: proxy\napis: \"ntdll:*\"\n")))
        .expect("valid");
    assert_eq!(config.apis.len(), direct.len());
    assert!(config
        .apis
        .iter()
        .all(|e| e.dll == "ntdll" && e.strategy == Strategy::RouteToNt));
    assert!(config.apis.iter().any(|e| e.func == "NtClose"));
    // Every syscall-layer function is offered now, the convenience-backed
    // ones included.
    assert!(config.apis.iter().any(|e| e.func == "NtCreateThreadEx"));
    assert!(config
        .apis
        .iter()
        .any(|e| e.func == "NtWaitForSingleObject"));
    // Every selected route pulls its syscall helper.
    assert_eq!(config.required_syscalls().len(), direct.len());
}

/// A direct `ntdll!Nt*` route renders a generated `extern "system"` proxy
/// that forwards to the syscall-layer helper.
#[test]
fn a_direct_nt_route_renders_a_generated_proxy() {
    let config = proxy_config(&["ntdll!NtClose"]);
    let block = render_block(&config, &xor_strings());
    assert!(block.contains("extern \"system\" fn proxy_0"), "{block}");
    assert!(block.contains("crate::nt_close(handle)"), "{block}");
    // Proxies must never trace: they run on payload threads too, where the
    // stub's thread-locals are not provisioned (a debug `eprintln!` there
    // reads garbage through the stub's TLS index and faults).
    assert!(!block.contains("tech_dbg"), "proxy traces: {block}");
    assert!(!block.contains('$'), "leftover placeholder: {block}");
}

#[test]
fn api_accepts_a_bare_scalar_selector() {
    let config = ApiResolutionConfig::from_yaml(Some(&yaml(
        "mode: proxy\napis: \"kernel32!OpenProcess\"\n",
    )))
    .expect("valid");
    assert_eq!(config.apis.len(), 1);
    assert_eq!(config.apis[0].func, "OpenProcess");
}

#[test]
fn module_name_is_normalized() {
    let y = yaml(
            "mode: proxy\napis:\n  - \"KERNEL32.DLL!ReadProcessMemory\"\n  - \"C:/Windows/System32/ntdll!NtReadVirtualMemory\"\n",
        );
    let config = ApiResolutionConfig::from_yaml(Some(&y)).expect("valid");
    assert_eq!(config.apis.len(), 2);
    assert_eq!(config.apis[0].func, "ReadProcessMemory");
    assert_eq!(config.apis[1].func, "NtReadVirtualMemory");
}

#[test]
fn repeated_apis_are_deduplicated() {
    let y = yaml(
            "mode: proxy\napis:\n  - \"kernel32!ReadProcessMemory\"\n  - \"KERNEL32!ReadProcessMemory\"\n",
        );
    let config = ApiResolutionConfig::from_yaml(Some(&y)).expect("valid");
    assert_eq!(config.apis.len(), 1);
}

#[test]
fn a_proxy_with_no_apis_is_a_noop() {
    let y = yaml("mode: proxy\n");
    let config = ApiResolutionConfig::from_yaml(Some(&y)).expect("valid");
    assert!(config.is_noop());
}

#[test]
fn rejects_an_unknown_mode() {
    let y = yaml("mode: intercept\n");
    let err = ApiResolutionConfig::from_yaml(Some(&y)).expect_err("unknown mode");
    assert!(
        err.to_string().contains("api_resolution.mode"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_an_unknown_unmatched() {
    let y = yaml("mode: proxy\nunmatched: deny\n");
    let err = ApiResolutionConfig::from_yaml(Some(&y)).expect_err("unknown unmatched");
    assert!(
        err.to_string().contains("api_resolution.unmatched"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_an_api_outside_the_catalogue() {
    let y = yaml("mode: proxy\napis:\n  - \"kernel32!Nope\"\n");
    let err = ApiResolutionConfig::from_yaml(Some(&y)).expect_err("unknown api");
    assert!(
        err.to_string().contains("api_resolution.apis"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_a_selector_without_a_module() {
    let y = yaml("mode: proxy\napis:\n  - \"ReadProcessMemory\"\n");
    let err = ApiResolutionConfig::from_yaml(Some(&y)).expect_err("malformed selector");
    assert!(
        err.to_string().contains("api_resolution.apis"),
        "unclear error: {err}"
    );
}

#[test]
fn selectors_are_unique_and_well_formed() {
    let mut seen = std::collections::BTreeSet::new();
    for entry in CATALOGUE {
        assert!(!entry.dll.is_empty());
        assert!(!entry.func.is_empty());
        assert_eq!(
            entry.dll,
            normalize_module(entry.dll),
            "catalogue dll must be pre-normalized"
        );
        assert!(seen.insert(entry.selector()), "duplicate selector");
        if entry.strategy == Strategy::RouteToNt {
            assert!(
                entry.nt.is_some(),
                "{} needs an Nt* target",
                entry.selector()
            );
        }
    }
}

fn xor_strings() -> StringsConfig {
    StringsConfig {
        strategy: crate::engine::obfuscation::StringStrategy::Xor,
        key: Some([0x5Au8; 32]),
    }
}

fn proxy_config(apis: &[&str]) -> ApiResolutionConfig {
    let list: String = apis.iter().map(|a| format!("  - \"{a}\"\n")).collect();
    let y = yaml(&format!("mode: proxy\napis:\n{list}"));
    ApiResolutionConfig::from_yaml(Some(&y)).expect("valid")
}

fn proxy_config_with_unmatched(apis: &[&str], unmatched: &str) -> ApiResolutionConfig {
    let list: String = apis.iter().map(|a| format!("  - \"{a}\"\n")).collect();
    let y = yaml(&format!(
        "mode: proxy\napis:\n{list}unmatched: {unmatched}\n"
    ));
    ApiResolutionConfig::from_yaml(Some(&y)).expect("valid")
}

/// The generated code with comment lines removed (comments may name APIs).
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn noop_block_when_nothing_is_proxied() {
    let block = render_block(&ApiResolutionConfig::default(), &xor_strings());
    assert!(block.contains("pub fn resolution_policy"));
    assert!(block.contains("crate::ImportPolicy::Forward"));
    assert!(!block.contains("proxy_0"));
}

#[test]
fn renders_proxies_and_policy_without_cleartext_names() {
    let config = proxy_config(&["kernel32!ReadProcessMemory", "ntdll!NtReadVirtualMemory"]);
    let block = render_block(&config, &xor_strings());
    assert!(block.contains("proxy_0"));
    assert!(block.contains("proxy_1"));
    assert!(block.contains("fn resolution_policy"));
    assert!(block.contains("crate::ImportPolicy::Proxy("));
    assert!(block.contains("normalize_module"));
    assert!(block.contains("crate::nt_read_vm"));
    assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
    let code = code_only(&block);
    assert!(!code.contains("ReadProcessMemory"), "cleartext name leaked");
    assert!(
        !code.contains("NtReadVirtualMemory"),
        "cleartext name leaked"
    );
}

#[test]
fn forward_strategy_renders_a_runtime_resolver() {
    // No shipped catalogue entry uses `forward` any more (OpenProcess is a
    // rebuild, GetProcAddress is the handler); the strategy stays available
    // for future "thick" APIs, so it is exercised directly.
    let entry = ApiEntry {
        dll: "kernel32",
        func: "SomeThickApi",
        strategy: Strategy::Forward,
        nt: None,
    };
    let body = forward_proxy(0, &entry, &xor_strings(), "a: u32", "u32", "u32", "a");
    assert!(body.contains("original_0"));
    assert!(body.contains("GetModuleHandleA"));
    assert!(body.contains("OnceLock"));
    let code = code_only(&body);
    assert!(!code.contains("SomeThickApi"), "cleartext name leaked");
}

#[test]
fn handler_entry_renders_the_module_lookup() {
    let config = proxy_config(&["kernel32!GetProcAddress"]);
    let block = render_block(&config, &xor_strings());
    assert!(block.contains("GetModuleFileNameA"));
    assert!(block.contains("resolution_policy(&path, func)"));
    assert!(block.contains("crate::ImportPolicy::Proxy("));
    assert!(block.contains("original_0"));
    assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
}

/// `unmatched` picks the policy's miss arm: `forward` resolves normally,
/// `abort` returns `ImportPolicy::Abort` so the load fails (finding 1).
#[test]
fn unmatched_selects_the_miss_decision() {
    let forward = proxy_config(&["kernel32!ReadProcessMemory"]);
    let block = render_block(&forward, &xor_strings());
    assert!(
        block.contains("crate::ImportPolicy::Forward") && !block.contains("ImportPolicy::Abort"),
        "forward should be the miss arm: {block}"
    );

    let abort = proxy_config_with_unmatched(&["kernel32!ReadProcessMemory"], "abort");
    let block = render_block(&abort, &xor_strings());
    assert!(
        block.contains("crate::ImportPolicy::Abort") && !block.contains("ImportPolicy::Forward"),
        "abort should be the miss arm: {block}"
    );
    assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
}

#[test]
fn rebuild_entry_defines_the_native_structures() {
    let config = proxy_config(&["kernel32!OpenProcess"]);
    let block = render_block(&config, &xor_strings());
    assert!(block.contains("struct ObjectAttributes"));
    assert!(block.contains("struct ClientId"));
    assert!(block.contains("OBJ_INHERIT"));
    assert!(block.contains("crate::nt_open_process"));
}

/// The process-memory wrappers rebuild the Win32 signatures on the native
/// helpers and declare the syscall each one ends up calling.
#[test]
fn memory_and_handle_wrappers_route_to_the_native_helpers() {
    let config = proxy_config(&[
        "kernel32!VirtualAlloc",
        "kernel32!VirtualProtect",
        "kernel32!VirtualFree",
        "kernel32!CloseHandle",
        "kernel32!WaitForSingleObject",
    ]);
    assert_eq!(
        config.required_syscalls(),
        vec![
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtFreeVirtualMemory",
            "NtClose",
            "NtWaitForSingleObject"
        ]
    );

    let block = render_block(&config, &xor_strings());
    for helper in [
        "crate::nt_alloc_vm",
        "crate::nt_protect_vm",
        "crate::nt_free_vm",
        "crate::nt_close",
        "crate::nt_wait_for_single_object_native",
    ] {
        assert!(block.contains(helper), "missing {helper}: {block}");
    }
    assert!(block.contains("current_process()"));
    assert!(block.contains("set_last_error("));
    assert!(!block.contains('$'), "leftover placeholder: {block}");

    let code = code_only(&block);
    for name in [
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualFree",
        "CloseHandle",
        "WaitForSingleObject",
    ] {
        assert!(!code.contains(name), "cleartext name leaked: {name}");
    }
}

/// `NtFreeVirtualMemory` is also selectable as a direct `ntdll!` route.
#[test]
fn ntdll_free_route_renders_a_direct_proxy() {
    let config = proxy_config(&["ntdll!NtFreeVirtualMemory"]);
    assert_eq!(config.required_syscalls(), vec!["NtFreeVirtualMemory"]);
    let block = render_block(&config, &xor_strings());
    assert!(block.contains("extern \"system\" fn proxy_0"), "{block}");
    assert!(block.contains("crate::nt_free_vm"), "{block}");
    assert!(!block.contains('$'), "leftover placeholder: {block}");
}

/// The batch-2 wrappers: a query, a thread create (which also needs
/// `ThreadBasicInformation`) and a token open.
#[test]
fn query_thread_and_token_wrappers_route_to_the_native_helpers() {
    let config = proxy_config(&[
        "kernel32!VirtualQuery",
        "kernel32!CreateThread",
        "advapi32!OpenThreadToken",
    ]);
    assert_eq!(
        config.required_syscalls(),
        vec![
            "NtQueryVirtualMemory",
            "NtCreateThreadEx",
            "NtQueryInformationThread",
            "NtOpenThreadToken"
        ]
    );

    let block = render_block(&config, &xor_strings());
    for helper in [
        "crate::nt_query_vm",
        "crate::nt_create_thread_ex_native",
        "crate::nt_query_info_thread",
        "crate::nt_open_thread_token",
    ] {
        assert!(block.contains(helper), "missing {helper}: {block}");
    }
    assert!(block.contains("ThreadBasicInformation"), "{block}");
    assert!(!block.contains('$'), "leftover placeholder: {block}");
    let code = code_only(&block);
    for name in ["VirtualQuery", "CreateThread", "OpenThreadToken"] {
        assert!(!code.contains(name), "cleartext name leaked: {name}");
    }
}

fn parse_api_resolution(yaml: &str) -> Result<ApiResolutionConfig> {
    let yaml: YamlApiResolutionPlan = serde_yml::from_str(yaml).expect("valid YAML");
    ApiResolutionConfig::from_yaml(Some(&yaml))
}

#[test]
fn parses_the_sleep_hook_with_defaults() {
    let config =
        parse_api_resolution("mode: proxy\nhooks:\n  sleep:\n    assume_single_threaded: true\n")
            .expect("valid hook");
    let sleep = config.hooks.sleep.expect("the hook should be present");
    assert_eq!(sleep.min_ms, 1000);
    assert_eq!(sleep.max_ms, 600_000);
    assert!(!config.is_noop(), "a hook alone still installs a proxy");
}

#[test]
fn parses_explicit_hook_values() {
    let config = parse_api_resolution(
            "mode: proxy\nhooks:\n  sleep:\n    min_ms: 2000\n    max_ms: 120000\n    assume_single_threaded: true\n",
        )
        .expect("valid hook");
    let sleep = config.hooks.sleep.expect("the hook should be present");
    assert_eq!(sleep.min_ms, 2000);
    assert_eq!(sleep.max_ms, 120_000);
}

#[test]
fn hook_requires_the_single_thread_acknowledgement() {
    let err = parse_api_resolution("mode: proxy\nhooks:\n  sleep: {}\n")
        .expect_err("the hook must require the acknowledgement");
    assert!(err.to_string().contains("assume_single_threaded"));
}

#[test]
fn hook_requires_proxy_mode() {
    let err =
        parse_api_resolution("mode: none\nhooks:\n  sleep:\n    assume_single_threaded: true\n")
            .expect_err("a hook without proxy mode must fail");
    assert!(err.to_string().contains("mode: proxy"));
}

#[test]
fn hook_rejects_an_unimplemented_variant() {
    let err = parse_api_resolution(
        "mode: proxy\nhooks:\n  sleep:\n    obfuscate: foliage\n    assume_single_threaded: true\n",
    )
    .expect_err("a non-ekko variant must fail");
    assert!(err.to_string().contains("foliage"));
}

#[test]
fn hook_rejects_an_inverted_window() {
    let err = parse_api_resolution(
            "mode: proxy\nhooks:\n  sleep:\n    min_ms: 5000\n    max_ms: 1000\n    assume_single_threaded: true\n",
        )
        .expect_err("min_ms > max_ms must fail");
    assert!(err.to_string().contains("greater than"));
}

/// With only a hook, the block still declares `NtDelayExecution`, proxies
/// `Sleep` by function name (API-set imports name a virtual module) and
/// never traces on the payload thread.
#[test]
fn a_hook_alone_renders_a_complete_proxy() {
    let config =
        parse_api_resolution("mode: proxy\nhooks:\n  sleep:\n    assume_single_threaded: true\n")
            .expect("valid hook");
    assert_eq!(config.required_syscalls(), vec!["NtDelayExecution"]);

    let block = render_block(&config, &xor_strings());
    assert!(
        block.contains("crate::sleep_runtime::ekko_sleep"),
        "{block}"
    );
    assert!(block.contains("crate::payload_region::get()"), "{block}");
    assert!(block.contains("crate::nt_delay_execution"), "{block}");
    assert!(block.contains("CONCEALING"), "{block}");
    assert!(block.contains("const MIN_MS: u32 = 1000;"), "{block}");
    assert!(block.contains("const MAX_MS: u32 = 600000;"), "{block}");
    assert!(
        !block.contains("want_module"),
        "the hook matches by function name only: {block}"
    );
    assert!(!block.contains('$'), "leftover placeholder: {block}");
    let code = code_only(&block);
    assert!(!code.contains("tech_dbg"), "the proxy traces: {code}");
    assert!(!code.contains("Sleep"), "the API name leaked: {code}");
}

#[test]
fn every_catalogue_entry_has_a_proxy_body() {
    for entry in CATALOGUE {
        let body = proxy_body(0, entry, &xor_strings());
        assert!(
            code_only(&body).contains("proxy_0"),
            "no proxy body for {}",
            entry.selector()
        );
    }
}

#[test]
fn required_syscalls_lists_the_route_targets() {
    let config = proxy_config(&[
        "kernel32!ReadProcessMemory",
        "ntdll!NtReadVirtualMemory",
        "kernel32!OpenProcess",
    ]);
    assert_eq!(
        config.required_syscalls(),
        vec!["NtReadVirtualMemory", "NtOpenProcess"]
    );
}

#[test]
fn injection_entries_route_to_the_existing_syscalls() {
    let config = proxy_config(&[
        "kernel32!VirtualAllocEx",
        "kernel32!WriteProcessMemory",
        "kernel32!CreateRemoteThread",
        "kernel32!QueueUserAPC",
    ]);
    assert_eq!(
        config.required_syscalls(),
        vec![
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtCreateThreadEx",
            "NtQueueApcThread"
        ]
    );

    let block = render_block(&config, &xor_strings());
    assert!(block.contains("crate::nt_alloc_vm"), "{block}");
    assert!(block.contains("crate::nt_write_vm"), "{block}");
    assert!(
        block.contains("crate::nt_create_thread_ex_native"),
        "{block}"
    );
    assert!(block.contains("crate::nt_queue_apc"), "{block}");
    assert!(!block.contains('$'), "leftover placeholder: {block}");
}

#[test]
fn token_entries_route_to_the_new_syscalls() {
    let config = proxy_config(&[
        "advapi32!OpenProcessToken",
        "advapi32!DuplicateTokenEx",
        "advapi32!ImpersonateLoggedOnUser",
    ]);
    assert_eq!(
        config.required_syscalls(),
        vec![
            "NtOpenProcessToken",
            "NtDuplicateToken",
            "NtSetInformationThread"
        ]
    );

    let block = render_block(&config, &xor_strings());
    assert!(block.contains("crate::nt_open_process_token"), "{block}");
    assert!(block.contains("crate::nt_duplicate_token"), "{block}");
    assert!(block.contains("crate::nt_set_info_thread"), "{block}");
    assert!(!block.contains('$'), "leftover placeholder: {block}");
}

#[test]
fn open_process_token_rebuild_calls_the_three_argument_native() {
    let config = proxy_config(&["advapi32!OpenProcessToken"]);
    let block = render_block(&config, &xor_strings());
    assert!(
        block.contains("crate::nt_open_process_token(process, desired_access, token)"),
        "{block}"
    );
}

#[test]
fn duplicate_token_ex_does_not_pass_the_level_as_effective_only() {
    let config = proxy_config(&["advapi32!DuplicateTokenEx"]);
    let block = render_block(&config, &xor_strings());
    assert!(block.contains("_impersonation_level: i32"), "{block}");
    assert!(
        block.contains("core::ptr::null(),\n            0,\n            token_type,"),
        "{block}"
    );
}

#[test]
fn injection_and_token_names_stay_out_of_the_code() {
    let config = proxy_config(&[
        "kernel32!VirtualAllocEx",
        "kernel32!CreateRemoteThread",
        "advapi32!DuplicateTokenEx",
    ]);
    let block = render_block(&config, &xor_strings());
    let code = code_only(&block);
    for name in ["VirtualAllocEx", "CreateRemoteThread", "DuplicateTokenEx"] {
        assert!(!code.contains(name), "cleartext name leaked: {name}");
    }
}
