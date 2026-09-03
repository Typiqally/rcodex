use rcodex::{
    api::RemoteEnvironment,
    compatibility::{
        parse_stock_codex_version, verify_remote_codex_version, verify_stock_codex_capabilities,
    },
};

fn environment(version: Option<&str>) -> RemoteEnvironment {
    RemoteEnvironment {
        app_server_version: version.map(str::to_owned),
        arch: Some("x86_64".into()),
        busy: false,
        client_type: Some("cli".into()),
        display_name: Some("example-codex-host".into()),
        env_id: "env-id".into(),
        host_name: Some("example-host".into()),
        installation_id: None,
        kind: Some("computer".into()),
        last_seen_at: None,
        name: None,
        online: true,
        os: Some("linux".into()),
    }
}

#[test]
fn stock_codex_version_is_detected_without_a_fixed_allowlist() {
    for (output, expected) in [
        ("codex-cli 0.152.0\n", "0.152.0"),
        ("codex-cli 99.4.0\n", "99.4.0"),
        (
            "codex-cli 0.154.0-alpha.1 (development build)\n",
            "0.154.0-alpha.1",
        ),
    ] {
        assert_eq!(parse_stock_codex_version(output).unwrap(), expected);
    }
}

#[test]
fn malformed_stock_codex_versions_are_rejected() {
    for output in [
        "",
        "codex-cli",
        "codex 0.153.0",
        "codex-cli latest",
        "codex-cli 0.153.0\nextra",
    ] {
        assert!(parse_stock_codex_version(output).is_err(), "{output:?}");
    }
}

#[test]
fn stock_codex_must_expose_both_remote_terminal_options() {
    let supported = "--remote <ADDR>\n--remote-auth-token-env <ENV_VAR>\n";
    verify_stock_codex_capabilities(supported).unwrap();

    for unsupported in [
        "--remote-auth-token-env <ENV_VAR>\n",
        "--remote <ADDR>\n",
        "--remotely <ADDR>\n--remote-auth-token-environment <ENV_VAR>\n",
    ] {
        let error = verify_stock_codex_capabilities(unsupported).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("required remote terminal options")
        );
    }
}

#[test]
fn matching_local_and_remote_versions_are_accepted() {
    for version in ["0.152.0", "99.4.0", "0.154.0-alpha.1"] {
        verify_remote_codex_version(version, &environment(Some(version))).unwrap();
    }
}

#[test]
fn mismatched_or_unreported_remote_versions_are_rejected() {
    let mismatch = verify_remote_codex_version("0.154.0", &environment(Some("0.153.0")))
        .unwrap_err()
        .to_string();
    assert!(mismatch.contains("example-codex-host"));
    assert!(mismatch.contains("local Codex CLI 0.154.0"));
    assert!(mismatch.contains("remote Codex App Server 0.153.0"));
    assert!(mismatch.contains("both versions match"));

    let unknown = verify_remote_codex_version("0.154.0", &environment(None))
        .unwrap_err()
        .to_string();
    assert!(unknown.contains("does not report a Codex App Server version"));

    let malformed = verify_remote_codex_version("0.154.0", &environment(Some("latest")))
        .unwrap_err()
        .to_string();
    assert!(malformed.contains("invalid Codex App Server version"));
}
