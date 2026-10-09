use rcodex::{
    api::RemoteEnvironment,
    compatibility::{
        SUPPORTED_CODEX_VERSION, verify_remote_codex_version, verify_stock_codex_version,
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
fn codex_0_153_is_the_supported_local_and_remote_version() {
    assert_eq!(SUPPORTED_CODEX_VERSION, "0.153.0");
    verify_stock_codex_version("codex-cli 0.153.0\n").unwrap();
    verify_remote_codex_version(&environment(Some("0.153.0"))).unwrap();
}

#[test]
fn stale_or_unreported_codex_versions_are_rejected() {
    let local_error = verify_stock_codex_version("codex-cli 0.152.0\n").unwrap_err();
    assert!(local_error.to_string().contains("codex-cli 0.153.0"));

    let remote_error = verify_remote_codex_version(&environment(Some("0.152.0"))).unwrap_err();
    assert!(remote_error.to_string().contains("pinned to 0.153.0"));

    let unknown_error = verify_remote_codex_version(&environment(None)).unwrap_err();
    assert!(unknown_error.to_string().contains("Codex unknown"));
}
