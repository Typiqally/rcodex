use rcodex::update::UpdateSettings;
use std::{fs, process::Command};

#[cfg(unix)]
#[test]
fn update_settings_and_rollback_commands_work_without_codex_authentication() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("rcodex");
    fs::copy(env!("CARGO_BIN_EXE_rcodex"), &executable).unwrap();
    let verifier = directory.path().join("gh");
    fs::write(&verifier, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&verifier, fs::Permissions::from_mode(0o700)).unwrap();
    let state = directory.path().join("state");
    let execute = |action| {
        Command::new(&executable)
            .args(["update", action])
            .env("HOME", directory.path())
            .env("RCODEX_HOME", &state)
            .env("CODEX_HOME", directory.path().join("no-auth"))
            .env("PATH", directory.path())
            .output()
            .unwrap()
    };
    let enabled = execute("enable");
    assert_eq!(enabled.status.success(), cfg!(target_os = "macos"));
    assert_eq!(
        UpdateSettings::load(&state.join("update.json"))
            .unwrap()
            .enabled,
        cfg!(target_os = "macos")
    );
    assert!(execute("disable").status.success());
    assert!(
        !UpdateSettings::load(&state.join("update.json"))
            .unwrap()
            .enabled
    );
    assert!(!execute("rollback").status.success());
    if cfg!(target_os = "macos") {
        assert!(execute("enable").status.success());
    }
    let backup = executable.with_extension("previous");
    fs::write(&backup, b"previous executable").unwrap();
    assert!(execute("rollback").status.success());
    assert_eq!(fs::read(&executable).unwrap(), b"previous executable");
    assert!(
        !UpdateSettings::load(&state.join("update.json"))
            .unwrap()
            .enabled
    );
    assert!(!directory.path().join("no-auth").exists());
}

#[cfg(unix)]
#[test]
fn unsupported_verifier_cannot_enable_automatic_updates() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("rcodex");
    fs::copy(env!("CARGO_BIN_EXE_rcodex"), &executable).unwrap();
    fs::write(directory.path().join("gh"), "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(
        directory.path().join("gh"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let output = Command::new(&executable)
        .args(["update", "enable"])
        .env("HOME", directory.path())
        .env("RCODEX_HOME", directory.path().join("state"))
        .env("PATH", directory.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        !UpdateSettings::load(&directory.path().join("state/update.json"))
            .unwrap()
            .enabled
    );
}
