use rcodex::update::{Installation, ReleaseManifest, UpdateSettings, parse_codex_version};
use sha2::{Digest, Sha256};
use std::fs;

fn manifest(binary: &[u8]) -> ReleaseManifest {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "version": "0.2.0",
        "codex_versions": ["0.153.0"],
        "assets": [{"name": "rcodex-0.2.0-aarch64-apple-darwin",
                    "target": "aarch64-apple-darwin",
                    "sha256": format!("{:x}", Sha256::digest(binary)),
                    "size": binary.len()}]
    }))
    .unwrap()
}

#[test]
fn only_new_stable_releases_matching_both_codex_versions_are_selected() {
    let release = manifest(b"new binary");
    assert!(
        release
            .select("0.1.0", "0.153.0", "0.153.0", "aarch64-apple-darwin")
            .unwrap()
            .is_some()
    );
    for (current, local, remote, target) in [
        ("0.2.0", "0.153.0", "0.153.0", "aarch64-apple-darwin"),
        ("0.3.0", "0.153.0", "0.153.0", "aarch64-apple-darwin"),
        ("0.1.0", "0.154.0", "0.153.0", "aarch64-apple-darwin"),
        ("0.1.0", "0.153.0", "unknown", "aarch64-apple-darwin"),
        ("0.1.0", "0.153.0", "0.153.0", "x86_64-apple-darwin"),
    ] {
        assert!(
            release
                .select(current, local, remote, target)
                .unwrap()
                .is_none()
        );
    }
    let mut invalid = release.clone();
    invalid.version = "0.3.0-beta.1".into();
    assert!(invalid.validate().is_err());
    invalid.version = "../../payload".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn malformed_or_ambiguous_manifests_are_rejected() {
    let release = manifest(b"new binary");
    let mut invalid = release.clone();
    invalid.schema_version = 2;
    assert!(invalid.validate().is_err());
    invalid = release.clone();
    invalid.assets[0].name = "../../rcodex".into();
    assert!(invalid.validate().is_err());
    invalid = release.clone();
    invalid.assets[0].sha256 = "bad".into();
    assert!(invalid.validate().is_err());
    invalid = release.clone();
    invalid.assets.push(invalid.assets[0].clone());
    assert!(invalid.validate().is_err());
    invalid = release.clone();
    invalid.assets[0].size = 0;
    assert!(invalid.validate().is_err());
    invalid = release;
    invalid.codex_versions.clear();
    assert!(invalid.validate().is_err());
}

#[test]
fn settings_are_opt_in_throttled_and_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("update.json");
    let mut settings = UpdateSettings::load(&path).unwrap();
    assert!(!settings.due(100_000));
    settings.enabled = true;
    assert!(settings.due(100_000));
    settings.last_checked = Some(100_000);
    assert!(!settings.due(100_001));
    assert!(!settings.due(99_999));
    assert!(settings.due(186_400));
    settings.save(&path).unwrap();
    assert_eq!(settings, UpdateSettings::load(&path).unwrap());
    fs::write(&path, "broken").unwrap();
    assert!(UpdateSettings::load(&path).is_err());
}

#[test]
fn codex_version_output_is_strict() {
    assert_eq!(
        parse_codex_version("codex-cli 0.153.0\n").unwrap(),
        "0.153.0"
    );
    for output in [
        "0.153.0",
        "codex-cli 0.153.0 extra",
        "codex-cli 0.154.0-beta.1",
    ] {
        assert!(parse_codex_version(output).is_err());
    }
}

#[test]
fn install_is_atomic_keeps_backup_and_rolls_back() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("rcodex");
    fs::write(&executable, "old binary").unwrap();
    let install = Installation::lock(&executable, true).unwrap();
    let release = manifest(b"new binary");
    install.replace(b"new binary", &release.assets[0]).unwrap();
    assert_eq!(fs::read(&executable).unwrap(), b"new binary");
    assert_eq!(fs::read(install.backup_path()).unwrap(), b"old binary");
    install.rollback().unwrap();
    assert_eq!(fs::read(&executable).unwrap(), b"old binary");
}

#[test]
fn tampered_download_never_changes_installation_or_backup() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("rcodex");
    fs::write(&executable, "old binary").unwrap();
    let install = Installation::lock(&executable, true).unwrap();
    let release = manifest(b"new binary");
    assert!(install.replace(b"bad binary", &release.assets[0]).is_err());
    assert_eq!(fs::read(&executable).unwrap(), b"old binary");
    assert!(!install.backup_path().exists());
    assert!(install.rollback().is_err());
}

#[test]
fn active_sessions_block_installation() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("rcodex");
    fs::write(&executable, "old binary").unwrap();
    let session = Installation::lock(&executable, false).unwrap();
    assert!(Installation::lock(&executable, true).is_err());
    assert!(
        session
            .replace(b"new binary", &manifest(b"new binary").assets[0])
            .is_err()
    );
    drop(session);
    assert!(Installation::lock(&executable, true).is_ok());
}

#[cfg(unix)]
#[test]
fn symlink_installations_and_backups_are_rejected() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("rcodex");
    let other = directory.path().join("other");
    fs::write(&other, "untouched").unwrap();
    symlink(&other, &executable).unwrap();
    assert!(Installation::lock(&executable, true).is_err());
    fs::remove_file(&executable).unwrap();
    fs::write(&executable, "old binary").unwrap();
    let install = Installation::lock(&executable, true).unwrap();
    symlink(&other, install.backup_path()).unwrap();
    assert!(
        install
            .replace(b"new binary", &manifest(b"new binary").assets[0])
            .is_err()
    );
    assert!(install.rollback().is_err());
    assert_eq!(fs::read(&other).unwrap(), b"untouched");
}
