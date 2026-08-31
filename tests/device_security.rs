#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use rcodex::{
    device_key::p256_x963_to_spki_der,
    protocol::EnrollmentRecord,
    state::{
        ControllerState, delete_controller_state, load_controller_state, save_controller_state,
    },
};

#[cfg(target_os = "macos")]
use rcodex::device_key::{
    create_os_protected_device_key, delete_os_protected_device_key,
    sign_with_os_protected_device_key,
};

fn enrollment() -> EnrollmentRecord {
    EnrollmentRecord {
        account_user_id: "account-user".into(),
        algorithm: "ecdsa_p256_sha256".into(),
        client_id: "client-id".into(),
        key_id: "rcodex_osn_key-id".into(),
        protection_class: "os_protected_nonextractable".into(),
        public_key_spki_der_base64: "public-key".into(),
    }
}

#[test]
fn wraps_an_uncompressed_p256_point_as_spki_der() {
    let mut point = vec![0x04];
    point.extend(1_u8..=64);

    let spki = p256_x963_to_spki_der(&point).unwrap();

    assert_eq!(spki.len(), 91);
    assert_eq!(
        &spki[..26],
        &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ]
    );
    assert_eq!(&spki[26..], point);
}

#[test]
fn rejects_non_p256_public_key_material() {
    assert!(p256_x963_to_spki_der(&[0x04; 64]).is_err());
    assert!(p256_x963_to_spki_der(&[0x03; 65]).is_err());
}

#[test]
fn controller_state_round_trips_without_secrets_and_is_owner_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested/state.json");
    let state = ControllerState {
        enrollment: enrollment(),
    };

    save_controller_state(&path, &state).unwrap();
    let loaded = load_controller_state(&path).unwrap();
    let serialized = std::fs::read_to_string(&path).unwrap();

    assert_eq!(loaded, state);
    assert!(!serialized.to_ascii_lowercase().contains("token"));
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn controller_state_deletion_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested/state.json");
    let state = ControllerState {
        enrollment: enrollment(),
    };
    save_controller_state(&path, &state).unwrap();

    delete_controller_state(&path).unwrap();
    assert!(!path.exists());
    delete_controller_state(&path).unwrap();
}

#[test]
#[cfg(target_os = "macos")]
#[ignore = "touches the login Keychain; run explicitly with --ignored"]
fn macos_keychain_key_can_sign_but_is_not_exported() {
    let key = create_os_protected_device_key().unwrap();
    let signature = sign_with_os_protected_device_key(&key.key_id, b"rcodex-test-payload");
    let deletion = delete_os_protected_device_key(&key.key_id);

    let signature = signature.unwrap();
    assert_eq!(key.algorithm, "ecdsa_p256_sha256");
    assert_eq!(key.protection_class, "os_protected_nonextractable");
    assert_eq!(signature.first(), Some(&0x30));
    assert!(signature.len() > 64);
    deletion.unwrap();
}
