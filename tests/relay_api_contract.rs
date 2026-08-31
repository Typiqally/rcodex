use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcodex::{
    api::{build_manual_pairing_body, client_revocation_path},
    protocol::{ConnectionChallenge, EnrollmentChallenge, EnrollmentRecord},
    relay::{
        DeviceKeyProof, EnrollmentStartResponse, RemoteControlSession, build_enroll_finish_body,
        build_refresh_finish_body, validate_and_build_connection_signing_payload,
        validate_remote_session,
    },
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn enrollment() -> EnrollmentRecord {
    EnrollmentRecord {
        account_user_id: "account-user".into(),
        algorithm: "ecdsa_p256_sha256".into(),
        client_id: "client-id".into(),
        key_id: "key-id".into(),
        protection_class: "os_protected_nonextractable".into(),
        public_key_spki_der_base64: "public-key".into(),
    }
}

#[test]
fn manual_pairing_body_matches_the_desktop_controller() {
    assert_eq!(
        build_manual_pairing_body("client-id", " abcd efgh ").unwrap(),
        json!({
            "client_id": "client-id",
            "manual_pairing_code": "ABCD-EFGH"
        })
    );
    assert!(build_manual_pairing_body("client-id", "ABC").is_err());
    assert!(build_manual_pairing_body("client-id", "ABCD-EFG!").is_err());
}

#[test]
fn client_revocation_path_encodes_the_exact_controller_id() {
    assert_eq!(
        client_revocation_path("cli/id with spaces").unwrap(),
        "/wham/remote/control/clients/cli%2Fid%20with%20spaces"
    );
    assert!(client_revocation_path(" ").is_err());
}

fn challenge(path: &str) -> EnrollmentChallenge {
    EnrollmentChallenge {
        account_user_id: "account-user".into(),
        audience: "remote_control_client_enrollment".into(),
        challenge_expires_at: 2_000_000_000,
        challenge_id: "challenge-id".into(),
        challenge_token: "opaque-challenge-token".into(),
        client_id: "client-id".into(),
        device_identity_hash: None,
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        purpose: "remote_control_client_enrollment".into(),
        target_origin: "https://chatgpt.com".into(),
        target_path: format!("/backend-api{path}"),
    }
}

fn proof() -> DeviceKeyProof {
    DeviceKeyProof {
        algorithm: "ecdsa_p256_sha256".into(),
        challenge_token: "opaque-challenge-token".into(),
        key_id: "key-id".into(),
        signature_der_base64: "signature".into(),
        signed_payload_base64: "payload".into(),
    }
}

#[test]
fn enrollment_start_response_uses_the_observed_wire_schema() {
    let response: EnrollmentStartResponse = serde_json::from_value(json!({
        "account_user_id": "account-user",
        "client_id": "client-id",
        "device_key_challenge": challenge("/codex/remote/control/client/enroll/finish")
    }))
    .unwrap();

    assert_eq!(response.account_user_id, "account-user");
    assert_eq!(response.client_id, "client-id");
    assert_eq!(response.device_key_challenge.challenge_id, "challenge-id");
}

#[test]
fn enrollment_finish_body_matches_the_desktop_client() {
    let body = build_enroll_finish_body(&enrollment(), "step-up-token", proof());

    assert_eq!(
        body,
        json!({
            "client_id": "client-id",
            "step_up_token": "step-up-token",
            "device_identity": {
                "key_id": "key-id",
                "public_key_spki_der_base64": "public-key",
                "algorithm": "ecdsa_p256_sha256",
                "protection_class": "os_protected_nonextractable"
            },
            "device_key_proof": {
                "challenge_token": "opaque-challenge-token",
                "key_id": "key-id",
                "signature_der_base64": "signature",
                "signed_payload_base64": "payload",
                "algorithm": "ecdsa_p256_sha256"
            }
        })
    );
}

#[test]
fn refresh_finish_body_does_not_repeat_device_identity() {
    assert_eq!(
        build_refresh_finish_body(&enrollment(), proof()),
        json!({
            "client_id": "client-id",
            "device_key_proof": {
                "challenge_token": "opaque-challenge-token",
                "key_id": "key-id",
                "signature_der_base64": "signature",
                "signed_payload_base64": "payload",
                "algorithm": "ecdsa_p256_sha256"
            }
        })
    );
}

#[test]
fn session_and_websocket_challenge_are_bound_to_token_and_enrollment() {
    let record = enrollment();
    let session = RemoteControlSession {
        account_user_id: record.account_user_id.clone(),
        client_id: record.client_id.clone(),
        expires_at: "2033-05-18T03:33:20Z".into(),
        remote_control_token: "relay-session-token".into(),
        scopes: vec!["remote_control_controller_websocket".into()],
    };
    validate_remote_session(&record, &session, 1_999_999_999).unwrap();
    let token_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(b"relay-session-token"));
    let challenge = ConnectionChallenge {
        account_user_id: record.account_user_id.clone(),
        audience: "remote_control_client_websocket".into(),
        client_id: record.client_id.clone(),
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        purpose: "remote_control_client_websocket".into(),
        scopes: vec!["remote_control_controller_websocket".into()],
        session_id: "session-id".into(),
        target_origin: "https://chatgpt.com".into(),
        target_path: "/backend-api/codex/remote/control/client".into(),
        token_expires_at: 2_000_000_000,
        token_sha256_base64url: token_hash,
    };

    validate_and_build_connection_signing_payload(&record, &session, &challenge, 1_999_999_999)
        .unwrap();

    let mut tampered = challenge;
    tampered.token_sha256_base64url = URL_SAFE_NO_PAD.encode(Sha256::digest(b"different-token"));
    assert!(
        validate_and_build_connection_signing_payload(&record, &session, &tampered, 1_999_999_999)
            .is_err()
    );
}
