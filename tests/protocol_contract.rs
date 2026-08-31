use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcodex::protocol::{
    API_BASE, ConnectionChallenge, EnrollmentChallenge, EnrollmentRecord, OAuthAuthorizeParams,
    build_connection_signing_payload, build_enrollment_signing_payload, build_oauth_authorize_url,
    client_message_envelope, device_identity_hash,
};
use serde_json::json;
use sha2::{Digest, Sha256};

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
fn device_identity_hash_matches_the_desktop_field_order() {
    let record = enrollment();
    let identity_json = r#"{"algorithm":"ecdsa_p256_sha256","keyId":"rcodex_osn_key-id","protectionClass":"os_protected_nonextractable","publicKeySpkiDerBase64":"public-key"}"#;
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(identity_json.as_bytes()));

    assert_eq!(device_identity_hash(&record), expected);
}

#[test]
fn enrollment_payload_is_byte_compatible_with_the_desktop_app() {
    let record = enrollment();
    let challenge = EnrollmentChallenge {
        account_user_id: record.account_user_id.clone(),
        audience: "remote_control_client_enrollment".into(),
        challenge_expires_at: 2_000_000_000,
        challenge_id: "challenge-id".into(),
        challenge_token: "opaque-token".into(),
        client_id: record.client_id.clone(),
        device_identity_hash: None,
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        purpose: "remote_control_client_enrollment".into(),
        target_origin: "https://chatgpt.com".into(),
        target_path: "/backend-api/codex/remote/control/client/enroll/finish".into(),
    };
    let identity_hash = device_identity_hash(&record);
    let expected = r#"{"domain":"codex-device-key-sign-payload/v1","payload":{"accountUserId":"account-user","audience":"remote_control_client_enrollment","challengeExpiresAt":2000000000,"challengeId":"challenge-id","clientId":"client-id","deviceIdentitySha256Base64url":"__HASH__","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","targetOrigin":"https://chatgpt.com","targetPath":"/backend-api/codex/remote/control/client/enroll/finish","type":"remoteControlClientEnrollment"}}"#
        .replace("__HASH__", &identity_hash);

    let actual = build_enrollment_signing_payload(
        &record,
        &challenge,
        "/codex/remote/control/client/enroll/finish",
        false,
    )
    .unwrap();

    assert_eq!(actual, expected.as_bytes());
}

#[test]
fn refresh_requires_the_server_device_identity_hash() {
    let record = enrollment();
    let challenge = EnrollmentChallenge {
        account_user_id: record.account_user_id.clone(),
        audience: "remote_control_client_enrollment".into(),
        challenge_expires_at: 2_000_000_000,
        challenge_id: "challenge-id".into(),
        challenge_token: "opaque-token".into(),
        client_id: record.client_id.clone(),
        device_identity_hash: None,
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        purpose: "remote_control_client_enrollment".into(),
        target_origin: "https://chatgpt.com".into(),
        target_path: "/backend-api/codex/remote/control/client/refresh/finish".into(),
    };

    let error = build_enrollment_signing_payload(
        &record,
        &challenge,
        "/codex/remote/control/client/refresh/finish",
        true,
    )
    .unwrap_err();

    assert!(error.to_string().contains("device identity hash"));
}

#[test]
fn websocket_payload_is_byte_compatible_with_the_desktop_app() {
    let challenge = ConnectionChallenge {
        account_user_id: "account-user".into(),
        audience: "remote_control_client_websocket".into(),
        client_id: "client-id".into(),
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        purpose: "remote_control_client_websocket".into(),
        scopes: vec!["remote_control_controller_websocket".into()],
        session_id: "session-id".into(),
        target_origin: "https://chatgpt.com".into(),
        target_path: "/backend-api/codex/remote/control/client".into(),
        token_expires_at: 2_000_000_000,
        token_sha256_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    let expected = r#"{"domain":"codex-device-key-sign-payload/v1","payload":{"accountUserId":"account-user","audience":"remote_control_client_websocket","clientId":"client-id","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","scopes":["remote_control_controller_websocket"],"sessionId":"session-id","targetOrigin":"https://chatgpt.com","targetPath":"/backend-api/codex/remote/control/client","tokenExpiresAt":2000000000,"tokenSha256Base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","type":"remoteControlClientConnection"}}"#;

    let actual = build_connection_signing_payload(&challenge).unwrap();

    assert_eq!(actual, expected.as_bytes());
}

#[test]
fn oauth_url_uses_the_desktop_pkce_step_up_contract() {
    let url = build_oauth_authorize_url(&OAuthAuthorizeParams {
        account_id: Some("workspace-id".into()),
        code_challenge: "challenge".into(),
        originator: "codex_desktop".into(),
        redirect_uri: "http://localhost:1455/auth/callback".into(),
        state: "state".into(),
    })
    .unwrap();
    let pairs: BTreeMap<_, _> = url.query_pairs().into_owned().collect();

    assert_eq!(
        url.origin().ascii_serialization(),
        "https://auth.openai.com"
    );
    assert_eq!(url.path(), "/oauth/authorize");
    assert_eq!(
        pairs.get("client_id").unwrap(),
        "app_EMoamEEZ73f0CkXaXp7hrann"
    );
    assert_eq!(pairs.get("scope").unwrap(), "codex.remote_control.enroll");
    assert_eq!(pairs.get("reauth").unwrap(), "remote_control");
    assert_eq!(pairs.get("max_age").unwrap(), "0");
    assert_eq!(pairs.get("allowed_workspace_id").unwrap(), "workspace-id");
}

#[test]
fn client_envelope_matches_relay_protocol_v3() {
    let envelope = client_message_envelope(
        "client-id",
        "environment-id",
        "stream-id",
        1,
        json!({"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "rcodex", "version": "0.1.0"}}}),
    );

    assert_eq!(
        envelope,
        json!({
            "type": "client_message",
            "client_id": "client-id",
            "seq_id": 1,
            "stream_id": "stream-id",
            "env_id": "environment-id",
            "skip_history": false,
            "message": {"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "rcodex", "version": "0.1.0"}}}
        })
    );
    assert_eq!(API_BASE, "https://chatgpt.com/backend-api");
}
