#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcodex::auth::{
    RefreshResponse, build_refresh_request, load_codex_auth, merge_refresh_response,
};
use serde_json::{Value, json};

fn jwt(payload: Value) -> String {
    format!(
        "{}.{}.signature",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
    )
}

fn auth_document() -> Value {
    let access_token = jwt(json!({
        "exp": 2_000_000_000_i64,
        "https://api.openai.com/auth": {
            "chatgpt_account_id": "workspace-id",
            "chatgpt_account_user_id": "account-user-id",
            "user_id": "legacy-auth-user-id"
        }
    }));
    json!({
        "OPENAI_API_KEY": null,
        "auth_mode": "chatgpt",
        "last_refresh": "2026-08-31T12:00:00Z",
        "unrelated_future_field": {"preserve": true},
        "tokens": {
            "access_token": access_token,
            "account_id": "workspace-id",
            "id_token": "old-id-token",
            "refresh_token": "old-refresh-token"
        }
    })
}

fn write_auth(document: &Value) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.json");
    std::fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (directory, path)
}

#[test]
fn loads_chatgpt_auth_and_extracts_account_identity_without_exposing_tokens() {
    let (_directory, path) = write_auth(&auth_document());

    let auth = load_codex_auth(&path).unwrap();

    assert_eq!(auth.account_id(), "workspace-id");
    assert_eq!(auth.account_user_id(), "account-user-id");
    assert_eq!(auth.expires_at(), 2_000_000_000);
    assert!(auth.matches_relay_account_user_id("account-user-id"));
    assert!(auth.matches_relay_account_user_id("legacy-auth-user-id"));
    assert!(!auth.matches_relay_account_user_id("different-user-id"));
    assert!(!format!("{auth}").contains("old-refresh-token"));
}

#[test]
fn refresh_request_matches_the_codex_oauth_contract() {
    let (_directory, path) = write_auth(&auth_document());
    let auth = load_codex_auth(&path).unwrap();

    assert_eq!(
        build_refresh_request(&auth),
        json!({
            "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
            "grant_type": "refresh_token",
            "refresh_token": "old-refresh-token"
        })
    );
}

#[test]
fn refresh_rotation_preserves_unknown_auth_fields() {
    let fresh_access = jwt(json!({
        "exp": 2_100_000_000_i64,
        "https://api.openai.com/auth": {
            "chatgpt_account_id": "workspace-id",
            "chatgpt_account_user_id": "account-user-id"
        }
    }));
    let updated = merge_refresh_response(
        auth_document(),
        RefreshResponse {
            access_token: Some(fresh_access.clone()),
            id_token: Some("fresh-id-token".into()),
            refresh_token: Some("fresh-refresh-token".into()),
        },
        "2026-08-31T13:00:00Z",
    )
    .unwrap();

    assert_eq!(updated["unrelated_future_field"]["preserve"], true);
    assert_eq!(updated["tokens"]["access_token"], fresh_access);
    assert_eq!(updated["tokens"]["id_token"], "fresh-id-token");
    assert_eq!(updated["tokens"]["refresh_token"], "fresh-refresh-token");
    assert_eq!(updated["last_refresh"], "2026-08-31T13:00:00Z");
}

#[test]
#[cfg(unix)]
fn rejects_auth_files_readable_by_other_users() {
    let (_directory, path) = write_auth(&auth_document());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = load_codex_auth(&path).unwrap_err();

    assert!(error.to_string().contains("group or others"));
}
