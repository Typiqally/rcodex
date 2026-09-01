use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcodex::{
    api::{EnvironmentList, parse_retry_after},
    oauth::validate_step_up_token,
};
use serde_json::{Value, json};

fn jwt(payload: Value) -> String {
    format!(
        "{}.{}.signature",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
    )
}

#[test]
fn validates_fresh_account_bound_step_up_token() {
    let token = jwt(json!({
        "iat": 1_000,
        "pwd_auth_time": 1_050_000,
        "scope": "codex.remote_control.enroll",
        "https://api.openai.com/auth": {
            "chatgpt_account_user_id": "account-user"
        }
    }));

    validate_step_up_token(&token, "account-user", 1_100).unwrap();
    assert!(validate_step_up_token(&token, "different-user", 1_100).is_err());
    assert!(validate_step_up_token(&token, "account-user", 1_400).is_err());
}

#[test]
fn parses_environment_list_and_uses_desktop_display_fallbacks() {
    let list: EnvironmentList = serde_json::from_value(json!({
        "items": [{
            "env_id": "env-id",
            "display_name": "example-codex-host",
            "host_name": "example-host",
            "name": null,
            "kind": "host",
            "client_type": "CODEX_CLI",
            "online": true,
            "busy": false,
            "os": "linux",
            "arch": "x86_64",
            "app_server_version": "0.152.0",
            "installation_id": "installation-id",
            "last_seen_at": "2026-08-31T12:00:00Z"
        }],
        "cursor": null
    }))
    .unwrap();

    let environment = &list.items[0];
    assert_eq!(environment.display_name(), "example-codex-host");
    assert_eq!(environment.host_name(), "example-host");
    assert!(environment.online);
}

#[test]
fn retry_after_accepts_delta_seconds_and_rejects_unbounded_waits() {
    assert_eq!(parse_retry_after("2"), Some(Duration::from_secs(2)));
    assert_eq!(parse_retry_after("31"), Some(Duration::from_secs(30)));
    assert_eq!(parse_retry_after("not-a-delay"), None);
}
