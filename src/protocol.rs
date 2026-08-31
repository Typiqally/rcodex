use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

pub const API_BASE: &str = "https://chatgpt.com/backend-api";
pub const AUTH_ISSUER: &str = "https://auth.openai.com";
pub const OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const ENROLL_SCOPE: &str = "codex.remote_control.enroll";
pub const SESSION_SCOPE: &str = "remote_control_controller_websocket";
pub const SIGNING_DOMAIN: &str = "codex-device-key-sign-payload/v1";
pub const RELAY_PROTOCOL_VERSION: u8 = 3;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentRecord {
    pub account_user_id: String,
    pub algorithm: String,
    pub client_id: String,
    pub key_id: String,
    pub protection_class: String,
    pub public_key_spki_der_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnrollmentChallenge {
    pub account_user_id: String,
    pub audience: String,
    pub challenge_expires_at: i64,
    pub challenge_id: String,
    pub challenge_token: String,
    pub client_id: String,
    #[serde(default)]
    pub device_identity_hash: Option<String>,
    pub nonce: String,
    pub purpose: String,
    pub target_origin: String,
    pub target_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionChallenge {
    pub account_user_id: String,
    pub audience: String,
    pub client_id: String,
    pub nonce: String,
    pub purpose: String,
    pub scopes: Vec<String>,
    pub session_id: String,
    pub target_origin: String,
    pub target_path: String,
    pub token_expires_at: i64,
    pub token_sha256_base64url: String,
}

#[derive(Clone, Debug)]
pub struct OAuthAuthorizeParams {
    pub account_id: Option<String>,
    pub code_challenge: String,
    pub originator: String,
    pub redirect_uri: String,
    pub state: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceIdentity<'a> {
    algorithm: &'a str,
    key_id: &'a str,
    protection_class: &'a str,
    public_key_spki_der_base64: &'a str,
}

#[derive(Serialize)]
struct SigningEnvelope<T> {
    domain: &'static str,
    payload: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentSigningPayload<'a> {
    account_user_id: &'a str,
    audience: &'a str,
    challenge_expires_at: i64,
    challenge_id: &'a str,
    client_id: &'a str,
    device_identity_sha256_base64url: &'a str,
    nonce: &'a str,
    target_origin: &'a str,
    target_path: &'a str,
    r#type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionSigningPayload<'a> {
    account_user_id: &'a str,
    audience: &'a str,
    client_id: &'a str,
    nonce: &'a str,
    scopes: &'a [String],
    session_id: &'a str,
    target_origin: &'a str,
    target_path: &'a str,
    token_expires_at: i64,
    token_sha256_base64url: &'a str,
    r#type: &'static str,
}

pub fn device_identity_hash(record: &EnrollmentRecord) -> String {
    let identity = DeviceIdentity {
        algorithm: &record.algorithm,
        key_id: &record.key_id,
        protection_class: &record.protection_class,
        public_key_spki_der_base64: &record.public_key_spki_der_base64,
    };
    let bytes = serde_json::to_vec(&identity).expect("serializing a device identity cannot fail");
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

pub fn build_enrollment_signing_payload(
    record: &EnrollmentRecord,
    challenge: &EnrollmentChallenge,
    expected_relative_path: &str,
    require_device_identity_hash: bool,
) -> Result<Vec<u8>> {
    validate_nonce(&challenge.nonce)?;
    let (expected_origin, expected_path) = relay_target(expected_relative_path)?;
    if challenge.purpose != "remote_control_client_enrollment"
        || challenge.audience != "remote_control_client_enrollment"
        || challenge.account_user_id != record.account_user_id
        || challenge.client_id != record.client_id
        || challenge.target_origin != expected_origin
        || challenge.target_path != expected_path
    {
        bail!("remote-control enrollment challenge does not match the local enrollment");
    }

    if require_device_identity_hash && challenge.device_identity_hash.is_none() {
        bail!("remote-control enrollment challenge is missing device identity hash");
    }
    let local_hash = device_identity_hash(record);
    let challenge_hash = challenge
        .device_identity_hash
        .as_deref()
        .unwrap_or(&local_hash);
    if challenge_hash != local_hash {
        bail!("remote-control enrollment challenge does not match local device identity");
    }

    serde_json::to_vec(&SigningEnvelope {
        domain: SIGNING_DOMAIN,
        payload: EnrollmentSigningPayload {
            account_user_id: &challenge.account_user_id,
            audience: "remote_control_client_enrollment",
            challenge_expires_at: challenge.challenge_expires_at,
            challenge_id: &challenge.challenge_id,
            client_id: &challenge.client_id,
            device_identity_sha256_base64url: challenge_hash,
            nonce: &challenge.nonce,
            target_origin: &challenge.target_origin,
            target_path: &challenge.target_path,
            r#type: "remoteControlClientEnrollment",
        },
    })
    .context("serialize enrollment signing payload")
}

pub fn build_connection_signing_payload(challenge: &ConnectionChallenge) -> Result<Vec<u8>> {
    validate_nonce(&challenge.nonce)?;
    validate_sha256(&challenge.token_sha256_base64url)?;
    let (expected_origin, expected_path) = relay_target("/codex/remote/control/client")?;
    if challenge.purpose != "remote_control_client_websocket"
        || challenge.audience != "remote_control_client_websocket"
        || challenge.target_origin != expected_origin
        || challenge.target_path != expected_path
        || challenge.scopes != [SESSION_SCOPE]
    {
        bail!("remote-control websocket challenge does not match the expected relay contract");
    }

    serde_json::to_vec(&SigningEnvelope {
        domain: SIGNING_DOMAIN,
        payload: ConnectionSigningPayload {
            account_user_id: &challenge.account_user_id,
            audience: &challenge.audience,
            client_id: &challenge.client_id,
            nonce: &challenge.nonce,
            scopes: &challenge.scopes,
            session_id: &challenge.session_id,
            target_origin: &challenge.target_origin,
            target_path: &challenge.target_path,
            token_expires_at: challenge.token_expires_at,
            token_sha256_base64url: &challenge.token_sha256_base64url,
            r#type: "remoteControlClientConnection",
        },
    })
    .context("serialize websocket signing payload")
}

pub fn build_oauth_authorize_url(params: &OAuthAuthorizeParams) -> Result<Url> {
    let mut url = Url::parse(&format!("{AUTH_ISSUER}/oauth/authorize"))?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", OAUTH_CLIENT_ID)
            .append_pair("redirect_uri", &params.redirect_uri)
            .append_pair("scope", ENROLL_SCOPE)
            .append_pair("code_challenge", &params.code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &params.state)
            .append_pair("originator", &params.originator)
            .append_pair("reauth", "remote_control")
            .append_pair("max_age", "0")
            .append_pair("codex_cli_simplified_flow", "true");
        if let Some(account_id) = &params.account_id {
            query
                .append_pair("allowed_workspace_id", account_id)
                .append_pair("current_workspace_id", account_id);
        }
    }
    Ok(url)
}

pub fn client_message_envelope(
    client_id: &str,
    env_id: &str,
    stream_id: &str,
    seq_id: u64,
    message: Value,
) -> Value {
    json!({
        "type": "client_message",
        "client_id": client_id,
        "seq_id": seq_id,
        "stream_id": stream_id,
        "env_id": env_id,
        "skip_history": false,
        "message": message,
    })
}

pub fn relay_target(relative_path: &str) -> Result<(String, String)> {
    let base = Url::parse(&format!("{API_BASE}/"))?;
    let target = base.join(relative_path.trim_start_matches('/'))?;
    Ok((
        target.origin().ascii_serialization(),
        target.path().to_owned(),
    ))
}

fn validate_nonce(value: &str) -> Result<()> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .context("remote-control nonce is not base64url")?;
    if decoded.len() < 32 {
        bail!("remote-control nonce is too short");
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .context("remote-control digest is not base64url")?;
    if decoded.len() != 32 {
        bail!("remote-control digest is not a SHA-256 value");
    }
    Ok(())
}
