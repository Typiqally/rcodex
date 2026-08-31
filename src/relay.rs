use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::protocol::{
    ConnectionChallenge, EnrollmentChallenge, EnrollmentRecord, SESSION_SCOPE,
    build_connection_signing_payload,
};

#[derive(Deserialize)]
pub struct EnrollmentStartResponse {
    pub account_user_id: String,
    pub client_id: String,
    pub device_key_challenge: EnrollmentChallenge,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DeviceKeyProof {
    pub algorithm: String,
    pub challenge_token: String,
    pub key_id: String,
    pub signature_der_base64: String,
    pub signed_payload_base64: String,
}

#[derive(Clone, Deserialize)]
pub struct RemoteControlSession {
    pub account_user_id: String,
    pub client_id: String,
    pub expires_at: String,
    pub remote_control_token: String,
    pub scopes: Vec<String>,
}

pub fn device_key_proof(
    challenge_token: &str,
    key_id: &str,
    signed_payload: &[u8],
    signature_der: &[u8],
) -> DeviceKeyProof {
    DeviceKeyProof {
        algorithm: "ecdsa_p256_sha256".into(),
        challenge_token: challenge_token.into(),
        key_id: key_id.into(),
        signature_der_base64: STANDARD.encode(signature_der),
        signed_payload_base64: STANDARD.encode(signed_payload),
    }
}

pub fn build_enroll_finish_body(
    enrollment: &EnrollmentRecord,
    step_up_token: &str,
    proof: DeviceKeyProof,
) -> Value {
    json!({
        "client_id": enrollment.client_id,
        "step_up_token": step_up_token,
        "device_identity": {
            "key_id": enrollment.key_id,
            "public_key_spki_der_base64": enrollment.public_key_spki_der_base64,
            "algorithm": enrollment.algorithm,
            "protection_class": enrollment.protection_class,
        },
        "device_key_proof": proof,
    })
}

pub fn build_refresh_finish_body(enrollment: &EnrollmentRecord, proof: DeviceKeyProof) -> Value {
    json!({
        "client_id": enrollment.client_id,
        "device_key_proof": proof,
    })
}

pub fn validate_remote_session(
    enrollment: &EnrollmentRecord,
    session: &RemoteControlSession,
    now_epoch: i64,
) -> Result<i64> {
    if session.client_id != enrollment.client_id
        || session.account_user_id != enrollment.account_user_id
    {
        bail!("remote-control session does not match the local enrollment");
    }
    if session.scopes != [SESSION_SCOPE] {
        bail!("remote-control session has unexpected scopes");
    }
    validate_session_secret(&session.remote_control_token)?;
    let expires_at = DateTime::parse_from_rfc3339(&session.expires_at)
        .context("remote-control session expiration is not RFC 3339")?
        .timestamp();
    if expires_at <= now_epoch {
        bail!("remote-control session is already expired");
    }
    Ok(expires_at)
}

pub fn validate_and_build_connection_signing_payload(
    enrollment: &EnrollmentRecord,
    session: &RemoteControlSession,
    challenge: &ConnectionChallenge,
    now_epoch: i64,
) -> Result<Vec<u8>> {
    let session_expiration = validate_remote_session(enrollment, session, now_epoch)?;
    if challenge.client_id != enrollment.client_id
        || challenge.account_user_id != enrollment.account_user_id
        || challenge.token_expires_at != session_expiration
        || challenge.token_expires_at <= now_epoch
    {
        bail!("remote-control websocket challenge does not match the active session");
    }
    let expected = Sha256::digest(session.remote_control_token.as_bytes());
    let supplied = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&challenge.token_sha256_base64url)
        .context("remote-control websocket challenge token digest is invalid")?;
    if !constant_time_equal(&expected, &supplied) {
        bail!("remote-control websocket challenge is bound to a different session token");
    }
    build_connection_signing_payload(challenge)
}

fn validate_session_secret(value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        bail!("remote-control session token is empty or malformed");
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
