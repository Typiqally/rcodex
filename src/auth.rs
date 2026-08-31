use std::{fmt, fs, io::Write, path::Path};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::protocol::OAUTH_CLIENT_ID;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[derive(Clone)]
pub struct CodexAuth {
    access_token: String,
    account_id: String,
    account_user_id: String,
    auth_user_id: Option<String>,
    expires_at: i64,
    refresh_token: String,
}

impl CodexAuth {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn account_user_id(&self) -> &str {
        &self.account_user_id
    }

    pub fn matches_relay_account_user_id(&self, candidate: &str) -> bool {
        candidate == self.account_user_id
            || self
                .auth_user_id
                .as_deref()
                .is_some_and(|id| candidate == id)
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn needs_refresh(&self, now_epoch: i64) -> bool {
        self.expires_at <= now_epoch.saturating_add(5 * 60)
    }
}

impl fmt::Display for CodexAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ChatGPT auth for account {} (expires {})",
            self.account_id, self.expires_at
        )
    }
}

impl fmt::Debug for CodexAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAuth")
            .field("account_id", &self.account_id)
            .field("account_user_id", &self.account_user_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct AuthDocument {
    auth_mode: Option<String>,
    tokens: Option<AuthTokens>,
}

#[derive(Deserialize)]
struct AuthTokens {
    access_token: String,
    account_id: Option<String>,
    refresh_token: String,
}

#[derive(Deserialize)]
struct AccessTokenClaims {
    exp: i64,
    #[serde(rename = "https://api.openai.com/auth")]
    auth: AccessTokenIdentity,
}

#[derive(Deserialize)]
struct AccessTokenIdentity {
    account_id: Option<String>,
    account_user_id: Option<String>,
    chatgpt_account_id: Option<String>,
    chatgpt_account_user_id: Option<String>,
    user_id: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RefreshResponse {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

pub fn load_codex_auth(path: &Path) -> Result<CodexAuth> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect Codex auth file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("Codex auth path is not a regular file: {}", path.display());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("Codex auth file must not be accessible by group or others");
    }

    let document: AuthDocument = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read Codex auth file {}", path.display()))?,
    )
    .context("parse Codex auth file")?;
    if document.auth_mode.as_deref() != Some("chatgpt") {
        bail!("rcodex requires Codex CLI ChatGPT subscription authentication");
    }
    let tokens = document.tokens.context("Codex auth file has no tokens")?;
    validate_secret("access token", &tokens.access_token)?;
    validate_secret("refresh token", &tokens.refresh_token)?;
    let claims = decode_access_token(&tokens.access_token)?;
    let claim_account_id = claims
        .auth
        .chatgpt_account_id
        .or(claims.auth.account_id)
        .context("Codex access token has no ChatGPT account ID")?;
    let account_id = tokens
        .account_id
        .unwrap_or_else(|| claim_account_id.clone());
    if account_id != claim_account_id {
        bail!("Codex auth account ID does not match its access token");
    }
    let account_user_id = claims
        .auth
        .chatgpt_account_user_id
        .clone()
        .or_else(|| claims.auth.account_user_id.clone())
        .context("Codex access token has no ChatGPT account user ID")?;

    Ok(CodexAuth {
        access_token: tokens.access_token,
        account_id,
        account_user_id,
        auth_user_id: claims.auth.user_id,
        expires_at: claims.exp,
        refresh_token: tokens.refresh_token,
    })
}

pub fn build_refresh_request(auth: &CodexAuth) -> Value {
    json!({
        "client_id": OAUTH_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": auth.refresh_token,
    })
}

pub fn merge_refresh_response(
    mut document: Value,
    response: RefreshResponse,
    refreshed_at: &str,
) -> Result<Value> {
    let object = document
        .as_object_mut()
        .context("Codex auth document is not an object")?;
    let tokens = object
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("Codex auth document has no token object")?;
    if let Some(access_token) = response.access_token {
        validate_secret("refreshed access token", &access_token)?;
        decode_access_token(&access_token)?;
        tokens.insert("access_token".into(), Value::String(access_token));
    }
    if let Some(id_token) = response.id_token {
        validate_secret("refreshed ID token", &id_token)?;
        tokens.insert("id_token".into(), Value::String(id_token));
    }
    if let Some(refresh_token) = response.refresh_token {
        validate_secret("rotated refresh token", &refresh_token)?;
        tokens.insert("refresh_token".into(), Value::String(refresh_token));
    }
    object.insert("last_refresh".into(), Value::String(refreshed_at.into()));
    Ok(document)
}

pub async fn refresh_codex_auth(client: &reqwest::Client, path: &Path) -> Result<CodexAuth> {
    let before_bytes = fs::read(path)
        .with_context(|| format!("read Codex auth file {} before refresh", path.display()))?;
    let before_document: Value =
        serde_json::from_slice(&before_bytes).context("parse Codex auth before refresh")?;
    let before = load_codex_auth(path)?;

    let response = client
        .post(format!("{}/oauth/token", crate::protocol::AUTH_ISSUER))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&build_refresh_request(&before))
        .send()
        .await
        .context("request Codex OAuth token refresh")?;
    if !response.status().is_success() {
        bail!("Codex OAuth token refresh failed ({})", response.status());
    }
    let refresh: RefreshResponse = response
        .json()
        .await
        .context("parse Codex OAuth refresh response")?;

    if !auth_file_matches_snapshot(path, &before_bytes)? {
        return load_codex_auth(path);
    }

    let refreshed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let updated = merge_refresh_response(before_document, refresh, &refreshed_at)?;
    save_auth_document(path, &updated)?;
    load_codex_auth(path)
}

fn auth_file_matches_snapshot(path: &Path, expected: &[u8]) -> Result<bool> {
    Ok(fs::read(path)
        .with_context(|| format!("re-read Codex auth file {} after refresh", path.display()))?
        == expected)
}

fn save_auth_document(path: &Path, document: &Value) -> Result<()> {
    let parent = path.parent().context("Codex auth path has no parent")?;
    let temporary = parent.join(format!(".auth-{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(document).context("serialize refreshed Codex auth")?;
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create temporary Codex auth {}", temporary.display()))?;
        file.write_all(&bytes)
            .context("write refreshed Codex auth")?;
        file.write_all(b"\n")
            .context("finish refreshed Codex auth")?;
        file.sync_all().context("flush refreshed Codex auth")?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("protect refreshed Codex auth")?;
        fs::rename(&temporary, path).context("install refreshed Codex auth")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn decode_access_token(token: &str) -> Result<AccessTokenClaims> {
    let payload = token
        .split('.')
        .nth(1)
        .filter(|part| !part.is_empty())
        .context("Codex access token is not a JWT")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("Codex access token payload is not base64url")?;
    serde_json::from_slice(&bytes).context("Codex access token payload is invalid")
}

fn validate_secret(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        bail!("Codex {name} is empty or malformed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::auth_file_matches_snapshot;

    #[test]
    fn auth_snapshot_detects_any_concurrent_file_change() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        std::fs::write(&path, b"before").unwrap();

        assert!(auth_file_matches_snapshot(&path, b"before").unwrap());
        std::fs::write(&path, b"after").unwrap();
        assert!(!auth_file_matches_snapshot(&path, b"before").unwrap());
    }
}
