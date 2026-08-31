use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::{Method, Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::sleep;

use crate::{
    auth::{CodexAuth, load_codex_auth, refresh_codex_auth},
    protocol::{API_BASE, EnrollmentRecord},
    relay::{EnrollmentStartResponse, RemoteControlSession},
};

#[derive(Clone, Deserialize)]
pub struct RemoteEnvironment {
    pub app_server_version: Option<String>,
    pub arch: Option<String>,
    pub busy: bool,
    pub client_type: Option<String>,
    pub display_name: Option<String>,
    pub env_id: String,
    pub host_name: Option<String>,
    pub installation_id: Option<String>,
    pub kind: Option<String>,
    pub last_seen_at: Option<String>,
    pub name: Option<String>,
    pub online: bool,
    pub os: Option<String>,
}

impl RemoteEnvironment {
    pub fn display_name(&self) -> &str {
        first_nonempty([
            self.display_name.as_deref(),
            self.name.as_deref(),
            self.host_name.as_deref(),
            Some(&self.env_id),
        ])
    }

    pub fn host_name(&self) -> &str {
        first_nonempty([
            self.host_name.as_deref(),
            self.name.as_deref(),
            self.display_name.as_deref(),
            Some(&self.env_id),
        ])
    }
}

#[derive(Deserialize)]
pub struct EnvironmentList {
    pub cursor: Option<String>,
    pub items: Vec<RemoteEnvironment>,
}

pub struct RelayApi {
    client: reqwest::Client,
    auth_path: PathBuf,
}

impl RelayApi {
    pub fn new(auth_path: PathBuf) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(45))
            .user_agent(format!("rcodex/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build rcodex HTTP client")?;
        Ok(Self { client, auth_path })
    }

    pub fn http_client(&self) -> &reqwest::Client {
        &self.client
    }

    pub async fn auth(&self) -> Result<CodexAuth> {
        let auth = load_codex_auth(&self.auth_path)?;
        if auth.needs_refresh(chrono::Utc::now().timestamp()) {
            return refresh_codex_auth(&self.client, &self.auth_path).await;
        }
        Ok(auth)
    }

    pub async fn list_environments(
        &self,
        client_id: Option<&str>,
    ) -> Result<Vec<RemoteEnvironment>> {
        let mut cursor: Option<String> = None;
        let mut environments = Vec::new();
        loop {
            let root = match client_id {
                Some(client_id) => format!(
                    "/codex/remote/control/clients/{}/environments",
                    url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>()
                ),
                None => "/codex/remote/control/environments".into(),
            };
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("limit", "100");
            if let Some(cursor) = &cursor {
                query.append_pair("cursor", cursor);
            }
            let page: EnvironmentList = self
                .request_json(Method::GET, &format!("{root}?{}", query.finish()), None)
                .await?;
            environments.extend(page.items);
            cursor = page.cursor;
            if cursor.is_none() {
                return Ok(environments);
            }
        }
    }

    pub async fn pair_client(&self, client_id: &str, manual_pairing_code: &str) -> Result<()> {
        let body = build_manual_pairing_body(client_id, manual_pairing_code)?;
        self.send(Method::POST, "/wham/remote/control/client/pair", Some(body))
            .await?;
        Ok(())
    }

    pub async fn revoke_client(&self, client_id: &str) -> Result<()> {
        self.send_allowing_not_found(Method::DELETE, &client_revocation_path(client_id)?, None)
            .await?;
        Ok(())
    }

    pub async fn enroll_start(&self) -> Result<EnrollmentStartResponse> {
        self.request_json(
            Method::POST,
            "/codex/remote/control/client/enroll/start",
            Some(json!({})),
        )
        .await
    }

    pub async fn enroll_finish(&self, body: Value) -> Result<RemoteControlSession> {
        self.request_json(
            Method::POST,
            "/codex/remote/control/client/enroll/finish",
            Some(body),
        )
        .await
    }

    pub async fn refresh_start(
        &self,
        enrollment: &EnrollmentRecord,
    ) -> Result<EnrollmentStartResponse> {
        self.request_json(
            Method::POST,
            "/codex/remote/control/client/refresh/start",
            Some(json!({"client_id": enrollment.client_id})),
        )
        .await
    }

    pub async fn refresh_finish(&self, body: Value) -> Result<RemoteControlSession> {
        self.request_json(
            Method::POST,
            "/codex/remote/control/client/refresh/finish",
            Some(body),
        )
        .await
    }

    async fn request_json<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T> {
        self.send(method, path, body)
            .await?
            .json::<T>()
            .await
            .context("parse remote-control response")
    }

    async fn send(&self, method: Method, path: &str, body: Option<Value>) -> Result<Response> {
        self.send_with_status_policy(method, path, body, false)
            .await
    }

    async fn send_allowing_not_found(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Response> {
        self.send_with_status_policy(method, path, body, true).await
    }

    async fn send_with_status_policy(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        allow_not_found: bool,
    ) -> Result<Response> {
        let mut auth = self.auth().await?;
        let mut refreshed_after_unauthorized = false;
        let mut retry_count = 0_u8;
        loop {
            let mut request = self
                .client
                .request(method.clone(), format!("{API_BASE}{path}"))
                .bearer_auth(auth.access_token())
                .header("ChatGPT-Account-Id", auth.account_id());
            if let Some(body) = &body {
                request = request.json(body);
            }
            let response = request
                .send()
                .await
                .context("send remote-control request")?;
            if response.status() == StatusCode::UNAUTHORIZED && !refreshed_after_unauthorized {
                auth = refresh_codex_auth(&self.client, &self.auth_path).await?;
                refreshed_after_unauthorized = true;
                continue;
            }
            if (response.status() == StatusCode::TOO_MANY_REQUESTS
                || response.status().is_server_error())
                && retry_count < 3
            {
                let delay = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_retry_after)
                    .unwrap_or_else(|| Duration::from_millis(250 * 2_u64.pow(retry_count.into())));
                retry_count += 1;
                sleep(delay).await;
                continue;
            }
            if !(response.status().is_success()
                || allow_not_found && response.status() == StatusCode::NOT_FOUND)
            {
                bail!("remote-control request failed ({})", response.status());
            }
            return Ok(response);
        }
    }
}

pub fn build_manual_pairing_body(client_id: &str, manual_pairing_code: &str) -> Result<Value> {
    if client_id.trim().is_empty() {
        bail!("rcodex client ID is empty");
    }
    let compact = manual_pairing_code
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    if compact.len() != 8
        || !compact
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        bail!("manual pairing code must contain exactly eight letters or digits");
    }
    let formatted = format!("{}-{}", &compact[..4], &compact[4..]);
    Ok(json!({
        "client_id": client_id,
        "manual_pairing_code": formatted,
    }))
}

pub fn client_revocation_path(client_id: &str) -> Result<String> {
    if client_id.trim().is_empty() {
        bail!("rcodex client ID is empty");
    }
    let mut url = url::Url::parse("https://chatgpt.invalid/wham/remote/control/clients/")?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("could not construct client revocation path"))?
        .pop_if_empty()
        .push(client_id);
    Ok(url.path().into())
}

pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let seconds = value.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds.min(30)))
}

fn first_nonempty<const N: usize>(values: [Option<&str>; N]) -> &str {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .unwrap_or("")
}
