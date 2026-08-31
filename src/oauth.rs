use std::process::Command;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Duration, timeout},
};
use url::Url;

use crate::protocol::{
    AUTH_ISSUER, ENROLL_SCOPE, OAUTH_CLIENT_ID, OAuthAuthorizeParams, build_oauth_authorize_url,
};

const CALLBACK_PORTS: [u16; 2] = [1455, 1457];
const CALLBACK_PATH: &str = "/auth/callback";

#[derive(Deserialize)]
struct StepUpClaims {
    iat: i64,
    pwd_auth_time: i64,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scp: Vec<String>,
    #[serde(rename = "https://api.openai.com/auth")]
    auth: StepUpIdentity,
}

#[derive(Deserialize)]
struct StepUpIdentity {
    account_user_id: Option<String>,
    chatgpt_account_user_id: Option<String>,
}

#[derive(Deserialize)]
struct TokenExchangeResponse {
    access_token: String,
}

pub fn validate_step_up_token(
    token: &str,
    expected_account_user_id: &str,
    now_epoch: i64,
) -> Result<()> {
    let payload = token
        .split('.')
        .nth(1)
        .filter(|part| !part.is_empty())
        .context("remote-control step-up token is not a JWT")?;
    let claims: StepUpClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .context("remote-control step-up token is not base64url")?,
    )
    .context("remote-control step-up token payload is invalid")?;
    let account_user_id = claims
        .auth
        .chatgpt_account_user_id
        .or(claims.auth.account_user_id)
        .context("remote-control step-up token has no account user ID")?;
    if account_user_id != expected_account_user_id {
        bail!("remote-control step-up token belongs to a different account");
    }
    if claims.iat > now_epoch.saturating_add(60) || now_epoch.saturating_sub(claims.iat) > 300 {
        bail!("remote-control step-up token is not fresh");
    }
    if now_epoch
        .saturating_mul(1000)
        .saturating_sub(claims.pwd_auth_time)
        > 300_000
    {
        bail!("remote-control step-up token has no fresh password authentication");
    }
    let mut scopes: Vec<_> = claims
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    scopes.extend(claims.scp);
    scopes.sort();
    scopes.dedup();
    if scopes != [ENROLL_SCOPE] {
        bail!("remote-control step-up token has unexpected authorization scopes");
    }
    Ok(())
}

pub async fn request_step_up_token(
    client: &reqwest::Client,
    account_id: &str,
    account_user_id: &str,
) -> Result<String> {
    let (listener, port) = bind_callback().await?;
    let redirect_uri = format!("http://localhost:{port}{CALLBACK_PATH}");
    let (verifier, challenge) = pkce_pair();
    let state = random_base64url(32);
    let authorize_url = build_oauth_authorize_url(&OAuthAuthorizeParams {
        account_id: Some(account_id.into()),
        code_challenge: challenge,
        originator: "codex_desktop".into(),
        redirect_uri: redirect_uri.clone(),
        state: state.clone(),
    })?;

    open_browser(&authorize_url)?;
    let code = timeout(
        Duration::from_secs(10 * 60),
        receive_callback(listener, &state),
    )
    .await
    .context("timed out waiting for remote-control authorization")??;

    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("client_id", OAUTH_CLIENT_ID)
        .append_pair("code_verifier", &verifier);
    let response = client
        .post(format!("{AUTH_ISSUER}/oauth/token"))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form.finish())
        .send()
        .await
        .context("exchange remote-control authorization code")?;
    if !response.status().is_success() {
        bail!(
            "remote-control authorization exchange failed ({})",
            response.status()
        );
    }
    let token = response
        .json::<TokenExchangeResponse>()
        .await
        .context("parse remote-control authorization exchange")?
        .access_token;
    validate_step_up_token(&token, account_user_id, chrono::Utc::now().timestamp())?;
    Ok(token)
}

async fn bind_callback() -> Result<(TcpListener, u16)> {
    for port in CALLBACK_PORTS {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            return Ok((listener, port));
        }
    }
    bail!("remote-control OAuth callback ports 1455 and 1457 are both in use")
}

async fn receive_callback(listener: TcpListener, expected_state: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener.accept().await.context("accept OAuth callback")?;
        let mut buffer = vec![0_u8; 8192];
        let count = stream
            .read(&mut buffer)
            .await
            .context("read OAuth callback")?;
        let request =
            std::str::from_utf8(&buffer[..count]).context("OAuth callback is not UTF-8")?;
        let target = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .context("OAuth callback request is malformed")?;
        let url = Url::parse(&format!("http://localhost{target}"))?;
        if url.path() != CALLBACK_PATH {
            respond(&mut stream, 404, "Not found").await?;
            continue;
        }
        let parameters: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        if parameters.get("state").map(String::as_str) != Some(expected_state) {
            respond(&mut stream, 400, "Authorization state did not match").await?;
            bail!("remote-control OAuth callback state did not match");
        }
        if let Some(error) = parameters.get("error") {
            respond(&mut stream, 400, "Authorization was not completed").await?;
            bail!("remote-control authorization failed: {error}");
        }
        let code = parameters
            .get("code")
            .filter(|code| !code.is_empty())
            .cloned()
            .context("remote-control OAuth callback has no code")?;
        respond(
            &mut stream,
            200,
            "Remote-control authorization complete. You can close this tab.",
        )
        .await?;
        return Ok(code);
    }
}

async fn respond(stream: &mut tokio::net::TcpStream, status: u16, body: &str) -> Result<()> {
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write OAuth callback response")
}

fn pkce_pair() -> (String, String) {
    let verifier = random_base64url(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn random_base64url(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn open_browser(url: &Url) -> Result<()> {
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(url.as_str()).status();
    #[cfg(not(target_os = "macos"))]
    let status = Command::new("xdg-open").arg(url.as_str()).status();
    let status = status.context("open remote-control authorization in browser")?;
    if !status.success() {
        bail!("could not open the remote-control authorization browser");
    }
    Ok(())
}
