use std::{ffi::OsString, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async,
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        http::{StatusCode, header::AUTHORIZATION},
    },
};

use crate::{api::RemoteEnvironment, transport::RelayTransport};

pub const SHIM_AUTH_TOKEN_ENV: &str = "RCODEX_SHIM_AUTH_TOKEN";

pub struct LocalShim {
    auth_token: String,
    listener: TcpListener,
}

impl LocalShim {
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind rcodex loopback websocket")?;
        let auth_token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        Ok(Self {
            auth_token,
            listener,
        })
    }

    pub fn url(&self) -> Result<String> {
        let address = self
            .listener
            .local_addr()
            .context("read rcodex shim address")?;
        Ok(format!("ws://{address}"))
    }

    pub fn auth_token(&self) -> &str {
        &self.auth_token
    }

    #[allow(clippy::result_large_err)]
    pub async fn accept(self) -> Result<WebSocketStream<TcpStream>> {
        let (stream, peer) = tokio::time::timeout(Duration::from_secs(30), self.listener.accept())
            .await
            .context("stock Codex did not connect to the rcodex shim")??;
        if !peer.ip().is_loopback() {
            bail!("rcodex rejected a non-loopback shim connection");
        }
        let expected_token = self.auth_token;
        accept_hdr_async(stream, move |request: &Request, response: Response| {
            authorize_shim_request(request, response, &expected_token)
        })
        .await
        .context("accept authenticated stock Codex websocket connection")
    }

    pub async fn serve(self, relay: RelayTransport) -> Result<()> {
        relay.bridge_local(self.accept().await?).await
    }
}

#[allow(clippy::result_large_err)]
fn authorize_shim_request(
    request: &Request,
    response: Response,
    expected_token: &str,
) -> std::result::Result<Response, ErrorResponse> {
    let authorized = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|candidate| candidate.as_bytes().ct_eq(expected_token.as_bytes()).into());
    if authorized {
        return Ok(response);
    }
    let mut rejected = ErrorResponse::new(Some("Unauthorized".into()));
    *rejected.status_mut() = StatusCode::UNAUTHORIZED;
    Err(rejected)
}

pub fn select_environment<'a>(
    environments: &'a [RemoteEnvironment],
    requested: Option<&str>,
) -> Result<&'a RemoteEnvironment> {
    if let Some(requested) = requested {
        let environment = environments
            .iter()
            .find(|environment| environment.env_id == requested)
            .with_context(|| format!("remote-control environment {requested} was not found"))?;
        if !environment.online {
            bail!("remote-control environment {requested} is offline");
        }
        return Ok(environment);
    }

    let mut online = environments.iter().filter(|environment| environment.online);
    let environment = online
        .next()
        .context("no paired Codex remote-control host is online")?;
    if online.next().is_some() {
        bail!("multiple Codex hosts are online; choose one with --device <ENV_ID>");
    }
    Ok(environment)
}

pub fn codex_remote_args(url: &str, remote_cwd: Option<&Path>) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("--remote"),
        OsString::from(url),
        OsString::from("--remote-auth-token-env"),
        OsString::from(SHIM_AUTH_TOKEN_ENV),
    ];
    if let Some(remote_cwd) = remote_cwd {
        arguments.push(OsString::from("-C"));
        arguments.push(remote_cwd.as_os_str().to_owned());
    }
    arguments
}
