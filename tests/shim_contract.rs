use std::{ffi::OsString, path::Path};

use rcodex::{
    api::RemoteEnvironment,
    shim::{LocalShim, SHIM_AUTH_TOKEN_ENV, codex_remote_args, select_environment},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION},
};

fn environment(id: &str, online: bool) -> RemoteEnvironment {
    RemoteEnvironment {
        app_server_version: Some("0.151.0".into()),
        arch: Some("x86_64".into()),
        busy: false,
        client_type: Some("cli".into()),
        display_name: Some(format!("host-{id}")),
        env_id: id.into(),
        host_name: Some(format!("host-{id}")),
        installation_id: None,
        kind: Some("computer".into()),
        last_seen_at: None,
        name: None,
        online,
        os: Some("linux".into()),
    }
}

#[test]
fn one_online_host_is_selected_automatically() {
    let environments = vec![environment("offline", false), environment("online", true)];
    let selected = select_environment(&environments, None).unwrap();
    assert_eq!(selected.env_id, "online");
}

#[test]
fn ambiguous_or_offline_host_selection_is_rejected() {
    let environments = vec![environment("one", true), environment("two", true)];
    assert!(select_environment(&environments, None).is_err());
    assert!(select_environment(&environments, Some("missing")).is_err());

    let offline = vec![environment("one", false)];
    assert!(select_environment(&offline, Some("one")).is_err());
}

#[test]
fn stock_codex_receives_only_the_loopback_remote_and_remote_cwd() {
    assert_eq!(
        codex_remote_args("ws://127.0.0.1:43123", Some(Path::new("/srv/project"))),
        vec![
            OsString::from("--remote"),
            OsString::from("ws://127.0.0.1:43123"),
            OsString::from("--remote-auth-token-env"),
            OsString::from(SHIM_AUTH_TOKEN_ENV),
            OsString::from("-C"),
            OsString::from("/srv/project"),
        ]
    );
}

#[tokio::test]
async fn shim_rejects_a_client_without_its_per_run_bearer_token() {
    let shim = LocalShim::bind().await.unwrap();
    let url = shim.url().unwrap();
    let accepting = tokio::spawn(shim.accept());

    assert!(connect_async(url).await.is_err());
    assert!(accepting.await.unwrap().is_err());
}

#[tokio::test]
async fn shim_accepts_a_client_with_its_per_run_bearer_token() {
    let shim = LocalShim::bind().await.unwrap();
    let url = shim.url().unwrap();
    let token = shim.auth_token().to_owned();
    let accepting = tokio::spawn(shim.accept());
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());

    let (client, _) = connect_async(request).await.unwrap();
    let server = accepting.await.unwrap().unwrap();

    drop(client);
    drop(server);
}
