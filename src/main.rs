use std::{path::PathBuf, process::Stdio};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rcodex::{
    api::RelayApi,
    broker::{
        BrokerAction, BrokerErrorCode, BrokerHost, BrokerResponse, BrokerSession,
        MAX_BROKER_FRAME_BYTES, decode_request,
    },
    compatibility::{
        parse_stock_codex_version, verify_remote_codex_version, verify_stock_codex_capabilities,
    },
    controller::{enroll, ensure_session},
    shim::{LocalShim, SHIM_AUTH_TOKEN_ENV, codex_remote_args, select_environment},
    state::load_controller_state,
    transport::RelayTransport,
    update::{self, Installation, UpdateSettings},
};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

#[derive(Parser)]
#[command(version, about = "Control a remote Codex host through OpenAI's relay")]
struct Cli {
    /// Paired environment ID; optional when exactly one host is online.
    #[arg(long, value_name = "ENV_ID")]
    device: Option<String>,
    /// Working directory for new tasks on the remote host.
    #[arg(short = 'C', long = "cd", value_name = "DIR")]
    remote_cwd: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Check, install, configure, or roll back signed rcodex updates.
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
    /// List Codex hosts visible to the current ChatGPT account.
    Devices,
    /// Enroll a separate rcodex controller identity.
    Enroll,
    /// Pair the enrolled rcodex identity with a Codex host.
    Pair {
        /// Eight-character code from the host; omit it for a hidden prompt.
        code: Option<String>,
    },
    /// Refresh and verify the rcodex controller session.
    Session,
    /// Revoke this controller, delete its Keychain key, and remove local state.
    Unenroll,
    /// Exchange one initialize message with a remote Codex host.
    Probe {
        /// Environment ID from `rcodex devices`.
        #[arg(long)]
        device: String,
    },
    /// Revoke an obsolete rcodex controller identity.
    #[command(hide = true)]
    RevokeClient { client_id: String },
    /// Serve the isolated relay controller over bounded JSONL.
    #[command(hide = true, about = "Serve the relay controller over bounded JSONL")]
    Broker,
}

#[derive(Subcommand)]
enum UpdateAction {
    /// Check for a signed release compatible with the local and selected remote Codex.
    Check,
    /// Install a compatible signed release while no rcodex session is running.
    Install,
    /// Enable a daily update check before starting a TUI session.
    Enable,
    /// Disable automatic updates.
    Disable,
    /// Restore the previous executable and disable automatic updates.
    Rollback,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("rcodex: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::resolve()?;
    if let Some(Command::Update { action }) = cli.command {
        return run_update(action, &paths, cli.device.as_deref()).await;
    }
    let api = RelayApi::new(paths.auth.clone())?;
    let Some(command) = cli.command else {
        return run_remote_tui(
            &api,
            &paths,
            cli.device.as_deref(),
            cli.remote_cwd.as_deref(),
        )
        .await;
    };
    match command {
        Command::Update { .. } => unreachable!("handled before relay initialization"),
        Command::Devices => {
            let client_id = if paths.state.exists() {
                Some(load_controller_state(&paths.state)?.enrollment.client_id)
            } else {
                None
            };
            let environments = api.list_environments(client_id.as_deref()).await?;
            if environments.is_empty() {
                println!("No Codex remote-control hosts found.");
            }
            for environment in environments {
                let status = if environment.online {
                    "online"
                } else {
                    "offline"
                };
                println!(
                    "{}\t{}\t{}\t{}",
                    environment.env_id,
                    status,
                    environment.display_name(),
                    environment.host_name()
                );
            }
        }
        Command::Enroll => {
            let (state, _) = enroll(&api, &paths.state).await?;
            println!(
                "Enrolled rcodex client {} with an OS-protected non-exportable key.",
                state.enrollment.client_id
            );
        }
        Command::Pair { code } => {
            let state = load_controller_state(&paths.state)
                .context("rcodex is not enrolled; run `rcodex enroll` first")?;
            let code = match code {
                Some(code) => code,
                None => rpassword::prompt_password("Pairing code: ")
                    .context("read pairing code from the terminal")?,
            };
            api.pair_client(&state.enrollment.client_id, &code).await?;
            println!(
                "Paired rcodex client {} with the Codex host.",
                state.enrollment.client_id
            );
        }
        Command::Session => {
            let (state, _) = ensure_session(&api, &paths.state).await?;
            println!(
                "Verified rcodex relay session for client {}.",
                state.enrollment.client_id
            );
        }
        Command::Unenroll => {
            let state = load_controller_state(&paths.state)
                .context("rcodex is not enrolled; no controller state was found")?;
            api.revoke_client(&state.enrollment.client_id).await?;
            rcodex::device_key::delete_os_protected_device_key(&state.enrollment.key_id)
                .context("delete the rcodex Keychain key after revocation")?;
            rcodex::state::delete_controller_state(&paths.state)?;
            println!("Revoked the rcodex controller and removed its local identity.");
        }
        Command::Probe { device } => {
            let (state, session) = ensure_session(&api, &paths.state).await?;
            let auth = api.auth().await?;
            let environments = api
                .list_environments(Some(&state.enrollment.client_id))
                .await?;
            let environment = environments
                .iter()
                .find(|environment| environment.env_id == device)
                .with_context(|| format!("remote-control environment {device} was not found"))?;
            if !environment.online {
                anyhow::bail!("remote-control environment {device} is offline");
            }
            let mut transport =
                RelayTransport::connect(&auth, &state.enrollment, &session, &device).await?;
            transport
                .send_app_message(json!({
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "clientInfo": {
                            "name": "rcodex",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }
                }))
                .await?;
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                transport.receive_app_message(),
            )
            .await
            .context("timed out waiting for the remote Codex initialize response")??;
            println!("{}", serde_json::to_string_pretty(&response)?);
            transport.close().await?;
        }
        Command::RevokeClient { client_id } => {
            api.revoke_client(&client_id).await?;
            println!("Revoked obsolete rcodex client {client_id}.");
        }
        Command::Broker => {
            let _session = Installation::lock(&std::env::current_exe()?, false)?;
            run_broker(&api, &paths).await?;
        }
    }
    Ok(())
}

async fn run_update(action: UpdateAction, paths: &Paths, device: Option<&str>) -> Result<()> {
    let settings_path = paths.state.with_file_name("update.json");
    match action {
        UpdateAction::Enable | UpdateAction::Disable | UpdateAction::Rollback => {
            let installation = Installation::lock(&std::env::current_exe()?, true)?;
            let mut settings = UpdateSettings::load(&settings_path)?;
            match action {
                UpdateAction::Enable => {
                    update::target()?;
                    let status = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::process::Command::new("gh")
                            .args(["attestation", "verify", "--help"])
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .kill_on_drop(true)
                            .status(),
                    )
                    .await
                    .context("GitHub CLI check timed out")?
                    .context("install GitHub CLI (`gh`) before enabling signed updates")?;
                    if !status.success() {
                        anyhow::bail!("GitHub CLI must support `gh attestation verify`");
                    }
                    settings.enabled = true;
                    settings.last_checked = None;
                }
                UpdateAction::Disable => settings.enabled = false,
                UpdateAction::Rollback => {
                    // Disable first so the restored executable is not replaced on its next start.
                    settings.enabled = false;
                    settings.save(&settings_path)?;
                    installation.rollback()?;
                    println!(
                        "Restored the previous rcodex executable; automatic updates are disabled."
                    );
                    return Ok(());
                }
                _ => unreachable!(),
            }
            settings.save(&settings_path)?;
            println!(
                "Automatic rcodex updates {}.",
                if settings.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
        }
        UpdateAction::Check | UpdateAction::Install => {
            let local = inspect_stock_codex().await?;
            let api = RelayApi::new(paths.auth.clone())?;
            let (state, _) = ensure_session(&api, &paths.state).await?;
            let environments = api
                .list_environments(Some(&state.enrollment.client_id))
                .await?;
            let remote = select_environment(&environments, device)?;
            let remote_version = remote
                .app_server_version
                .as_deref()
                .context("remote Codex version is unknown")?;
            let Some(available) =
                update::check(env!("CARGO_PKG_VERSION"), &local, remote_version).await?
            else {
                println!("No newer signed rcodex release supports local/remote Codex {local}.");
                return Ok(());
            };
            if matches!(action, UpdateAction::Install) {
                let installation = Installation::lock(&std::env::current_exe()?, true)?;
                available.install(&installation).await?;
                println!(
                    "Installed rcodex {}; the next invocation uses it. Run `rcodex update rollback` to restore the previous version.",
                    available.manifest.version
                );
            } else {
                println!(
                    "rcodex {} is compatible with local/remote Codex {local}. Run `rcodex update install`.",
                    available.manifest.version
                );
            }
        }
    }
    Ok(())
}

async fn automatic_update(paths: &Paths, local: &str, remote: &str) -> Result<bool> {
    let settings_path = paths.state.with_file_name("update.json");
    let mut settings = UpdateSettings::load(&settings_path)?;
    if !settings.due(update::now()) {
        return Ok(false);
    }
    let executable = std::env::current_exe()?;
    let Ok(installation) = Installation::lock(&executable, true) else {
        return Ok(false);
    };
    // Re-read after taking the installation lock; another invocation may have checked already.
    settings = UpdateSettings::load(&settings_path)?;
    if !settings.due(update::now()) {
        return Ok(false);
    }
    settings.last_checked = Some(update::now());
    settings.save(&settings_path)?;
    let Some(available) = update::check(env!("CARGO_PKG_VERSION"), local, remote).await? else {
        return Ok(false);
    };
    available.install(&installation).await?;
    eprintln!("Updated rcodex to {}.", available.manifest.version);
    Ok(true)
}

fn restart_after_update() -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = std::process::Command::new(std::env::current_exe()?)
            .args(std::env::args_os().skip(1))
            .exec();
        Err(error).context("restart updated rcodex; run the command again")
    }
    #[cfg(not(unix))]
    anyhow::bail!("rcodex updated; run the command again")
}

async fn run_broker(api: &RelayApi, paths: &Paths) -> Result<()> {
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = BufWriter::new(tokio::io::stdout());
    let mut session = BrokerSession::default();
    loop {
        let Some(mut frame) = read_broker_frame(&mut input).await? else {
            return Ok(());
        };
        let decoded = decode_request(&frame);
        frame.fill(0);
        let request = match decoded {
            Ok(request) => request,
            Err(_) => {
                write_broker_response(
                    &mut output,
                    &BrokerResponse::error(0, BrokerErrorCode::InvalidRequest),
                )
                .await?;
                continue;
            }
        };
        let request_id = request.id();
        let action = match session.accept(request) {
            Ok(action) => action,
            Err(code) => {
                write_broker_response(&mut output, &BrokerResponse::error(request_id, code))
                    .await?;
                continue;
            }
        };
        match action {
            BrokerAction::Respond(response) => {
                write_broker_response(&mut output, &response).await?;
            }
            BrokerAction::Pair { id, pairing_code } => {
                let response = match pair_and_list_hosts(api, paths, pairing_code.as_str()).await {
                    Ok(hosts) => BrokerResponse::paired(id, hosts),
                    Err(code) => BrokerResponse::error(id, code),
                };
                write_broker_response(&mut output, &response).await?;
            }
            BrokerAction::ListHosts { id } => {
                let response = match list_broker_hosts(api, paths).await {
                    Ok(hosts) => BrokerResponse::hosts(id, hosts),
                    Err(code) => BrokerResponse::error(id, code),
                };
                write_broker_response(&mut output, &response).await?;
            }
            BrokerAction::OpenAppServer { id, environment_id } => {
                match open_remote_app_server(api, paths, &environment_id).await {
                    Ok(transport) => {
                        write_broker_response(
                            &mut output,
                            &BrokerResponse::ready(id, environment_id),
                        )
                        .await?;
                        drop(output);
                        return transport.bridge_stdio().await;
                    }
                    Err(code) => {
                        write_broker_response(&mut output, &BrokerResponse::error(id, code))
                            .await?;
                    }
                }
            }
        }
    }
}

async fn pair_and_list_hosts(
    api: &RelayApi,
    paths: &Paths,
    pairing_code: &str,
) -> std::result::Result<Vec<BrokerHost>, BrokerErrorCode> {
    let (state, _) = ensure_session(api, &paths.state)
        .await
        .map_err(|error| classify_broker_error(&error))?;
    api.pair_client(&state.enrollment.client_id, pairing_code)
        .await
        .map_err(|error| classify_broker_error(&error))?;
    broker_hosts_for_client(api, &state.enrollment.client_id).await
}

async fn list_broker_hosts(
    api: &RelayApi,
    paths: &Paths,
) -> std::result::Result<Vec<BrokerHost>, BrokerErrorCode> {
    let (state, _) = ensure_session(api, &paths.state)
        .await
        .map_err(|error| classify_broker_error(&error))?;
    broker_hosts_for_client(api, &state.enrollment.client_id).await
}

async fn broker_hosts_for_client(
    api: &RelayApi,
    client_id: &str,
) -> std::result::Result<Vec<BrokerHost>, BrokerErrorCode> {
    let environments = api
        .list_environments(Some(client_id))
        .await
        .map_err(|error| classify_broker_error(&error))?;
    if environments.len() > 100 {
        return Err(BrokerErrorCode::RelayUnavailable);
    }
    environments
        .into_iter()
        .map(BrokerHost::try_from)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| BrokerErrorCode::RelayUnavailable)
}

async fn open_remote_app_server(
    api: &RelayApi,
    paths: &Paths,
    environment_id: &str,
) -> std::result::Result<RelayTransport, BrokerErrorCode> {
    let local_version = inspect_stock_codex()
        .await
        .map_err(|_| BrokerErrorCode::IncompatibleVersion)?;
    let (state, session) = ensure_session(api, &paths.state)
        .await
        .map_err(|error| classify_broker_error(&error))?;
    let auth = api
        .auth()
        .await
        .map_err(|error| classify_broker_error(&error))?;
    let environments = api
        .list_environments(Some(&state.enrollment.client_id))
        .await
        .map_err(|error| classify_broker_error(&error))?;
    let environment = environments
        .iter()
        .find(|environment| environment.env_id == environment_id)
        .ok_or(BrokerErrorCode::HostNotFound)?;
    if !environment.online {
        return Err(BrokerErrorCode::HostOffline);
    }
    verify_remote_codex_version(&local_version, environment)
        .map_err(|_| BrokerErrorCode::IncompatibleVersion)?;
    RelayTransport::connect(&auth, &state.enrollment, &session, environment_id)
        .await
        .map_err(|error| classify_broker_error(&error))
}

fn classify_broker_error(error: &anyhow::Error) -> BrokerErrorCode {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("auth") || message.contains("login") || message.contains("account") {
        BrokerErrorCode::AuthenticationRequired
    } else if message.contains("enroll") || message.contains("keychain") {
        BrokerErrorCode::EnrollmentRequired
    } else if message.contains("version") || message.contains("pinned") {
        BrokerErrorCode::IncompatibleVersion
    } else {
        BrokerErrorCode::RelayUnavailable
    }
}

async fn read_broker_frame(reader: &mut BufReader<tokio::io::Stdin>) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    let read = reader
        .take((MAX_BROKER_FRAME_BYTES + 2) as u64)
        .read_until(b'\n', &mut frame)
        .await
        .context("read relay broker request")?;
    if read == 0 {
        return Ok(None);
    }
    if frame.len() > MAX_BROKER_FRAME_BYTES + usize::from(frame.ends_with(b"\n")) {
        anyhow::bail!("relay broker request exceeded the safety limit");
    }
    while matches!(frame.last(), Some(b'\n' | b'\r')) {
        frame.pop();
    }
    Ok(Some(frame))
}

async fn write_broker_response(
    writer: &mut BufWriter<tokio::io::Stdout>,
    response: &BrokerResponse,
) -> Result<()> {
    let bytes = serde_json::to_vec(response).context("serialize relay broker response")?;
    if bytes.len() > MAX_BROKER_FRAME_BYTES {
        anyhow::bail!("relay broker response exceeded the safety limit");
    }
    writer
        .write_all(&bytes)
        .await
        .context("write relay broker response")?;
    writer
        .write_all(b"\n")
        .await
        .context("finish relay broker response")?;
    writer.flush().await.context("flush relay broker response")
}

async fn run_remote_tui(
    api: &RelayApi,
    paths: &Paths,
    requested_device: Option<&str>,
    remote_cwd: Option<&std::path::Path>,
) -> Result<()> {
    let (state, session) = ensure_session(api, &paths.state).await?;
    let auth = api.auth().await?;
    let environments = api
        .list_environments(Some(&state.enrollment.client_id))
        .await?;
    let environment = select_environment(&environments, requested_device)?;
    let local = inspect_stock_codex().await?;
    let remote = environment
        .app_server_version
        .as_deref()
        .unwrap_or("unknown");
    match tokio::time::timeout(
        std::time::Duration::from_secs(45),
        automatic_update(paths, &local, remote),
    )
    .await
    {
        Ok(Ok(true)) => return restart_after_update(),
        Ok(Ok(false)) => {}
        Ok(Err(error)) => eprintln!("rcodex automatic update skipped: {error:#}"),
        Err(_) => {
            eprintln!("rcodex automatic update timed out; continuing with the installed version")
        }
    }
    let _session = Installation::lock(&std::env::current_exe()?, false)?;
    verify_remote_codex_version(&local, environment)?;
    let environment_id = environment.env_id.clone();
    let environment_name = environment.display_name().to_owned();
    let relay =
        RelayTransport::connect(&auth, &state.enrollment, &session, &environment_id).await?;
    let shim = LocalShim::bind().await?;
    let shim_url = shim.url()?;
    let shim_auth_token = shim.auth_token().to_owned();

    eprintln!("Connecting stock Codex TUI to {environment_name} through OpenAI's relay…");
    let mut command = tokio::process::Command::new("codex");
    command
        .args(codex_remote_args(&shim_url, remote_cwd))
        .env(SHIM_AUTH_TOKEN_ENV, shim_auth_token)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = command.spawn().context("launch stock Codex TUI")?;
    let bridge = shim.serve(relay);
    tokio::pin!(bridge);
    tokio::select! {
        result = &mut bridge => result.context("rcodex relay bridge stopped"),
        status = child.wait() => {
            let status = status.context("wait for stock Codex TUI")?;
            if status.success() {
                Ok(())
            } else {
                anyhow::bail!("stock Codex TUI exited with {status}")
            }
        }
        signal = tokio::signal::ctrl_c() => {
            signal.context("listen for interrupt")?;
            Ok(())
        }
    }
}

async fn inspect_stock_codex() -> Result<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new("codex")
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Codex version check timed out")??;
    if !output.status.success() {
        anyhow::bail!("stock Codex CLI could not report its version");
    }
    let version = parse_stock_codex_version(
        std::str::from_utf8(&output.stdout).context("Codex version is not UTF-8")?,
    )?;
    let help = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new("codex")
            .arg("--help")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Codex help check timed out")??;
    if !help.status.success() {
        anyhow::bail!("stock Codex CLI could not report its supported options");
    }
    verify_stock_codex_capabilities(
        std::str::from_utf8(&help.stdout).context("Codex help is not UTF-8")?,
    )?;
    Ok(version)
}

struct Paths {
    auth: PathBuf,
    state: PathBuf,
}

impl Paths {
    fn resolve() -> Result<Self> {
        let user_home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set")?;
        let codex_home = std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| user_home.join(".codex"));
        let rcodex_home = std::env::var_os("RCODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| user_home.join(".rcodex"));
        Ok(Self {
            auth: codex_home.join("auth.json"),
            state: rcodex_home.join("state.json"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn pairing_code_can_be_read_from_a_hidden_prompt() {
        let cli = Cli::try_parse_from(["rcodex", "pair"]).unwrap();
        let Some(Command::Pair { code }) = cli.command else {
            panic!("pair command was not parsed");
        };
        assert!(code.is_none());
    }
}
