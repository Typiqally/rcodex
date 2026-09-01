use std::{path::PathBuf, process::Stdio};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rcodex::{
    api::RelayApi,
    compatibility::{verify_remote_codex_version, verify_stock_codex_version},
    controller::{enroll, ensure_session},
    shim::{LocalShim, SHIM_AUTH_TOKEN_ENV, codex_remote_args, select_environment},
    state::load_controller_state,
    transport::RelayTransport,
};
use serde_json::json;

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
    }
    Ok(())
}

async fn run_remote_tui(
    api: &RelayApi,
    paths: &Paths,
    requested_device: Option<&str>,
    remote_cwd: Option<&std::path::Path>,
) -> Result<()> {
    ensure_stock_codex_version().await?;
    let (state, session) = ensure_session(api, &paths.state).await?;
    let auth = api.auth().await?;
    let environments = api
        .list_environments(Some(&state.enrollment.client_id))
        .await?;
    let environment = select_environment(&environments, requested_device)?;
    verify_remote_codex_version(environment)?;
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

async fn ensure_stock_codex_version() -> Result<()> {
    let output = tokio::process::Command::new("codex")
        .arg("--version")
        .output()
        .await
        .context("run stock Codex CLI; ensure `codex` is on PATH")?;
    if !output.status.success() {
        anyhow::bail!("stock Codex CLI could not report its version");
    }
    let version = String::from_utf8(output.stdout).context("stock Codex version is not UTF-8")?;
    verify_stock_codex_version(&version)
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
