use anyhow::{Context, Result, bail};

use crate::api::RemoteEnvironment;

const REQUIRED_REMOTE_OPTIONS: [&str; 2] = ["--remote", "--remote-auth-token-env"];

pub fn parse_stock_codex_version(version_output: &str) -> Result<String> {
    let output = version_output.trim();
    if output.chars().any(char::is_control) {
        bail!("stock Codex CLI reported a malformed version");
    }
    let mut fields = output.split_ascii_whitespace();
    if fields.next() != Some("codex-cli") {
        bail!("stock Codex CLI version must start with `codex-cli`");
    }
    let version = fields
        .next()
        .context("stock Codex CLI did not report a version")?;
    Ok(parse_version_token(version)
        .context("stock Codex CLI reported an invalid version")?
        .to_owned())
}

pub fn verify_stock_codex_capabilities(help_output: &str) -> Result<()> {
    let missing = REQUIRED_REMOTE_OPTIONS
        .into_iter()
        .filter(|option| !help_has_option(help_output, option))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "stock Codex CLI does not expose the required remote terminal options: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

pub fn verify_remote_codex_version(
    local_version: &str,
    environment: &RemoteEnvironment,
) -> Result<()> {
    let local_version =
        parse_version_token(local_version).context("local Codex CLI version is invalid")?;
    let remote_output = environment.app_server_version.as_deref().with_context(|| {
        format!(
            "remote host {} does not report a Codex App Server version",
            environment.display_name()
        )
    })?;
    let remote_version = parse_version_token(remote_output).with_context(|| {
        format!(
            "remote host {} reported an invalid Codex App Server version",
            environment.display_name()
        )
    })?;
    if remote_version != local_version {
        bail!(
            "remote host {} runs remote Codex App Server {remote_version}, but PATH provides local Codex CLI {local_version}; update the older installation so both versions match",
            environment.display_name(),
        );
    }
    Ok(())
}

fn parse_version_token(value: &str) -> Result<&str> {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        bail!("version contains control characters");
    }
    let version = value
        .split_ascii_whitespace()
        .next()
        .context("version is empty")?;
    if !version.starts_with(|character: char| character.is_ascii_digit())
        || !version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".+-".contains(character))
    {
        bail!("version token is malformed");
    }
    Ok(version)
}

fn help_has_option(help_output: &str, expected: &str) -> bool {
    help_output
        .lines()
        .flat_map(|line| line.split_ascii_whitespace())
        .any(|token| token == expected)
}
