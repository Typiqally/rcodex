use anyhow::{Result, bail};

use crate::api::RemoteEnvironment;

pub const SUPPORTED_CODEX_VERSION: &str = "0.152.0";

pub fn verify_stock_codex_version(version_output: &str) -> Result<()> {
    let expected = format!("codex-cli {SUPPORTED_CODEX_VERSION}");
    if version_output.trim() != expected {
        bail!(
            "rcodex is pinned to {expected}, but PATH provides {}",
            version_output.trim()
        );
    }
    Ok(())
}

pub fn verify_remote_codex_version(environment: &RemoteEnvironment) -> Result<()> {
    if environment.app_server_version.as_deref() != Some(SUPPORTED_CODEX_VERSION) {
        bail!(
            "remote host {} runs Codex {}; rcodex is pinned to {}",
            environment.display_name(),
            environment
                .app_server_version
                .as_deref()
                .unwrap_or("unknown"),
            SUPPORTED_CODEX_VERSION
        );
    }
    Ok(())
}
