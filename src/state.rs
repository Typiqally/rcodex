use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::protocol::EnrollmentRecord;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControllerState {
    pub enrollment: EnrollmentRecord,
}

pub fn load_controller_state(path: &Path) -> Result<ControllerState> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect rcodex state file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "rcodex state path is not a regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("rcodex state file must not be accessible by group or others");
    }
    let bytes = fs::read(path).with_context(|| format!("read rcodex state {}", path.display()))?;
    serde_json::from_slice(&bytes).context("parse rcodex state")
}

pub fn save_controller_state(path: &Path, state: &ControllerState) -> Result<()> {
    let parent = path
        .parent()
        .context("rcodex state path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create rcodex state directory {}", parent.display()))?;

    let temporary = parent.join(format!(".state-{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(state).context("serialize rcodex state")?;
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create temporary rcodex state {}", temporary.display()))?;
        file.write_all(&bytes).context("write rcodex state")?;
        file.write_all(b"\n").context("finish rcodex state")?;
        file.sync_all().context("flush rcodex state")?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("protect rcodex state")?;
        fs::rename(&temporary, path)
            .with_context(|| format!("install rcodex state {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn delete_controller_state(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("delete rcodex state {}", path.display())),
    }
}
