//! Opt-in, attestation-verified updates. This module never updates Codex itself.
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub const REPOSITORY: &str = "Typiqally/rcodex";
const MANIFEST_NAME: &str = "rcodex-update.json";
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAsset {
    pub name: String,
    pub target: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub version: String,
    pub codex_versions: Vec<String>,
    pub assets: Vec<ReleaseAsset>,
}

fn stable_version(value: &str) -> Result<Version> {
    let version = Version::parse(value).context("invalid stable version")?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        bail!("updates require a stable version without build metadata");
    }
    Ok(version)
}

impl ReleaseManifest {
    pub fn validate(&self) -> Result<()> {
        stable_version(&self.version)?;
        if self.schema_version != 1
            || self.codex_versions.is_empty()
            || self.codex_versions.len() > 32
            || self.assets.is_empty()
            || self.assets.len() > 2
        {
            bail!("invalid update manifest shape or schema version");
        }
        for version in &self.codex_versions {
            stable_version(version)?;
        }
        let mut targets = std::collections::HashSet::new();
        for asset in &self.assets {
            if !matches!(
                asset.target.as_str(),
                "aarch64-apple-darwin" | "x86_64-apple-darwin"
            ) || !targets.insert(&asset.target)
                || asset.name != format!("rcodex-{}-{}", self.version, asset.target)
                || asset.sha256.len() != 64
                || !asset
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || asset.size == 0
                || asset.size > MAX_BINARY_BYTES
            {
                bail!("invalid or duplicate update asset");
            }
        }
        Ok(())
    }

    pub fn select(
        &self,
        current: &str,
        local: &str,
        remote: &str,
        target: &str,
    ) -> Result<Option<&ReleaseAsset>> {
        self.validate()?;
        if stable_version(&self.version)? <= stable_version(current)?
            || local != remote
            || !self.codex_versions.iter().any(|version| version == local)
        {
            return Ok(None);
        }
        Ok(self.assets.iter().find(|asset| asset.target == target))
    }
}

pub fn parse_codex_version(output: &str) -> Result<String> {
    let version = output
        .trim()
        .strip_prefix("codex-cli ")
        .context("unrecognized Codex version output")?;
    stable_version(version)?;
    Ok(version.to_owned())
}

pub async fn local_codex_version() -> Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("codex")
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Codex version check timed out")??;
    if !output.status.success() {
        bail!("Codex could not report its version");
    }
    parse_codex_version(std::str::from_utf8(&output.stdout)?)
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSettings {
    pub enabled: bool,
    pub last_checked: Option<u64>,
}

impl UpdateSettings {
    pub fn load(path: &Path) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
            Ok(_) => {
                regular_file(path)?;
                if fs::metadata(path)?.len() > MAX_METADATA_BYTES {
                    bail!("update settings too large");
                }
                serde_json::from_slice(&fs::read(path)?).context("parse update settings")
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path.parent().context("update settings have no parent")?;
        fs::create_dir_all(parent)?;
        reject_symlink(path)?;
        atomic_write(path, &serde_json::to_vec_pretty(self)?, 0o600)
    }

    pub fn due(&self, now: u64) -> bool {
        self.enabled
            && self
                .last_checked
                .is_none_or(|last| now.saturating_sub(last) >= 86_400)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!("update path is not a regular file: {}", path.display())
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    Ok(())
}

fn regular_file(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    if !path.is_file() {
        bail!("update file does not exist: {}", path.display());
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut temporary = NamedTempFile::new_in(path.parent().context("update path has no parent")?)?;
    temporary.write_all(bytes)?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    #[cfg(not(unix))]
    let _ = mode;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .context("atomically install update file")?;
    File::open(path.parent().context("update path has no parent")?)?.sync_all()?;
    Ok(())
}

/// Shared locks span TUI/broker sessions; replacement requires an exclusive lock.
pub struct Installation {
    executable: PathBuf,
    _lock: File,
    exclusive: bool,
}

impl Installation {
    pub fn lock(executable: &Path, exclusive: bool) -> Result<Self> {
        regular_file(executable)?;
        let lock_path = executable.with_extension("update-lock");
        reject_symlink(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let lock = options.open(lock_path).context("open installation lock")?;
        if exclusive {
            FileExt::try_lock_exclusive(&lock)
        } else {
            FileExt::try_lock_shared(&lock)
        }
        .context("rcodex installation is in use; retry between sessions")?;
        Ok(Self {
            executable: executable.to_owned(),
            _lock: lock,
            exclusive,
        })
    }

    pub fn backup_path(&self) -> PathBuf {
        self.executable.with_extension("previous")
    }

    pub fn replace(&self, bytes: &[u8], asset: &ReleaseAsset) -> Result<()> {
        if !self.exclusive {
            bail!("installation requires an exclusive lock");
        }
        if bytes.len() as u64 != asset.size
            || format!("{:x}", Sha256::digest(bytes)) != asset.sha256
        {
            bail!("update binary failed size or SHA-256 verification");
        }
        regular_file(&self.executable)?;
        reject_symlink(&self.backup_path())?;
        atomic_write(&self.backup_path(), &fs::read(&self.executable)?, 0o700)?;
        atomic_write(&self.executable, bytes, 0o755)
    }

    pub fn rollback(&self) -> Result<()> {
        if !self.exclusive {
            bail!("rollback requires an exclusive lock");
        }
        regular_file(&self.backup_path())?;
        regular_file(&self.executable)?;
        atomic_write(&self.executable, &fs::read(self.backup_path())?, 0o755)
    }
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
}

async fn download(client: &reqwest::Client, url: &str, limit: u64) -> Result<Vec<u8>> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        bail!("update download exceeds size limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() as u64 + chunk.len() as u64 > limit {
            bail!("update download exceeds size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn verify_attestation(path: &Path, tag: &str) -> Result<()> {
    let status = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new("gh")
            .args(["attestation", "verify"])
            .arg(path)
            .args([
                "--hostname",
                "github.com",
                "--repo",
                REPOSITORY,
                "--signer-workflow",
                "Typiqally/rcodex/.github/workflows/release.yml",
                "--source-ref",
                &format!("refs/tags/{tag}"),
                "--deny-self-hosted-runners",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .context("GitHub attestation verification timed out")?
    .context("install GitHub CLI (`gh`) and authenticate before enabling updates")?;
    if !status.success() {
        bail!(
            "GitHub attestation verification failed; check `gh auth status` and release provenance"
        );
    }
    Ok(())
}

trait VerifyProvenance {
    async fn verify(&self, path: &Path, tag: &str) -> Result<()>;
}

struct GitHubVerifier;

impl VerifyProvenance for GitHubVerifier {
    async fn verify(&self, path: &Path, tag: &str) -> Result<()> {
        verify_attestation(path, tag).await
    }
}

struct Repository<V> {
    client: reqwest::Client,
    releases_url: String,
    asset_base: String,
    verifier: V,
}

pub struct AvailableUpdate {
    pub manifest: ReleaseManifest,
    pub asset: ReleaseAsset,
    repository: Repository<GitHubVerifier>,
}

pub fn target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        _ => bail!("binary updates are available only for macOS"),
    }
}

pub async fn check(current: &str, local: &str, remote: &str) -> Result<Option<AvailableUpdate>> {
    let target = target()?;
    let repository = Repository {
        client: reqwest::Client::builder()
            .https_only(true)
            .user_agent("rcodex-updater")
            .timeout(Duration::from_secs(15))
            .build()?,
        releases_url: format!("https://api.github.com/repos/{REPOSITORY}/releases?per_page=20"),
        asset_base: format!("https://github.com/{REPOSITORY}/releases/download"),
        verifier: GitHubVerifier,
    };
    Ok(repository
        .find(current, local, remote, target)
        .await?
        .map(|(manifest, asset)| AvailableUpdate {
            manifest,
            asset,
            repository,
        }))
}

impl<V: VerifyProvenance> Repository<V> {
    async fn find(
        &self,
        current: &str,
        local: &str,
        remote: &str,
        target: &str,
    ) -> Result<Option<(ReleaseManifest, ReleaseAsset)>> {
        let current_version = stable_version(current)?;
        if local != remote {
            bail!(
                "local Codex {local} and remote Codex {remote} must match before updating rcodex"
            );
        }
        let bytes = download(&self.client, &self.releases_url, MAX_METADATA_BYTES).await?;
        let mut releases: Vec<GitHubRelease> = serde_json::from_slice(&bytes)?;
        if releases.len() > 20 {
            bail!("too many releases in update response");
        }
        releases.retain(|release| {
            !release.draft
                && !release.prerelease
                && release
                    .tag_name
                    .strip_prefix('v')
                    .and_then(|value| stable_version(value).ok())
                    .is_some_and(|version| version > current_version)
        });
        releases.sort_by_cached_key(|release| {
            std::cmp::Reverse(Version::parse(&release.tag_name[1..]).expect("validated version"))
        });
        for release in releases {
            if !release
                .assets
                .iter()
                .any(|asset| asset.name == MANIFEST_NAME)
            {
                continue;
            }
            let bytes = download(
                &self.client,
                &format!("{}/{}/{MANIFEST_NAME}", self.asset_base, release.tag_name),
                MAX_METADATA_BYTES,
            )
            .await?;
            self.verify_bytes(&bytes, &release.tag_name).await?;
            let manifest: ReleaseManifest = serde_json::from_slice(&bytes)?;
            if release.tag_name != format!("v{}", manifest.version) {
                bail!("signed manifest does not match release tag");
            }
            if let Some(asset) = manifest.select(current, local, remote, target)? {
                let asset = asset.clone();
                if !release
                    .assets
                    .iter()
                    .any(|listed| listed.name == asset.name)
                {
                    bail!("signed binary is missing from release");
                }
                return Ok(Some((manifest, asset)));
            }
        }
        Ok(None)
    }

    async fn verify_bytes(&self, bytes: &[u8], tag: &str) -> Result<()> {
        let mut file = NamedTempFile::new()?;
        file.write_all(bytes)?;
        file.flush()?;
        self.verifier.verify(file.path(), tag).await
    }

    async fn install(
        &self,
        manifest: &ReleaseManifest,
        asset: &ReleaseAsset,
        installation: &Installation,
    ) -> Result<()> {
        let tag = format!("v{}", manifest.version);
        let bytes = download(
            &self.client,
            &format!("{}/{tag}/{}", self.asset_base, asset.name),
            asset.size,
        )
        .await?;
        self.verify_bytes(&bytes, &tag).await?;
        installation.replace(&bytes, asset)
    }
}

impl AvailableUpdate {
    pub async fn install(&self, installation: &Installation) -> Result<()> {
        self.repository
            .install(&self.manifest, &self.asset, installation)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    struct Server {
        base: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve(routes: HashMap<String, (u16, Vec<u8>, bool)>) -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut first = String::new();
                reader.read_line(&mut first).await.unwrap();
                let path = first.split_whitespace().nth(1).unwrap_or("").to_owned();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).await.unwrap();
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                }
                let missing = (404, Vec::new(), true);
                let (status, bytes, length) = routes.get(&path).unwrap_or(&missing);
                let length = if *length {
                    format!("Content-Length: {}\r\n", bytes.len())
                } else {
                    String::new()
                };
                let header = format!("HTTP/1.1 {status} Test\r\n{length}Connection: close\r\n\r\n");
                let mut stream = reader.into_inner();
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(bytes).await;
            }
        });
        Server { base, task }
    }

    struct TestVerifier {
        manifest_ok: bool,
        binary_ok: bool,
    }

    impl VerifyProvenance for TestVerifier {
        async fn verify(&self, path: &Path, tag: &str) -> Result<()> {
            assert!(tag.starts_with('v'));
            let bytes = fs::read(path)?;
            let allowed = if bytes.starts_with(b"{") {
                self.manifest_ok
            } else {
                self.binary_ok
            };
            if !allowed {
                bail!("test provenance verification rejected artifact");
            }
            Ok(())
        }
    }

    fn fixture() -> (Value, Value) {
        let manifest = json!({"schema_version": 1, "version": "0.2.0", "codex_versions": ["0.153.0"],
            "assets": [{"name": "rcodex-0.2.0-aarch64-apple-darwin", "target": "aarch64-apple-darwin",
                "size": 10, "sha256": format!("{:x}", Sha256::digest(b"new binary"))}]});
        let release = json!({"tag_name": "v0.2.0", "draft": false, "prerelease": false,
            "assets": [{"name": MANIFEST_NAME}, {"name": "rcodex-0.2.0-aarch64-apple-darwin"}]});
        (manifest, release)
    }

    async fn repository(
        manifest: Value,
        releases: Value,
        binary: &[u8],
        manifest_ok: bool,
        binary_ok: bool,
    ) -> (Server, Repository<TestVerifier>) {
        let server = serve(HashMap::from([
            (
                "/releases".into(),
                (200, serde_json::to_vec(&releases).unwrap(), true),
            ),
            (
                format!("/download/v0.2.0/{MANIFEST_NAME}"),
                (200, serde_json::to_vec(&manifest).unwrap(), true),
            ),
            (
                "/download/v0.2.0/rcodex-0.2.0-aarch64-apple-darwin".into(),
                (200, binary.to_vec(), true),
            ),
        ]))
        .await;
        let repository = Repository {
            client: reqwest::Client::new(),
            releases_url: format!("{}/releases", server.base),
            asset_base: format!("{}/download", server.base),
            verifier: TestVerifier {
                manifest_ok,
                binary_ok,
            },
        };
        (server, repository)
    }

    async fn find(
        repo: &Repository<TestVerifier>,
    ) -> Result<Option<(ReleaseManifest, ReleaseAsset)>> {
        repo.find("0.1.0", "0.153.0", "0.153.0", "aarch64-apple-darwin")
            .await
    }

    #[tokio::test]
    async fn downloaded_release_can_be_verified_installed_and_rolled_back() {
        let (manifest, release) = fixture();
        let (_server, repo) =
            repository(manifest, json!([release]), b"new binary", true, true).await;
        let (manifest, asset) = find(&repo).await.unwrap().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("rcodex");
        fs::write(&executable, b"old binary").unwrap();
        let installation = Installation::lock(&executable, true).unwrap();
        repo.install(&manifest, &asset, &installation)
            .await
            .unwrap();
        assert_eq!(fs::read(&executable).unwrap(), b"new binary");
        installation.rollback().unwrap();
        assert_eq!(fs::read(&executable).unwrap(), b"old binary");
    }

    #[tokio::test]
    async fn rejected_provenance_never_changes_the_executable() {
        for (manifest_ok, binary_ok) in [(false, true), (true, false)] {
            let (manifest, release) = fixture();
            let (_server, repo) = repository(
                manifest,
                json!([release]),
                b"new binary",
                manifest_ok,
                binary_ok,
            )
            .await;
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("rcodex");
            fs::write(&executable, b"old binary").unwrap();
            let installation = Installation::lock(&executable, true).unwrap();
            if manifest_ok {
                let (manifest, asset) = find(&repo).await.unwrap().unwrap();
                assert!(
                    repo.install(&manifest, &asset, &installation)
                        .await
                        .is_err()
                );
            } else {
                assert!(find(&repo).await.is_err());
            }
            assert_eq!(fs::read(&executable).unwrap(), b"old binary");
            assert!(!installation.backup_path().exists());
        }
    }

    #[tokio::test]
    async fn wrong_digest_short_and_oversized_binaries_leave_old_installation() {
        for binary in [b"bad binary".as_slice(), b"short", b"oversized binary"] {
            let (manifest, release) = fixture();
            let (_server, repo) = repository(manifest, json!([release]), binary, true, true).await;
            let (manifest, asset) = find(&repo).await.unwrap().unwrap();
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("rcodex");
            fs::write(&executable, b"old binary").unwrap();
            let installation = Installation::lock(&executable, true).unwrap();
            assert!(
                repo.install(&manifest, &asset, &installation)
                    .await
                    .is_err()
            );
            assert_eq!(fs::read(&executable).unwrap(), b"old binary");
        }
    }

    #[tokio::test]
    async fn draft_prerelease_old_and_unsigned_candidates_are_ignored() {
        let (manifest, release) = fixture();
        let mut draft = release.clone();
        draft["draft"] = json!(true);
        let mut prerelease = release.clone();
        prerelease["prerelease"] = json!(true);
        let mut old = release.clone();
        old["tag_name"] = json!("v0.1.0");
        let mut bad_tag = release.clone();
        bad_tag["tag_name"] = json!("../../bad");
        let mut unsigned = release;
        unsigned["assets"] = json!([]);
        let (_server, repo) = repository(
            manifest,
            json!([draft, prerelease, old, bad_tag, unsigned]),
            b"",
            false,
            false,
        )
        .await;
        assert!(find(&repo).await.unwrap().is_none());
        assert!(
            repo.find("invalid", "0.153.0", "0.153.0", "aarch64-apple-darwin")
                .await
                .is_err()
        );
        assert!(
            repo.find("0.1.0", "0.153.0", "0.154.0", "aarch64-apple-darwin")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn incompatible_manifest_is_skipped_but_wrong_tag_and_missing_asset_fail() {
        let (manifest, release) = fixture();
        let mut incompatible = manifest.clone();
        incompatible["codex_versions"] = json!(["0.154.0"]);
        let (_server, repo) =
            repository(incompatible, json!([release.clone()]), b"", true, true).await;
        assert!(find(&repo).await.unwrap().is_none());
        let mut wrong = manifest.clone();
        wrong["version"] = json!("0.3.0");
        let (_server, repo) = repository(wrong, json!([release.clone()]), b"", true, true).await;
        assert!(
            find(&repo)
                .await
                .unwrap_err()
                .to_string()
                .contains("release tag")
        );
        let mut missing = release;
        missing["assets"] = json!([{ "name": MANIFEST_NAME }]);
        let (_server, repo) = repository(manifest, json!([missing]), b"", true, true).await;
        assert!(
            find(&repo)
                .await
                .unwrap_err()
                .to_string()
                .contains("missing")
        );
    }

    #[tokio::test]
    async fn downloads_enforce_limits_with_and_without_content_length() {
        for length in [true, false] {
            let server = serve(HashMap::from([(
                "/large".into(),
                (200, vec![0; 100], length),
            )]))
            .await;
            assert!(
                download(
                    &reqwest::Client::new(),
                    &format!("{}/large", server.base),
                    10
                )
                .await
                .is_err()
            );
            assert!(
                download(
                    &reqwest::Client::new(),
                    &format!("{}/missing", server.base),
                    10
                )
                .await
                .is_err()
            );
        }
    }
}
