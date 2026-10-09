# Releasing

`rcodex` began inside a larger local workspace. Public history must contain
only the `rcodex` project; never publish the parent Workspace repository or its
history.

## Checklist

1. Confirm the source and documentation still label the private relay
   integration as unofficial and experimental.
2. Update `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, and the compatibility
   section in `README.md`.
3. Run the complete verification set:

   ```sh
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-targets
   cargo audit
   cargo package --allow-dirty
   ```

4. Scan the working tree and all history intended for publication for secrets,
   private IPs, account IDs, environment IDs, and real hostnames.
5. Verify that the public repository is a standalone export containing only
   this directory and a clean, intentional history.
6. Review the packaged file list and test installation from that package in a
   temporary directory.
7. Create a signed `vMAJOR.MINOR.PATCH` tag and publish release notes from the
   matching changelog entry.

Do not publish to crates.io: `publish = false` is intentional while the project
depends on undocumented upstream behavior.

## Signed binary releases

The `Signed macOS release` workflow builds Apple Silicon and Intel binaries,
writes `rcodex-update.json` with the last validated Codex version, byte sizes,
and SHA-256 digests, and signs all three artifacts using GitHub/Sigstore build
attestations. No persistent signing-key secret is needed. This setup requires a
public repository (or an Enterprise plan for private-repository attestations).
Attestations establish provenance; they are not Apple notarization.

After the checklist above, personally test the tagged build on a dedicated
authenticated Mac and paired host running the validated Codex version. Exercise
enrollment, session refresh, relay initialization, a stock TUI task, cancellation,
and reconnect. Keep real account data and credentials out of public CI. The
current workflow records your confirmation; it does not run live relay tests or
set up a dedicated runner.

Push the signed tag, then dispatch the workflow **at that tag**, after both
personal and live relay testing pass:

```sh
gh workflow run release.yml --ref vMAJOR.MINOR.PATCH \
  -f manual_test_confirmed=true -f live_relay_validated=true
```

The tag must match `Cargo.toml`. Dispatching from `main`, or leaving either
confirmation false, fails before building. The job reruns formatting, linting,
tests, dependency audit, and package verification. Publishing creates a draft,
uploads every asset, and then publishes it. If publication fails, inspect and
remove the incomplete draft before rerunning; never replace assets on an already
published release. The updater only accepts stable releases newer than itself,
so increment the rcodex package version for each update.

Until the first attested binary release is published, source-installed clients
can enable the updater but will find no eligible update. The daily compatibility
workflow produces evidence proposals only. A maintainer must validate relay
behavior, update the validation baseline and related tests/docs, and obtain personal
test sign-off for the changed runtime before shipping support for a new Codex
version.

Manual updater test before the first release:

- On a disposable installation, enable and disable updates; verify `update.json`
  reflects each action without changing enrollment or Codex authentication.
- Against an attested newer test release, check/install with matching local and
  remote versions; confirm the executable changes and the backup remains usable.
- Start a TUI session; confirm another updater cannot replace its executable.
  After closing the session, roll back and confirm automatic updates are disabled.

- [ ] I personally tested the updater and approve releasing this revision.
