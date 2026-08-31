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
