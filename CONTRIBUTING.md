# Contributing

Thanks for helping improve `rcodex`. Keep changes narrow, explain any observed
wire behavior without including real account or host data, and add a regression
test for every bug fix.

## Local checks

Use stable Rust and run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo audit
cargo package --allow-dirty
```

Some tests bind temporary loopback ports. The real macOS Keychain test is
ignored by default and must remain opt-in. Do not enable it in CI or run it on a
user's login Keychain without explicit consent.

## Pull requests

- Do not commit credentials, account IDs, environment IDs, IP addresses, or
  real hostnames. Use obvious `example-*` fixtures.
- Keep authentication tokens out of command-line arguments and logs.
- Bound all data accepted from the relay before allocating memory.
- Preserve unknown fields when reading and writing Codex-owned files.
- Document protocol assumptions and compatibility changes.
- Update `CHANGELOG.md` for user-visible changes.

By contributing, you agree that your contribution is licensed under the MIT
License.
