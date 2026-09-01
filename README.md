# rcodex

`rcodex` runs the stock Codex terminal interface against a paired remote Codex
host through OpenAI's relay. It does not use SSH, install a second TUI, or
replace the `codex` executable.

```text
stock Codex TUI
      │ authenticated loopback WebSocket
      ▼
   rcodex ───── OpenAI relay ───── paired Codex host
```

> [!WARNING]
> `rcodex` is unofficial experimental software. It is not affiliated with or
> supported by OpenAI. Although Codex App Server and remote TUI connections are
> documented, controller enrollment currently relies on observed,
> undocumented ChatGPT relay and OAuth behavior. Those interfaces can change or
> stop working without notice. Review the code before using it with your
> account.

## Current compatibility

- The controller currently requires macOS because its signing key is stored as
  a non-exportable key in the login Keychain.
- The local Codex CLI and remote App Server must both be exactly `0.152.0`.
- The remote host must already be configured and online in Codex Remote
  Control.
- A ChatGPT-authenticated Codex CLI installation is required. API-key-only
  authentication is not supported.

The exact version check is intentional while the relay protocol remains
experimental. See OpenAI's documentation for the supported
[App Server remote transport](https://developers.openai.com/codex/app-server)
and the official [Remote connections](https://developers.openai.com/codex/remote-connections)
workflow.

## Install

Install Rust and the stock Codex CLI, then authenticate Codex with ChatGPT:

```sh
codex login
codex --version
cargo install --locked --path .
```

`codex --version` must currently print `codex-cli 0.152.0`.

## Enroll and pair

Enrollment creates a separate controller identity for `rcodex`; it does not
replace a Claude installation or another account on the remote host.

```sh
rcodex enroll
```

The command opens a browser for a short account authorization. On the remote
Codex host, obtain an eight-character pairing code:

```sh
codex remote-control pair
```

Enter that code on the controller Mac:

```sh
rcodex pair
rcodex devices
```

The hidden prompt keeps the short-lived pairing code out of shell history. You
can also pass it as an argument when using a history-free automation context.

## Run

When exactly one paired host is online:

```sh
rcodex
```

Choose a host or remote working directory explicitly:

```sh
rcodex --device ENV_ID -C /srv/project
```

Useful diagnostics:

```sh
rcodex devices
rcodex session
rcodex probe --device ENV_ID
```

## Uninstall and revoke

Revoke the remote controller identity, delete the Keychain key, and remove
local `rcodex` state before uninstalling:

```sh
rcodex unenroll
cargo uninstall rcodex
```

`unenroll` is safe to retry if the server already removed the identity. If it
reports a local Keychain error, keep the state file and retry instead of
deleting `~/.rcodex` manually.

## Security and data

- `rcodex` reads the stock Codex ChatGPT session from
  `${CODEX_HOME:-~/.codex}/auth.json`. It rejects files accessible by group or
  other users.
- The private controller signing key stays in the macOS login Keychain and is
  created as non-exportable. `~/.rcodex/state.json` contains public enrollment
  metadata, not access or refresh tokens.
- Each invocation generates a 256-bit bearer token for its loopback WebSocket.
  The token is passed only through the child Codex process environment, not its
  command line.
- Relay frames and reassembled messages have fixed size and concurrency limits.
- Never expose the loopback WebSocket, copy `auth.json`, commit `.env` files, or
  run `rcodex` as root.

Report vulnerabilities according to [SECURITY.md](SECURITY.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo audit
```

The real Keychain integration test is ignored by default because macOS may
prompt and the test creates and deletes a login Keychain item. Run it only on a
disposable test identity or after reviewing it:

```sh
cargo test --test device_security macos_keychain_key_can_sign_but_is_not_exported -- --ignored
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [RELEASING.md](RELEASING.md) for the
full workflows.

## License and trademarks

The project is available under the [MIT License](LICENSE). OpenAI, ChatGPT, and
Codex are trademarks of their respective owner. Use of those names describes
compatibility only and does not imply endorsement.
