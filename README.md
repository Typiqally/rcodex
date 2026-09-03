# rcodex — remote control for OpenAI Codex CLI

`rcodex` is an unofficial macOS command-line client for connecting the stock
OpenAI Codex CLI terminal UI (TUI) to a paired remote Codex host. It lets you
run the official Codex terminal locally while Codex works with the files,
shell, tools, and compute on another development machine through OpenAI's
relay.

Unlike a custom web interface or SSH wrapper, `rcodex` does not replace the
`codex` executable, install a second TUI, or expose Codex App Server directly
to the public internet.

```text
stock Codex TUI
      │ authenticated loopback WebSocket
      ▼
   rcodex ───── OpenAI relay ───── paired Codex host
```

## What rcodex provides

- The familiar stock Codex CLI and terminal UI on your local Mac.
- Terminal access to a computer already paired with Codex Remote Control.
- Remote development from a selected working directory on the Codex host.
- An authenticated loopback WebSocket bridge to OpenAI's relay, with no direct
  inbound connection to the remote machine.

> [!WARNING]
> `rcodex` is unofficial experimental software. It is not affiliated with or
> supported by OpenAI. Although Codex App Server and remote terminal UI
> connections are documented, controller enrollment currently relies on
> observed, undocumented ChatGPT relay and OAuth behavior. Those interfaces can
> change or stop working without notice. Review the code before using it with
> your account.

## Current compatibility

- The controller currently requires macOS because its signing key is stored as
  a non-exportable key in the login Keychain.
- The local Codex CLI must expose the `--remote` and
  `--remote-auth-token-env` terminal options.
- The local Codex CLI and remote App Server must report the same version.
- The remote host must already be configured and online in Codex Remote
  Control.
- A ChatGPT-authenticated Codex CLI installation is required. API-key-only
  authentication is not supported.

`rcodex` does not pin a particular Codex release. It checks capabilities and
local/remote version parity at runtime, so matching future releases work
without an `rcodex` update. Mismatched releases are rejected because the
transport remains experimental; update the older Codex installation so both
versions match. See OpenAI's documentation for the supported
[App Server remote transport](https://developers.openai.com/codex/app-server)
and the official [Remote connections](https://developers.openai.com/codex/remote-connections)
workflow.

## Install

Install Rust, then install the latest OpenAI Codex CLI release from npm and
authenticate with ChatGPT:

```sh
npm install -g @openai/codex@latest
codex login
codex --version
cargo install --locked --path .
```

Install or update Codex on the remote host at the same time so its App Server
version matches the local CLI. See the official
[Codex CLI guide](https://developers.openai.com/codex/cli/) for platform setup
and authentication options.

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

## Codex remote-control FAQ

### Can I use Codex CLI with a remote development machine?

Yes. `rcodex` keeps the official Codex CLI terminal interface on your Mac and
connects it to a compatible, paired Codex host. Commands and tools then run in
the remote working directory you select.

### Is rcodex a Codex SSH client?

No. `rcodex` connects to a host already registered with Codex Remote Control
through OpenAI's relay. For the supported SSH-based workflow, use OpenAI's
[Remote connections](https://developers.openai.com/codex/remote-connections)
documentation.

### Does rcodex include or replace the OpenAI Codex CLI?

No. The official `codex` executable must already be installed. `rcodex`
checks its version, starts its stock terminal UI, and bridges that session to
the selected remote Codex App Server.

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
Codex are trademarks of their respective owners. Use of those names describes
compatibility only and does not imply endorsement.
