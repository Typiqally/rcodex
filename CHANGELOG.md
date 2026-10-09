# Changelog

All notable changes to this project will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Companion-project links to rclaude and a shared maintenance checklist for
  publishing, security, and broker conventions.
- Opt-in daily signed binary updates, compatibility-aware release selection,
  active-session installation locks, and rollback that disables auto-updates.
- Daily upstream Codex CLI/schema checks with deduplicated draft evidence PRs
  and failure issues; compatibility still requires live relay validation.
- Apple Silicon and Intel release workflow with signed GitHub attestations and
  explicit personal/live test confirmation before publication.
- Authenticated per-run loopback bridge for the stock Codex TUI.
- Bounded relay message reassembly.
- Safe, idempotent `rcodex unenroll` cleanup.
- Hidden pairing-code input to keep one-time codes out of shell history.
- Public project documentation, security policy, and CI.

### Changed

- Updated rustls to `0.23.45` to address `RUSTSEC-2026-0285`.
- Restored runtime remote CLI capability checks and local/remote version
  parity, so matching current Codex releases work without updating a version pin.
- Updated the monitored release-validation baseline to Codex `0.162.0`.
- Improved README discoverability for Codex CLI remote control, remote terminal
  UI, Codex App Server, and remote development searches.
- Token refresh now abandons its write if another process changed the Codex
  authentication file while the network request was in flight.

## [0.1.0] - 2026-08-31

### Added

- Initial experimental Codex Remote Control terminal client.

[Unreleased]: https://github.com/Typiqally/rcodex/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Typiqally/rcodex/releases/tag/v0.1.0
