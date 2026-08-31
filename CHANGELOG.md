# Changelog

All notable changes to this project will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Authenticated per-run loopback bridge for the stock Codex TUI.
- Bounded relay message reassembly.
- Safe, idempotent `rcodex unenroll` cleanup.
- Hidden pairing-code input to keep one-time codes out of shell history.
- Public project documentation, security policy, and CI.

### Changed

- Token refresh now abandons its write if another process changed the Codex
  authentication file while the network request was in flight.

## [0.1.0] - 2026-08-31

### Added

- Initial experimental Codex Remote Control terminal client.

[Unreleased]: https://github.com/Typiqally/rcodex/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Typiqally/rcodex/releases/tag/v0.1.0
