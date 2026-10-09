# Related-project maintenance

[rclaude](https://github.com/Typiqally/rclaude) and
[rcodex](https://github.com/Typiqally/rcodex) are companion Rust controllers that
keep the official provider terminal UI and isolate provider credentials from
machine integrations. Keep their project conventions aligned while retaining
independent authentication, transports, qualification, and release versions.

This document is mirrored in both repositories. When editing it, apply the same
change to the companion copy in the same maintenance pass.

## Check both projects when changing shared conventions

- README structure, installation guidance, experimental status, and reciprocal links.
- MIT licensing, contribution guidance, security reporting, and credential ignores.
- Formatting, strict Clippy, offline tests, dependency audit, and package verification.
- Pinned GitHub Actions, least-privilege workflow permissions, manually confirmed
  releases, SHA-256 digests, and build attestations.
- Broker versioning, frame/file bounds, credential redaction, error handling, and
  synthetic integration fixtures. Coordinate protocol changes with shared consumers.

In each PR or changelog entry that affects both, link the companion change or
state why the convention does not apply. Backport applicable security and
packaging fixes promptly; validate them independently in each project.

## Keep provider-specific behavior independent

Do not copy account endpoints, tokens, enrollment flows, or protocol assumptions
between providers. rcodex's relay pairing, signing identity, compatibility
monitoring, and updater have no automatic equivalent in rclaude. rclaude's Claude
cloud sessions, Files API staging, and OAuth/Keychain handling need their own
live evidence. CI platforms may differ with supported provider integration.

Passing tests or live qualification in one project does not qualify the other.
Release each project when its own checks pass; their version numbers need not
match. Never add a runtime dependency on the companion repository just to keep
project metadata or documentation aligned.
