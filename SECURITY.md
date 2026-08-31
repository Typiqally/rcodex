# Security policy

## Supported versions

Until the project reaches `1.0`, security fixes are provided only for the
latest release on the `main` branch.

| Version | Supported |
| --- | --- |
| Latest `0.x` | Yes |
| Older releases | No |

## Reporting a vulnerability

Do not open a public issue for a vulnerability, suspected credential leak, or
account-compromise scenario. Use GitHub's private vulnerability reporting at:

<https://github.com/Typiqally/rcodex/security/advisories/new>

Include the affected version or commit, reproduction steps, expected impact,
and any suggested mitigation. Remove access tokens, refresh tokens, pairing
codes, account IDs, environment IDs, hostnames, and Keychain material from the
report.

Maintainers aim to acknowledge reports within seven days. Please allow time for
a fix and coordinated disclosure before publishing details.

## Scope

Security-sensitive areas include:

- Codex authentication-file handling and token refresh;
- OAuth callback validation;
- relay enrollment, pairing, and controller revocation;
- device-key creation, signing, and deletion;
- loopback WebSocket authentication; and
- relay frame parsing and message reassembly.

The undocumented upstream relay protocol is a compatibility risk, but an
upstream behavior change by itself is not an `rcodex` vulnerability.
