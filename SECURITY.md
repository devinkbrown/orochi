# Security Policy

Orochi is a network daemon with its own TLS stack, post-quantum server-to-server
cryptography, and authentication surface. We take security reports seriously.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/devinkbrown/orochi/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). If that is
unavailable, email **devin.kyle.brown@gmail.com** with the details.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The affected version (commit hash) and your configuration, with secrets redacted.

We aim to acknowledge a report within a few days and to keep you updated as we
investigate and prepare a fix. Please give us a reasonable window to release a fix
before any public disclosure, and coordinate timing with us.

## Scope

High-interest areas include:

- The TLS 1.3 / hardened TLS 1.2 stack and certificate handling.
- The Tsumugi handshake and Suimyaku mesh record layer (server-to-server crypto).
- Authentication: SASL (PLAIN / SCRAM / EXTERNAL), session tokens, CERTFP.
- Connection admission, flood/raid controls, and resource bounds.
- The in-place upgrade (Helix) state handoff and the WASM plugin host.

## Supported versions

Orochi is developed on a rolling basis; fixes land on `main`. Operators should track
`main` and apply security fixes via the session-preserving `USR2` hot-upgrade.
