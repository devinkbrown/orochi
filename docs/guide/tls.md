# TLS and STS

Orochi is modern-only: TLS is implicit on a separate listener and there is no STARTTLS command path (`src/main.zig:216`, `src/main.zig:219`, `src/daemon/dispatch.zig:369`). A TLS-first deployment should enable `[tls]` and usually `[sts]`, while still providing the currently required `[listen].irc` parser key.

## TLS Listener

```toml
[tls]
enabled = true
port = 6697
cert_path = "/etc/orochi/tls/cert.pem"
key_path = "/etc/orochi/tls/key.pem"
dns_name = "irc.example.net"
request_client_cert = false
```

When `[tls].enabled` is true, `main.zig` loads the configured cert/key or bootstraps a self-signed Ed25519 leaf using `dns_name`, then sets `server.Config.tls_port`, certificate chain, signing key, and client-cert request flag (`src/main.zig:222`, `src/main.zig:224`, `src/main.zig:231`, `src/main.zig:234`). The server binds the TLS listener only when cert material and a signing key are present (`src/daemon/server.zig:1499`).

Set `request_client_cert = true` when using SASL EXTERNAL. The TLS engine requests a client certificate (`src/daemon/server.zig:2433`, `src/daemon/server.zig:2439`), and the SASL bridge maps the presented certificate fingerprint to an account binding (`src/daemon/sasl_bridge.zig:70`).

## Protocol capabilities

Orochi ships a clean-room, pure-Zig TLS 1.3 stack (`src/crypto/tls_client.zig`,
`src/crypto/tls_server.zig`). It is **TLS 1.3 only** — TLS 1.2/1.1/1.0, STARTTLS,
renegotiation, and record compression all fail closed.

**Cipher suites:** `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256` (the full RFC 8446 mandatory set; the key schedule
is SHA-256/SHA-384 dual-hash).

**Key exchange:** X25519 and secp256r1 (NIST P-256). The client offers shares for
both; the server prefers X25519 and falls back to P-256.

**Server certificates:** Ed25519 or ECDSA-P256 leaf (`tls_server.Config`).
ECDSA-P256 is the browser-compatible option; Ed25519 suits mesh/internal links.

**HelloRetryRequest:** the client handles HRR (cookie echo, RFC 5280 group rules,
synthetic `message_hash` transcript, second-HRR-fatal).

**Post-handshake KeyUpdate:** honored in both directions — the receiving side
rotates its traffic keys and replies with its own KeyUpdate when requested.

**Certificate validation (client):** chain-to-trust-anchor signature checks
(RSA-PSS/PKCS#1, ECDSA P-256/P-384, Ed25519), SAN dNSName matching, validity
window enforcement when a wall clock is supplied (live HTTPS + ACME paths pass
one), ExtendedKeyUsage `serverAuth` on the leaf, `keyCertSign` + basicConstraints
on path CAs, and X.509 **Name Constraints** (permitted/excluded dNSName subtrees).

**Revocation & transparency parsers:** clean-room, fail-closed parsing modules
exist for OCSP responses (`crypto/ocsp.zig`, RFC 6960), X.509 CRLs
(`crypto/crl.zig`, RFC 5280), and Certificate Transparency SCTs (`crypto/sct.zig`,
RFC 6962). These parse and expose status/structure; cryptographic signature
verification and live wiring into the handshake are not yet enabled.

**Mutual TLS:** the server can request an Ed25519 client certificate; its
fingerprint (CertFP) backs SASL EXTERNAL (see below).

## STS

```toml
[sts]
enabled = true
duration = 2592000
port = 6697
preload = false
```

STS is advertised only when `[sts].enabled` is true and a TLS listener is live (`src/main.zig:242`, `src/main.zig:247`, `src/main.zig:248`). The advertised value is built from `duration`, `port`, and `preload` (`src/main.zig:249`, `src/main.zig:254`). If STS is enabled without a live TLS listener, the daemon logs that STS is not advertised (`src/main.zig:260`).

The capability table intentionally omits `sts` until a runtime policy exists, preventing clients from being told to upgrade to a listener that is not available (`src/daemon/dispatch.zig:369`).
