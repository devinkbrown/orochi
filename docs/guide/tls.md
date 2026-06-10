# TLS and STS

Mizuchi is modern-only: TLS is implicit on a separate listener and there is no STARTTLS command path (`src/main.zig:216`, `src/main.zig:219`, `src/daemon/dispatch.zig:369`). A TLS-first deployment should enable `[tls]` and usually `[sts]`, while still providing the currently required `[listen].irc` parser key.

## TLS Listener

```toml
[tls]
enabled = true
port = 6697
cert_path = "/etc/mizuchi/tls/cert.pem"
key_path = "/etc/mizuchi/tls/key.pem"
dns_name = "irc.example.net"
request_client_cert = false
```

When `[tls].enabled` is true, `main.zig` loads the configured cert/key or bootstraps a self-signed Ed25519 leaf using `dns_name`, then sets `server.Config.tls_port`, certificate chain, signing key, and client-cert request flag (`src/main.zig:222`, `src/main.zig:224`, `src/main.zig:231`, `src/main.zig:234`). The server binds the TLS listener only when cert material and a signing key are present (`src/daemon/server.zig:1499`).

Set `request_client_cert = true` when using SASL EXTERNAL. The TLS engine requests a client certificate (`src/daemon/server.zig:2433`, `src/daemon/server.zig:2439`), and the SASL bridge maps the presented certificate fingerprint to an account binding (`src/daemon/sasl_bridge.zig:70`).

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
