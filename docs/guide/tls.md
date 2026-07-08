# TLS and STS

*Configure implicit TLS listeners and Strict Transport Security (STS) for a modern-only Orochi deployment.*

Orochi is modern-only: TLS is implicit on a separate listener, and there is no STARTTLS command path (`src/main.zig:216`, `src/main.zig:219`, `src/daemon/dispatch.zig:369`). A TLS-first deployment enables `[tls]` and usually `[sts]`, while still providing the currently required `[listen].irc` parser key.

## TLS listener

```toml
[tls]
enabled = true
port = 6697
cert_path = "/etc/orochi/tls/cert.pem"
key_path = "/etc/orochi/tls/key.pem"
dns_name = "irc.example.net"
request_client_cert = false
enable_tls12 = false
```

Set `enable_tls12 = true` to also accept hardened TLS 1.2 (ECDHE-AEAD) clients on the same listener via version dispatch. It is **off by default** to preserve the TLS 1.3-only posture. When enabled, the 1.2 leg presents a freshly bootstrapped ECDSA-P256 leaf (the 1.2 engine signs ServerKeyExchange with `ecdsa_secp256r1_sha256`), independent of the 1.3 leaf.

When `[tls].enabled` is true, `main.zig` loads the configured cert/key or bootstraps a self-signed Ed25519 leaf using `dns_name`, then sets `server.Config.tls_port`, the certificate chain, the signing key, and the client-cert request flag (`src/main.zig:222`, `src/main.zig:224`, `src/main.zig:231`, `src/main.zig:234`). The server binds the TLS listener only when both certificate material and a signing key are present (`src/daemon/server.zig:1499`).

Set `request_client_cert = true` when using SASL EXTERNAL. The TLS engine requests a client certificate (`src/daemon/server.zig:2433`, `src/daemon/server.zig:2439`), and the SASL bridge maps the presented certificate fingerprint to an account binding (`src/daemon/sasl_bridge.zig:70`).

## Protocol capabilities

Orochi ships a clean-room, pure-Zig TLS 1.3 stack, Yoroi (`src/crypto/tls_client.zig`, `src/crypto/tls_server.zig`). The live IRC-over-TLS listener uses TLS 1.3; TLS 1.1/1.0, STARTTLS, renegotiation, and record compression all fail closed.

A hardened TLS 1.2 client and server engine also exists as standalone modules (`src/crypto/tls12{,_client,_server}.zig`) for interop where TLS 1.3 is unavailable. It is deliberately restricted to ECDHE key exchange with AEAD suites only — ECDHE-ECDSA/RSA with AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 over secp256r1 — with no CBC, RC4, static-RSA key exchange, compression, or renegotiation. The TLS 1.2 PRF, key schedule, GCM (RFC 5288) and ChaCha20-Poly1305 (RFC 7905) record layer, and Finished message are all implemented and loopback-tested. Server-side ServerKeyExchange signing is ECDSA-P256.

| Capability | Detail |
|---|---|
| Cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` — the full RFC 8446 mandatory set; the key schedule is SHA-256/SHA-384 dual-hash. |
| Key exchange | X25519 and secp256r1 (NIST P-256). The client offers shares for both; the server prefers X25519 and falls back to P-256. |
| Server certificates | Ed25519 or ECDSA-P256 leaf (`tls_server.Config`). ECDSA-P256 is the browser-compatible option; Ed25519 suits mesh/internal links. |
| HelloRetryRequest | The client handles HRR (cookie echo, RFC 5280 group rules, synthetic `message_hash` transcript, second-HRR-fatal). |
| Post-handshake KeyUpdate | Honored in both directions: the receiving side rotates its traffic keys and replies with its own KeyUpdate when requested. |
| Mutual TLS | The server can request an Ed25519 client certificate; its fingerprint (CertFP) backs SASL EXTERNAL (see below). |
| Delegated credentials | TLS client/server consume RFC 9345 delegated credentials when explicitly configured/offered. The out-of-band helper `orochi delegated-credential inspect|validate` parses ready-made DC wire bytes and can validate the leaf signature, DelegationUsage, KeyUsage, and lifetime window against a leaf certificate. Minting/rotation is still not shipped because it needs production private-key loading and safe DC key-output policy. |

**Certificate validation (client):** chain-to-trust-anchor signature checks (RSA-PSS/PKCS#1, ECDSA P-256/P-384, Ed25519), SAN dNSName matching, validity-window enforcement when a wall clock is supplied (the live HTTPS and ACME paths pass one), ExtendedKeyUsage `serverAuth` on the leaf, `keyCertSign` plus basicConstraints on path CAs, and X.509 Name Constraints (permitted/excluded dNSName subtrees).

**Revocation and transparency parsers:** clean-room, fail-closed parsing modules exist for OCSP responses (`crypto/ocsp.zig`, RFC 6960), X.509 CRLs (`crypto/crl.zig`, RFC 5280), and Certificate Transparency SCTs (`crypto/sct.zig`, RFC 6962). These parse and expose status and structure; cryptographic signature verification and live wiring into the handshake are not yet enabled.

## Delegated credential helper

The helper is an offline inspection/validation path. It never starts the daemon,
binds a listener, loads the server's private key, or mints new credentials.

```sh
orochi delegated-credential inspect --dc dc.wire
orochi delegated-credential validate --dc dc.wire --cert fullchain.pem
orochi delegated-credential validate --dc dc.wire --cert fullchain.pem --time 1704067200
```

`--dc` is the raw `DelegatedCredential` extension payload. `inspect` validates
the wire framing and prints `valid_time`, `dc_cert_verify_algorithm`, outer
signature `algorithm`, SPKI length, and signature length. Supplying `--cert`, or
using `validate`, additionally checks the first certificate in the PEM/DER chain:
it must carry RFC 9345 DelegationUsage and digitalSignature KeyUsage, the DC
expiry (`leaf.notBefore + valid_time`) must be live, within the seven-day
remaining-lifetime cap, and before the leaf `notAfter`, and the DC signature must
verify under the leaf SPKI. The supported leaf-signature schemes are Ed25519,
ECDSA P-256/SHA-256, and RSA-PSS-RSAE-SHA256.

## STS

```toml
[sts]
enabled = true
duration = 2592000
port = 6697
preload = false
```

STS is advertised only when `[sts].enabled` is true and a TLS listener is live (`src/main.zig:242`, `src/main.zig:247`, `src/main.zig:248`). The advertised value is built from `duration`, `port`, and `preload` (`src/main.zig:249`, `src/main.zig:254`). If STS is enabled without a live TLS listener, the daemon logs that STS is not advertised (`src/main.zig:260`).

The capability table intentionally omits `sts` until a runtime policy exists, which prevents clients from being told to upgrade to a listener that is not available (`src/daemon/dispatch.zig:369`).
