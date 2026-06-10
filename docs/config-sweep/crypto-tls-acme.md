# Orochi config sweep — crypto / TLS / ACME (READ-ONLY survey)

Scope: `src/crypto/*` (named files), `src/daemon/acme_*.zig`, `src/proto/tls_*.zig`, `src/proto/acme_*.zig`.
Only operationally/perf-meaningful hardcoded literals are listed. Cryptographic domain constants are excluded (see note at bottom).

Proposed sections: `[acme]`, `[tls]`.

---

## `[acme]`

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|-----------|------------------|---------------|------------------|-------------------|------|---------|----------|
| src/daemon/acme_cli.zig:20 | `staging_directory` | `https://acme-staging-v02.api.letsencrypt.org/directory` | ACME staging directory URL (default endpoint) | `acme.staging_directory_url` | string | (= current) | – |
| src/daemon/acme_cli.zig:21 | `prod_directory` | `https://acme-v02.api.letsencrypt.org/directory` | ACME production directory URL (`--prod`) | `acme.prod_directory_url` | string | (= current) | – |
| src/daemon/acme_cli.zig:22 | `default_ca_bundle` | `/etc/ssl/certs/ca-certificates.crt` | CA trust-anchor bundle path validating the ACME endpoint cert | `acme.ca_bundle_path` | string | (= current) | – |
| src/daemon/acme_cli.zig:24 | `default_challenge_port` | `14402` | Loopback HTTP-01 port nginx proxies the challenge path to | `acme.challenge_port` | uint(u16) | 14402 | 1..65535 |
| src/daemon/acme_cli.zig:111 | `runIssue` CA bundle read cap | `4 << 20` (4 MiB) | Max bytes read from the CA bundle file | `acme.ca_bundle_max_bytes` | uint | 4194304 | 64KiB..64MiB |
| src/daemon/acme_cli.zig:182 | `loadTrustAnchors` PEM decode scratch | `8192` | Per-cert base64-decode scratch (caps single root DER size) | `acme.trust_anchor_scratch_bytes` | uint | 8192 | 4096..65536 |
| src/daemon/acme_runner.zig:55 | `max_response_bytes` | `256 * 1024` | Max bytes accepted for a single ACME HTTP response | `acme.max_response_bytes` | uint | 262144 | 16KiB..4MiB |
| src/daemon/acme_runner.zig:139 | `httpsRequest` request build buffer | `16 * 1024` | Max outbound HTTP request size (JWS POST body + headers) | `acme.request_buffer_bytes` | uint | 16384 | 8KiB..256KiB |
| src/daemon/acme_runner.zig:203 | `HttpsTransport.header_scratch` | `64` (http1.Header) | Max parsed response headers retained per exchange | `acme.max_response_headers` | uint | 64 | 16..256 |
| src/daemon/acme_runner.zig:239 | `exchange` error-body preview | `512` | Max bytes of RFC 7807 problem body logged on error/debug | `acme.error_body_preview_bytes` | uint | 512 | 0..4096 |
| src/daemon/acme_runner.zig:311 (IssueConfig:311 → field at :311) `max_steps` | `IssueConfig.max_steps` | `64` | Max ACME state-machine steps before aborting (loop/hang guard) | `acme.max_steps` | uint | 64 | 8..1024 |
| src/daemon/acme_runner.zig:407 | `systemResolveA` resolv.conf read cap | `64 * 1024` | Max bytes read from /etc/resolv.conf | `acme.resolv_conf_max_bytes` | uint | 65536 | 4KiB..1MiB |
| src/daemon/acme_runner.zig:436 | `queryOneServer` nameserver port | `53` | UDP port for DNS A-record lookup of ACME endpoint | `acme.dns_port` | uint(u16) | 53 | 1..65535 |
| src/daemon/acme_client.zig:41 | `max_nonce_retries` | `3` | Max `badNonce` retries per signed request before giving up | `acme.max_nonce_retries` | uint(u8) | 3 | 1..16 |
| src/daemon/acme_client.zig:189 | `State.token_buf` | `256` | Max ACME challenge token length held in state | `acme.max_token_len` | uint | 256 | 64..1024 (borderline) |
| src/daemon/acme_client.zig:190 | `State.keyauth_buf` | `512` | Max key-authorization length held in state | `acme.max_key_auth_len` | uint | 512 | 128..2048 (borderline) |
| src/daemon/acme_client.zig:264 | `signJws` protected-header buf | `1024` | Max JWS protected-header size | `acme.jws_header_buffer_bytes` | uint | 1024 | 512..8192 (borderline) |
| src/daemon/acme_client.zig:330 | `stepAccount` payload buf | `1024` | Max account/order JSON payload size built per step | `acme.jws_payload_buffer_bytes` | uint | 1024 | 512..8192 (borderline) |
| src/daemon/acme_http01_listener.zig:31 | `max_request` | `8 * 1024` | Max bytes read per challenge connection | `acme.http01_max_request_bytes` | uint | 8192 | 1KiB..64KiB |
| src/daemon/acme_http01_listener.zig:33 | `max_response` | `4 * 1024` | Max challenge response size (headers + key auth) | `acme.http01_max_response_bytes` | uint | 4096 | 1KiB..16KiB |
| src/daemon/acme_http01_listener.zig:54 | bind address | `0x7f00_0001` (127.0.0.1) | Loopback bind address for the HTTP-01 listener | `acme.http01_bind_address` | string | "127.0.0.1" | – (borderline; security-sensitive) |
| src/daemon/acme_http01_listener.zig:58 | `listen` backlog | `16` | TCP accept backlog for the challenge listener | `acme.http01_listen_backlog` | uint | 16 | 1..1024 |
| src/daemon/acme_http01_listener.zig:64 | accept poll timeout `tv` | `250 * 1000` usec (250 ms) | RCVTIMEO so the accept loop wakes to re-check the stop flag | `acme.http01_accept_poll_ms` | duration | 250ms | 50ms..5s |
| src/daemon/acme_http01_listener.zig:100 | per-conn read timeout `tv` | `5` sec | RCVTIMEO on accepted challenge connections (slow-client guard) | `acme.http01_conn_read_timeout_sec` | duration | 5s | 1s..60s |
| src/proto/acme_challenge.zig:34 | `max_token_len` | `256` | Wire-parse cap on challenge token length | `acme.wire_max_token_len` | uint | 256 | 64..1024 (borderline) |
| src/proto/acme_problem.zig:19 | `max_urn_len` | `256` | Parse cap on RFC 7807 problem `type` URN | `acme.problem_max_urn_len` | uint | 256 | 64..1024 (borderline) |
| src/proto/acme_problem.zig:20 | `max_detail_len` | `512` | Parse cap on RFC 7807 problem `detail` string | `acme.problem_max_detail_len` | uint | 512 | 128..4096 (borderline) |

---

## `[tls]`

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|-----------|------------------|---------------|------------------|-------------------|------|---------|----------|
| src/crypto/tls_client.zig:34 | `debug_log` (pub var) | `false` | Verbose TLS client tracing to stderr | `tls.debug_log` | bool | false | – |
| src/crypto/tls_client.zig:403 | `start` ALPN build buf | `512` | Max ALPN extension build buffer | `tls.alpn_buffer_bytes` | uint | 512 | 64..4096 (borderline) |
| src/crypto/tls_handshake.zig:52 | `transcript_cap` | `16 * 1024` | Max handshake transcript buffer retained for the hash | `tls.transcript_cap_bytes` | uint | 16384 | 8KiB..128KiB |
| src/crypto/secure_channel.zig:27 | `default_max_skip` | `256` | Double-ratchet max skipped message keys cached | `tls.ratchet_max_skip` | uint | 256 | 16..4096 |
| src/crypto/treekem.zig:27 | `max_members` | `1024` | TreeKEM max group members | `tls.treekem_max_members` | uint | 1024 | 8..65536 |
| src/crypto/tsumugi_handshake.zig:26 | `max_meshpass_len` | `4096` | Max Tsumugi mesh-password length accepted in the handshake | `tls.tsumugi_max_meshpass_len` | uint | 4096 | 256..65536 |

Note: Tsumugi prekey validity is driven by caller-supplied `ttl_ms`/`now_ms` (SignedPrekey.generate, tsumugi_handshake.zig:98/109-110) — no hardcoded default; route through `tls.tsumugi_prekey_ttl_ms` (duration) when a default is introduced. Currently NOT hardcoded.

---

## Left in code (cryptographic / protocol domain constants — intentionally NOT lifted)

- TLS record framing maxima: `max_plaintext_len = 16*1024`, `max_ciphertext_len = +256`, `record_header_len = 5` (tls_record.zig:12-14) — RFC 8446 record-layer constants.
- TLS wire-format field maxima sized to field width: `tls_psk.zig` (`maxInt(u16)`/`maxInt(u8)`), `tls_cookie.zig` (`maxInt(u16)`), `tls_session_ticket.zig` (`0xff`/`0xffff`), `tls_cert_message.zig` (`max_u24`/`max_u16`), `tls_alpn.max_name_len`, `tls_key_update.zig` (`secret_len=32`, `encoded_len=5`) — protocol-bound, must stay in code.
- Cipher-suite / version / msg-type IDs: `suite=0x1303` (tls_handshake.zig:48), `protocol_version=1` (tsumugi), `msg_type_key_update=24`, JOSE `jose_alg="ES256"`, RFC label strings.
- ASN.1/OID byte arrays + key/coord widths: `ecdsa_sha256_sig_alg`, `ecP256Spki`, SEC1 EC PEM DER template (acme_runner.zig:555-560), prime256v1 OID, `ec_json_max_len`/`okp_json_max_len` (derived from 32-byte coord b64), DNS `max_message_len`.
- Bignum limb counts: `rsa_verify.max_limbs=132` / `max_bytes` (RSA modulus cap; borderline but RFC/crypto-bound — left in code).
- `osEntropy` fallback fill byte `0x55`, ratchet/HKDF/AEAD nonce-key-tag lengths, P-256 field/scalar sizes.
