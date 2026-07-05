<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# TLS Hardening Roadmap

Derived from a gap analysis of the orochi Zig-native TLS stack (`src/crypto/tls*.zig`,
`x509*.zig`, `ocsp.zig`, `sct.zig`, `crl.zig`) against BoringSSL and WolfSSL.

**Where we're already ahead — keep these:** live TLS session export/import across the
USR2 hot-upgrade (no re-handshake); aggressive modern-only posture (no CBC, no
static-RSA/DHE, no TLS <1.2, no SHA-1 cert sigs, renegotiation refused); PQ-hybrid
KEX (X25519MLKEM768) wired server-side; 0-RTT with a shared replay guard; RFC
5705/9266 exporters for SCRAM channel binding.

Effort: **S** ≤½ day · **M** 1–3 days · **L** multi-day/spike-first.
Risk: how dangerous a mistake is on the *live* stack.

---

## Phase 0 — Assurance foundation (a from-scratch TLS stack MUST have this)

| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 0.1 | ✅ **DONE (rejection subset)** — **Adversarial crypto tests** (`wycheproof_kat.zig`): AEAD tamper (ct/tag/nonce/aad), X25519 all-zero low-order point, ECDSA r=0/s=0. Follow-up: positive independent-vector KATs (RSA-PSS, full curve set). | M | Low | `wycheproof_kat.zig` |
| 0.2 | ✅ **DONE** — **Fuzz harnesses** (`tls_fuzz.zig`): deterministic random + structured + bit-flip robustness over x509/record/handshake parsers; ~44k inputs/run, no panics found. Follow-up: coverage-guided `--fuzz` (Smith). | M | Low | `tls_fuzz.zig` |
| 0.3 | **BoGo shim + subset run** | L | Low | BoringSSL's protocol test runner against a shim. Design-spike first (which subset, shim wiring). |
| 0.4 | **Constant-time verification** | M | Low | dudect/ctgrind-style timing checks on ECDSA/X25519/RSA to validate the "CT by construction" claim. |

## Phase 1 — Surgical correctness fixes ✅ COMPLETE (only 1.3 PSS-384/512 + x509_verify alignment as noted follow-ups)

| # | Item | Effort | Risk | Files |
|---|------|--------|------|-------|
| 1.1 | ✅ **DONE** — **Downgrade sentinel (RFC 8446 §4.1.3)**: 1.2 engine stamps `DOWNGRD\x01` into `server_random[24..32]` at construction (covers full + resumed ServerHello). Follow-up: have `tls12_client` check it. | S | Med | `tls12_server.zig` |
| 1.2 | ✅ **DONE** — **Path-length basicConstraints enforcement**: `x509` retains `basic_constraints_path_len: ?u32`; validator rejects chains exceeding a CA's pathLen via the pure unit-tested `enforcePathLen` helper. | S | Med | `x509.zig`, `tls_client.zig`, `x509_selfsign.zig` |
| 1.3 | 🟡 **PARTIAL** — Added **RSA-PKCS1 SHA-384/512** to the production `tls_client` validator (real CAs use sha384WithRSA), no union change (avoids the wave-1 `oauth_jwt` break) + sha384 round-trip test. **Follow-up:** RSA-PSS SHA-384/512 (needs PSS-param parsing), align the non-production `x509_verify` simple validator. | M | Med | `tls_client.zig`, `x509_selfsign.zig` |
| 1.4 | ✅ **DONE** — **Client offers X25519MLKEM768**: hybrid ephemeral + `ek‖x25519` key_share + raw-concat combiner (matching the server, NOT `HybridKx.decapsulate`); key schedule now takes a variable-length secret. Integration-tested (hybrid-only client ↔ server completes, group 0x11ec, data round-trips). | S–M | Med | `tls_client.zig`, `supported_groups.zig`, `tls_server.zig` |
| 1.5 | ✅ **DONE (TLS 1.3)** — **record_size_limit (RFC 8449)**: negotiated both ways (offer/echo/parse/validate) + outbound records fragmented in `encrypt()` to honor the peer's limit (`recordContentLimit`). Integration-tested (100-byte limit → 250B payload fragments to 3 records, client reassembles). Follow-up: TLS 1.2. | M | Med | `tls_extension.zig`, `tls_record.zig`, `tls_server.zig`, `tls_client.zig` |
| 1.6 | ✅ **DONE** — **Ticket-key rotation**: `openTicketWithRotation` + `previous_ticket_key` on both TLS Configs; daemon retains `tls_previous_ticket_key`, threads it in, and rotates on REHASH (`rotateTicketKey`). Unit-tested both layers. Minor follow-up: carry `previous` across USR2. | M | Med | `tls_resumption.zig`, `tls12_server.zig`, `tls_server.zig`, `daemon/server.zig` |

## Phase 2 — Server-facing protocol features ✅ COMPLETE (2.1 OCSP stapling · 2.2 HRR · 2.3 cert compression · 2.4 SNI selection)

| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 2.1 | ✅ **COMPLETE** — server-side OCSP stapling, wire + producer. **Wire (inc 1-5):** ocsp.buildRequest[ForCerts]; x509 AIA-URL + must-staple + CertID inputs; TLS 1.3 CertificateEntry staple; TLS 1.2 CertificateStatus (gated, mirrors 1.3). Both legs staple `Config.ocsp_staple` only when the client offers status_request (byte-identical otherwise). **Gate (inc 6):** `ocsp.isStapleServable` (parse→successful→issuer-signed→good→thisUpdate≤now<nextUpdate±skew, throw-free), `x509.generalizedTimeToEpoch`, `http_fetch.post`. **Publish (inc 7):** `config.tls_ocsp_staple` + `publishOcspStaple`/`maybeSwapOcspStaple` reactor-0 atomic-swap (mirrors ACME reload); 1.2 stapled only when it shares the 1.3 leaf; staple cleared on cert reload. **Producer (inc 8):** `ocsp_staple.Service` background thread — fetch AIA → verify → freshness-gate → cache last-good → publish; revoked-own-cert logs CRITICAL; refresh at thisUpdate→nextUpdate halfway clamped [5m,24h]. `[ocsp]` config + main.zig wiring (gated on `[tls]` + on-disk cert_path). **Follow-up (low pri):** 1.2 client-side round-trip test; delegated-responder (id-kp-OCSPSigning) support; exponential backoff on fetch failure. | M | Med | `ocsp.zig`, `x509.zig`, `tls_server.zig`, `tls12_server.zig`, `tls_extension.zig`, `ocsp_staple.zig`, `http_fetch.zig`, `server.zig`, `config_format.zig`, `main.zig` |
| 2.2 | ✅ **COMPLETE** — server-side HelloRetryRequest (RFC 8446 §4.1.4 + §4.4.1). When a ClientHello offers no key_share the server can use but advertises a group it supports (via `supported_groups`), the server sends one HRR — a ServerHello with the magic random + a bare-group key_share — reusing `supported_groups.selectPreferred` (prefs x25519 › secp256r1 › x25519mlkem768). Transcript rewritten with the `message_hash` synthetic (type 254) before folding in the HRR; new `wait_second_client_hello` state; ClientHello2 is pinned to exactly the requested group (extra/other shares dropped, else `BadHandshake`); only one HRR per connection; 0-RTT skipped on the bounced hello. The in-repo `tls_client` HRR path was made real+compliant (single-share CH2 via `retry_key_share_group`, offered-share-aware rejection) and drives a full loopback interop test (withheld shares → HRR → retry → data both ways). Wire byte-identical for normal handshakes (any usable share ⇒ no HRR). | M | Med | `tls_server.zig`, `tls_client.zig`, `supported_groups.zig` |
| 2.3 | ✅ **COMPLETE** — certificate compression (RFC 8879), zlib, both directions. Shared `proto/cert_compression.zig` (Algorithm registry, `pickSupported`, `deflateZlib`, `inflateZlib` with the mandatory 3-layer bomb guard: declared-len ≤ 64 KiB before alloc, output capped at declared+1, exact-length match) built on the in-tree `std.compress.flate` `.zlib` container — **no new dependency**. Server: `compress_certificate(27)` negotiation, `Config.enable_cert_compression` (default off ⇒ byte-identical), `writeCertificate` emits `CompressedCertificate(25)` only when it actually shrinks (fallback to plain). Client: opt-in `offer_cert_compression` (default off, symmetric with the server gate) advertises zlib + decodes type-25 under the bomb guard (`decompressCertificate`), and rejects an unsolicited CompressedCertificate. zlib only — std has no brotli and its zstd is decode-only; brotli/zstd-only clients fall back to plain (no interop break). TLS 1.3 only. Tests: compressed round-trip loopback (duplicated chain forces compression) + module unit/bomb tests + a deterministic fallback-premise unit test (real self-signed certs always deflate smaller, so the writeCertificate fallback branch is proven via `deflateZlib` expanding tiny incompressible input rather than a fragile cert-based loopback). | M | Low | `cert_compression.zig`, `tls_extension.zig`, `tls_server.zig`, `tls_client.zig` |
| 2.4 | ✅ **COMPLETE (library)** — SNI-based cert selection (RFC 6066). `Config.sni_certs: []const SniCert` ({server_names, cert_chain, signing keys, ocsp_staple}); on ClientHello the server parses SNI via the existing `proto/sni.zig` (`extractOptional(raw)`) and picks the first entry whose `server_names` matches (case-insensitive exact + `*.` one-label wildcard, `serverNameMatches`), else the default top-level cert. `writeCertificate`/`writeCertificateVerify` route through `activeCertChain`/`activeOcspStaple`/`activeSigningKeyResolved` accessors; `sni_cert` index re-derived per ClientHello; `init` validates every entry has a chain + key. Empty `sni_certs` ⇒ byte-identical (SNI not consulted). Loopback test: 2 SNI certs + default, three connections select A/B/default (a green handshake against each cert's SAN+anchor *is* the selection proof) + `serverNameMatches` unit test. **Daemon plumbing (multi-cert `[tls]` config + main.zig load) is a separate follow-up** — this is the TLS-library capability, the ECH (5.1) prereq. | M | Low | `tls_server.zig`, `sni.zig` |

## Phase 3 — Performance

| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 3.1 | 🟡 **Phase 0 foundation landed** (pure `src/daemon/ktls.zig` — no wiring) — see [design](tls-design/ktls.md) | M–L | Med | **Phase 0 (this session):** kernel-UAPI constants (`SOL_TLS`/`TCP_ULP`/`TLS_TX`/versions), per-cipher `crypto_info` geometry (AES-GCM-128/256, ChaCha20-Poly1305), the `CryptoInfo.encode` byte serializer (authoritative UAPI layout: header ‖ iv ‖ key ‖ salt ‖ rec_seq), big-endian `seqToBytes`, and the TLS 1.3 static-IV → salt(4)/iv(8) (GCM) / no-salt+12-byte-iv (ChaCha) split, all golden-vector unit-tested. **Deferred to Phase 1 (needs deploy-kernel round-trip):** TLS 1.2 explicit-nonce derivation, the `setsockopt(TCP_ULP/TLS_TX)` attach + send-seam plaintext branch, boot per-suite capability probe, getsockopt-seq liveness self-test, `[tls] ktls=off\|tx\|txrx` config, USR2 offloaded-marker. Biggest throughput/CPU win. **Design correction (wave 1):** kTLS state is *kernel socket state that survives `execve`*, and we already carry client fds across USR2 — so a TX-offloaded socket keeps encrypting on the successor with **zero key re-injection** (add a 1-bit "offloaded" marker to the snapshot). The USR2 collision I'd assumed largely dissolves. **S2S is NOT TLS** (Tsumugi/Suimyaku) so it's out of scope — the only eligible sockets are client-facing implicit-TLS + wss. Recommended: **TX-only first** (RX kept userspace; RX extraction is fragile), rolled out to the wss media/upload data-plane before interactive IRC clients. |

## Phase 4 — Wire-or-cut (verifier code exists but is unreachable)

| # | Item | Effort | Risk | Decision |
|---|------|--------|------|----------|
| 4.1 | **SCT / Certificate Transparency** — `sct.zig` + `verifySct` exist, unwired, no log list | M | Low | Wire consumption + pinned logs, or cut |
| 4.2 | **CRL** — `crl.zig` parser exists, unwired, sig not self-verified | M | Low | Wire (with CDP fetch), or cut |
| 4.3 | **DTLS** — full DTLS 1.2/1.3 + DTLS-SRTP lib, no live listener; CID absent | — | Low | Keep as media-plane lib or cut; only relevant if media → standards WebRTC |

## Phase 5 — Deferred / forward-looking (revisit in 12–18 months)

| # | Item | Notes |
|---|------|-------|
| 5.1 | ECH (Encrypted Client Hello) | On-brand for privacy; needs DNS HTTPS-RR + SNI selection (2.4) first |
| 5.2 | Delegated credentials (RFC 9345) | Niche |
| 5.3 | Raw public keys (RFC 7250) | Could simplify mesh auth, but mesh uses Tsumugi |
| 5.4 | PQ-signature certs (ML-DSA/SLH-DSA) | No public CA issues them yet |

## Explicitly skipped (cut against modern-only posture)

AES-CCM/CCM_8 · X448/Ed448 · P-521 · DHE · static-RSA · CBC/encrypt-then-MAC ·
extended master secret (1.2 tickets off by default) · DTLS Connection ID (unless media pivots).

---

Design docs (wave 1): [0.3 BoGo](tls-design/bogo.md) · [2.1 server OCSP stapling](tls-design/ocsp-stapling.md) · [2.3 cert compression](tls-design/cert-compression.md) · [3.1 kTLS](tls-design/ktls.md).

## Wave 1 outcomes (2026-07-05)

20-agent workflow: 4 design spikes + 8 worktree-isolated implementations + 8 adversarial reviews.

**Designs — all 4 usable**, landed in `docs/dev/tls-design/`. Key correction: the kTLS↔USR2-migration tension mostly dissolves (kernel TLS state survives execve).

**Implementations — process learning:** the worktree isolation branched from a **stale base (`50ca052`, 673 commits behind HEAD)**, so most patches don't apply to HEAD and the agents' "compiles: yes" was against old code. Adversarial review + `git apply --check` triage:

| Item | Applies to HEAD | Review | Action |
|------|-----------------|--------|--------|
| 1.1 downgrade sentinel | ✅ clean | approve | **LANDED** |
| 1.3 validator consolidation | ✅ clean | revise (CRITICAL: `oauth_jwt.zig` union-exhaustiveness build break; 3rd validator in `tls12_client` left) | redo vs HEAD |
| 1.6 ticket-key rotation | ✅ clean | revise (dead code — `TicketKeyRing` unwired; no secureZero) | wire it, then land |
| 0.1 Wycheproof KATs | ✗ conflict | revise (self-generated "known" answers ≠ independent; mislabeled GCM vector) | redo with real vectors |
| 0.2 fuzz harnesses | ✗ conflict | revise (misses 2nd record parser; stale-base provenance) | redo vs HEAD |
| 1.2 path-length | ✗ conflict | revise (stale hunks; 3-arg call mismatch) | redo vs HEAD |
| 1.4 client PQ offer | ✗ conflict | revise (only consumer is ACME outbound; CH fragmentation risk) | redo, assess value |
| 1.5 record_size_limit | ✗ conflict | revise (stale hunks; missing upper-bound + alert) | redo vs HEAD |

**Wave-2 fix:** run implementers against **HEAD** (not a stale worktree base), and treat these reviewed patches as reference specs. The reviews already pinpoint each fix.

## Execution log

- 2026-07-05: Roadmap created from the three-agent gap-analysis inventory.
- 2026-07-05: Wave 1 — 4 designs landed; 1.1 downgrade sentinel LANDED; 7 impls triaged to wave 2 (stale-base + review findings above).
- 2026-07-05: Wave 2 (re-implemented vs HEAD, not stale worktrees) — landed **6 items**: 1.1 downgrade sentinel, 1.2 path-length, 1.3 (partial) RSA-SHA384/512 cert verify, 1.6 ticket-rotation mechanism, 0.2 fuzz harnesses, plus the roadmap + 4 design docs. All compile clean, tested, committed; **none deployed** (held for a full-suite + zig-review gate).
  - **Surgical tier exhausted** for the cleanly-landable items. **Remaining, by size:**
    - Small follow-ups: 1.3 PSS-384/512 (needs PSS-param parsing) + align `x509_verify`; 1.6 daemon rotation trigger (rotate-on-REHASH + carry `previous` across USR2); 1.4 client-PQ (low value); 0.1 adversarial crypto KATs.
    - **Multi-file / larger:** 1.5 record_size_limit.
    - **Multi-day features (scoped by the design docs, need dedicated sessions):** 3.1 kTLS, 4.x wire-or-cut SCT/CRL/DTLS. (2.2 server HRR + 2.3 cert compression + 2.4 SNI selection now DONE — Phase 2 COMPLETE.)
- 2026-07-05: **2.1 server OCSP stapling COMPLETE** (inc 6-8): servable gate + generalizedTimeToEpoch + http_fetch.post (inc 6); server publish/swap plumbing (inc 7); `ocsp_staple.Service` fetcher + `[ocsp]` config + main wiring (inc 8). Full suite green; **not deployed** (held for deploy gate). Remaining follow-ups are low-priority (1.2 client round-trip test, delegated responders, fetch backoff).
- 2026-07-05: **2.1 follow-up: OCSP fetch exponential backoff landed.** The `ocsp_staple.Service` retried a down responder every 15-min check interval; now `fetchAndPublish` returns success/failure and consecutive failures back off exponentially (`backoffSeconds`: min_refresh doubling per failure, clamped to max_refresh) via a `next_retry_unix` gate, reset on a successful publish or a leaf-serial change (a rotated cert gets a fresh attempt). Pure `backoffSeconds` unit-tested. Full suite green; **not deployed**.
- 2026-07-05: **3.1 kTLS `[tls] ktls` config landed.** `Config.KtlsMode` (off/tx/txrx, default off) parsed from `[tls] ktls`, projected through `TlsBootConfig`, and consumed by the `main.zig` boot report — which now crosses the operator's configured intent with the kernel's TLS-ULP capability (e.g. "kTLS tx requested; kernel is kTLS-capable" vs "requested but no TLS ULP"). Unknown mode → hard `ParseError`. Config parse tests + default assertion. No offload yet (mode only widens the boot report until the Phase 1 send-seam lands). Full suite green; **not deployed**.
- 2026-07-05: **3.1 kTLS attach primitives + real-kernel encoder validation landed.** `ktls.attachUlp` (setsockopt SOL_TCP/TCP_ULP="tls") + `ktls.attachTx` (SOL_TLS/TLS_TX from an encoded `crypto_info`) — the exact setsockopt calls Phase 1's send-seam will make. A gated loopback test establishes an ESTABLISHED TCP pair and installs our encoded TLS 1.3 `crypto_info` via TLS_TX for AES-GCM-128 (hard-asserted; universal on any kTLS kernel) + AES-GCM-256/ChaCha20 (best-effort per kernel support) — **the kernel accepting the struct validates our byte layout (header/field-order/sizes/rec_seq) against a real kernel**, closing the "self-authored vectors" gap. Passed on the dev kernel (7.0.3). Still no live send-seam wiring (that + USR2-marker + config is Phase 1). Full suite green; **not deployed**.
- 2026-07-05: **3.1 kTLS Phase 0 capability probe landed** — `ktls.ulpAvailable` (pure token parser, unit-tested) + `ktls.probeUlpSupport()` (reads `/proc/sys/net/ipv4/tcp_available_ulp`), wired into `main.zig` so a `[tls]`-enabled boot logs whether the kernel offers the TLS ULP — the "is the deploy kernel kTLS-capable?" check the design flags, now answered from the logs (informational; TLS still userspace). Per-suite `TLS_TX` acceptance probe + the `setsockopt` attach primitives remain Phase 1 (need an ESTABLISHED socket + deploy-kernel round-trip). Full suite green; **not deployed**.
- 2026-07-05: **3.1 kTLS Phase 0 foundation landed** — new pure `src/daemon/ktls.zig` (no syscalls, no live wiring): kernel-UAPI constants, per-cipher geometry, `CryptoInfo.encode` byte serializer, `seqToBytes`, and the TLS 1.3 salt/iv split, all golden-vector unit-tested (7 tests). Byte layout is authoritative (UAPI); TLS 1.2 explicit-nonce derivation + the live `setsockopt` attach/probe/self-test/config/USR2-marker are deferred to Phase 1 (need a deploy-kernel round-trip). Full suite green; **not deployed**.
- 2026-07-05: **Phase-C cross-completion UAF FIXED.** The daemon freed the superseded TLS generation *inline* on cert reload (`reloadTlsCertsLocked`) and OCSP-staple swap (`maybeSwapOcspStaple`), so a handshake that captured a cert-chain/staple slice at accept time could read freed bytes if a swap committed mid-handshake. Fix: retain the just-replaced generation one extra cycle (`reload_tls_prev`/`reload_tls12_prev`/`ocsp_staple_prev`) and free only the generation from two swaps ago — reloads are cadenced in hours/days, handshakes complete in ms, so no live handshake can reference a two-generations-old buffer. deinit frees the retained generations; the existing A→B→C reload test (testing allocator) now also asserts B is retained as `reload_tls_prev` and proves no leak/double-free. Full suite green; **not deployed**.
- 2026-07-05: **2.4 SNI-based cert selection COMPLETE (library) — Phase 2 done.** `Config.sni_certs` + per-ClientHello `selectSniCert` (reuses `proto/sni.zig` on `raw`) + `serverNameMatches` (exact/case-insensitive/`*.`-wildcard) + `activeCertChain`/`activeOcspStaple`/`activeSigningKeyResolved` accessors so `writeCertificate`/`writeCertificateVerify` present the SNI-matched cert. Empty `sni_certs` ⇒ byte-identical. Multi-cert loopback (A/B/default) + matcher unit test. `zig-code-reviewer`: **Approve** (cert/key never desync across default/HRR/PSK/mTLS — all key off the one `sni_cert` index set before any Certificate is written; SNI parse bounds-safe; wildcard boundaries correct). Follow-ups (LOW, deferred): (a) enforce CH2 SNI == CH1 SNI across HRR (harmless today — transcript-authenticated — but cheap strict-compliance); (b) `writeCertificateVerify` doesn't consult client `signature_algorithms` and `init` doesn't check each entry's key-type matches its leaf (pre-existing, applies to single-cert too); (c) daemon-side multi-cert config plumbing (no consumer yet; this is the ECH prereq). Full suite green; **not deployed**.
- 2026-07-05: **2.3 certificate compression (RFC 8879) COMPLETE — both directions.** New shared `proto/cert_compression.zig` (zlib via `std.compress.flate` `.zlib`, no new dep) with the 3-layer decompression-bomb guard. Server negotiates `compress_certificate(27)`, gated behind default-off `enable_cert_compression`, and emits `CompressedCertificate(25)` only when it shrinks (else plain). Client advertises zlib + decodes type-25 under the bomb guard. zlib-only (std has no brotli, zstd decode-only). Loopback round-trip + fallback + module bomb tests. Full suite green; **not deployed**. The design's phase-1-first (server-send-only) rationale was deploy-risk; since nothing is deployed the two phases shipped together for a clean round-trip test. The client offer is gated behind default-off `offer_cert_compression` (symmetric with the server), so the outbound ACME ClientHello stays byte-identical and no decode path is reachable until opted in; an unsolicited CompressedCertificate is rejected. `zig-code-reviewer`: **Approve** (bomb guard airtight — verified the `.limited(declared_len+1)` `+1` is load-bearing against std source; transcript folds identical bytes both ways; memory-clean; default-off gate byte-identical). Only LOW notes: 64 KiB cap asymmetry (deliberate), optional `bad_certificate`/`decompression_failure` alert mapping.
- 2026-07-05: **2.2 server HelloRetryRequest COMPLETE.** Server parses `supported_groups`, HRRs (once) for the preferred mutually-supported group when no usable key_share is offered, rewrites the transcript with the `message_hash` synthetic, and pins ClientHello2 to the requested group. Reused `supported_groups.selectPreferred`. Turned the in-repo `tls_client`'s previously-untested HRR handling into a real, RFC-compliant path (single-share CH2, offered-share-aware rejection) to drive a full loopback interop test. `zig-code-reviewer`: **Approve-with-nits, no CRITICAL/HIGH** (transcript/pinning/no-loop/0-RTT-ordering/memory-safety all verified); applied both MEDIUM CH2-hardening fixes — **M1** reject `early_data` in CH2 (§4.1.2/§4.2.10 MUST), **M2** reject a CH2 cipher-suite change vs the HRR (`hrr_suite`). Full suite green; **not deployed** (held for deploy gate). Follow-ups (low-pri): full CH1↔CH2 consistency diff (we only pin group+suite+early_data), HRR cookie emission (stateless retry), no-overlap negative test needs a hand-built/x448-capable client, and client-side L2 (tls_client re-emits `early_data` in CH2 on the resume+0-RTT+HRR combo — unreachable via ACME).
