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

## Phase 2 — Server-facing protocol features

| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 2.1 | ✅ **COMPLETE** — server-side OCSP stapling, wire + producer. **Wire (inc 1-5):** ocsp.buildRequest[ForCerts]; x509 AIA-URL + must-staple + CertID inputs; TLS 1.3 CertificateEntry staple; TLS 1.2 CertificateStatus (gated, mirrors 1.3). Both legs staple `Config.ocsp_staple` only when the client offers status_request (byte-identical otherwise). **Gate (inc 6):** `ocsp.isStapleServable` (parse→successful→issuer-signed→good→thisUpdate≤now<nextUpdate±skew, throw-free), `x509.generalizedTimeToEpoch`, `http_fetch.post`. **Publish (inc 7):** `config.tls_ocsp_staple` + `publishOcspStaple`/`maybeSwapOcspStaple` reactor-0 atomic-swap (mirrors ACME reload); 1.2 stapled only when it shares the 1.3 leaf; staple cleared on cert reload. **Producer (inc 8):** `ocsp_staple.Service` background thread — fetch AIA → verify → freshness-gate → cache last-good → publish; revoked-own-cert logs CRITICAL; refresh at thisUpdate→nextUpdate halfway clamped [5m,24h]. `[ocsp]` config + main.zig wiring (gated on `[tls]` + on-disk cert_path). **Follow-up (low pri):** 1.2 client-side round-trip test; delegated-responder (id-kp-OCSPSigning) support; exponential backoff on fetch failure. | M | Med | `ocsp.zig`, `x509.zig`, `tls_server.zig`, `tls12_server.zig`, `tls_extension.zig`, `ocsp_staple.zig`, `http_fetch.zig`, `server.zig`, `config_format.zig`, `main.zig` |
| 2.2 | ✅ **COMPLETE** — server-side HelloRetryRequest (RFC 8446 §4.1.4 + §4.4.1). When a ClientHello offers no key_share the server can use but advertises a group it supports (via `supported_groups`), the server sends one HRR — a ServerHello with the magic random + a bare-group key_share — reusing `supported_groups.selectPreferred` (prefs x25519 › secp256r1 › x25519mlkem768). Transcript rewritten with the `message_hash` synthetic (type 254) before folding in the HRR; new `wait_second_client_hello` state; ClientHello2 is pinned to exactly the requested group (extra/other shares dropped, else `BadHandshake`); only one HRR per connection; 0-RTT skipped on the bounced hello. The in-repo `tls_client` HRR path was made real+compliant (single-share CH2 via `retry_key_share_group`, offered-share-aware rejection) and drives a full loopback interop test (withheld shares → HRR → retry → data both ways). Wire byte-identical for normal handshakes (any usable share ⇒ no HRR). | M | Med | `tls_server.zig`, `tls_client.zig`, `supported_groups.zig` |
| 2.3 | **Certificate compression (RFC 8879)** — zstd/brotli; smaller handshakes | M | Low | Both BoringSSL + WolfSSL have it |
| 2.4 | **SNI-based cert selection** — client sends SNI, server ignores it; prereq for multi-cert + ECH | M | Low | |

## Phase 3 — Performance

| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 3.1 | **kTLS (kernel TLS offload)** — see [design](tls-design/ktls.md) | M–L | Med | Biggest throughput/CPU win. **Design correction (wave 1):** kTLS state is *kernel socket state that survives `execve`*, and we already carry client fds across USR2 — so a TX-offloaded socket keeps encrypting on the successor with **zero key re-injection** (add a 1-bit "offloaded" marker to the snapshot). The USR2 collision I'd assumed largely dissolves. **S2S is NOT TLS** (Tsumugi/Suimyaku) so it's out of scope — the only eligible sockets are client-facing implicit-TLS + wss. Recommended: **TX-only first** (RX kept userspace; RX extraction is fragile), rolled out to the wss media/upload data-plane before interactive IRC clients. |

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
    - **Multi-day features (scoped by the design docs, need dedicated sessions):** 2.2 server HRR, 2.3 cert compression, 2.4 SNI selection, 3.1 kTLS, 4.x wire-or-cut SCT/CRL/DTLS.
- 2026-07-05: **2.1 server OCSP stapling COMPLETE** (inc 6-8): servable gate + generalizedTimeToEpoch + http_fetch.post (inc 6); server publish/swap plumbing (inc 7); `ocsp_staple.Service` fetcher + `[ocsp]` config + main wiring (inc 8). Full suite green; **not deployed** (held for deploy gate). Remaining follow-ups are low-priority (1.2 client round-trip test, delegated responders, fetch backoff).
- 2026-07-05: **2.2 server HelloRetryRequest COMPLETE.** Server parses `supported_groups`, HRRs (once) for the preferred mutually-supported group when no usable key_share is offered, rewrites the transcript with the `message_hash` synthetic, and pins ClientHello2 to the requested group. Reused `supported_groups.selectPreferred`. Turned the in-repo `tls_client`'s previously-untested HRR handling into a real, RFC-compliant path (single-share CH2, offered-share-aware rejection) to drive a full loopback interop test. `zig-code-reviewer`: **Approve-with-nits, no CRITICAL/HIGH** (transcript/pinning/no-loop/0-RTT-ordering/memory-safety all verified); applied both MEDIUM CH2-hardening fixes — **M1** reject `early_data` in CH2 (§4.1.2/§4.2.10 MUST), **M2** reject a CH2 cipher-suite change vs the HRR (`hrr_suite`). Full suite green; **not deployed** (held for deploy gate). Follow-ups (low-pri): full CH1↔CH2 consistency diff (we only pin group+suite+early_data), HRR cookie emission (stateless retry), no-overlap negative test needs a hand-built/x448-capable client, and client-side L2 (tls_client re-emits `early_data` in CH2 on the resume+0-RTT+HRR combo — unreachable via ACME).
