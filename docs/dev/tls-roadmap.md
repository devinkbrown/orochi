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
| 0.1 | **Wycheproof vectors → KAT harness** | M | Low | Google edge-case JSON vectors for ECDSA P-256/P-384, X25519, RSA-PSS, AES-GCM, ChaCha20-Poly1305, HKDF. Drops into existing `*_kat.zig` pattern. Finds signature-malleability / carry / edge bugs. |
| 0.2 | **Fuzz harnesses** | M | Low | Zig built-in fuzzing over the attacker-facing parsers: TLS record, handshake messages, X.509. Highest defensive ROI. |
| 0.3 | **BoGo shim + subset run** | L | Low | BoringSSL's protocol test runner against a shim. Design-spike first (which subset, shim wiring). |
| 0.4 | **Constant-time verification** | M | Low | dudect/ctgrind-style timing checks on ECDSA/X25519/RSA to validate the "CT by construction" claim. |

## Phase 1 — Surgical correctness fixes (parallelizable)

| # | Item | Effort | Risk | Files |
|---|------|--------|------|-------|
| 1.1 | ✅ **DONE** — **Downgrade sentinel (RFC 8446 §4.1.3)**: 1.2 engine stamps `DOWNGRD\x01` into `server_random[24..32]` at construction (covers full + resumed ServerHello). Follow-up: have `tls12_client` check it. | S | Med | `tls12_server.zig` |
| 1.2 | ✅ **DONE** — **Path-length basicConstraints enforcement**: `x509` retains `basic_constraints_path_len: ?u32`; validator rejects chains exceeding a CA's pathLen via the pure unit-tested `enforcePathLen` helper. | S | Med | `x509.zig`, `tls_client.zig`, `x509_selfsign.zig` |
| 1.3 | **Validator + sig-alg consolidation** — collapse the two chain validators; align accepted sig set (RSA-PSS everywhere, SHA-384/512-RSA on the tls_client path) | M | Med | `x509_verify.zig`, `tls_client.zig` |
| 1.4 | **Client-side PQ offering** — client never offers X25519MLKEM768 (server-only today) | S | Low | `tls_client.zig` |
| 1.5 | **record_size_limit (RFC 8449)** — negotiate + enforce both legs | M | Med | `tls_server.zig`, `tls_client.zig`, `tls12*.zig` |
| 1.6 | 🟡 **MECHANISM DONE** — **Ticket-key rotation**: `openTicketWithRotation` + `previous_ticket_key` on both TLS Configs (try current, then previous); unit-tested. **Follow-up:** daemon-level trigger (rotate on REHASH + carry `previous` across USR2). | M | Med | `tls_resumption.zig`, `tls12_server.zig`, `tls_server.zig` |

## Phase 2 — Server-facing protocol features

| # | Item | Effort | Risk | Notes |
|---|------|--------|------|-------|
| 2.1 | **Server-side OCSP stapling** — CertificateStatus + status_request response, response cache, must-staple; fetch via ACME/OCSP responder | M | Med | We consume staples but never produce them |
| 2.2 | **Server-side HelloRetryRequest** — recover when a client offers only groups we lack a key_share for | M | Med | Interop robustness; server currently can't HRR |
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
- 2026-07-05: Wave 2 (re-implemented vs HEAD, not stale worktrees) — 1.2 path-length LANDED (pure `enforcePathLen` helper + parse/decode tests). Remaining surgical: 1.5 record_size_limit, 1.6 ticket-rotation (wire it), 1.4 client-PQ, 1.3 validator-consolidation (redo cleanly — the wave-1 patch had an `oauth_jwt.zig` union-exhaustiveness break).
