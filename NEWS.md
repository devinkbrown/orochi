<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Orochi — NEWS

Release notes for the Orochi daemon. Newest first. Orochi is a clean-room,
pure-Zig IRC/IRCX server with a post-quantum CRDT mesh, an in-house TLS 1.3
stack, and session-preserving zero-downtime hot-upgrades. Version numbers track
`build.zig.zon`. Dates are the deploy date to the live IRCXNet nodes.

---

## Unreleased

Committed on `main` and pushed; not yet deployed to the live IRCXNet nodes. A
security + mesh-hardening pass on top of 0.3.0.

### Security
- **Hidden-channel roster leak closed.** `NAMES <channel>`, bare `NAMES`, `WHO
  <channel>`, and WHOX (`WHO <channel> %fields`) returned the full member list of
  a secret (`+s`) or private (`+p`) channel to non-members — enabling roster
  enumeration. A non-member non-oper now gets a bare `RPL_ENDOFNAMES 366` /
  `RPL_ENDOFWHO 315`, matching the WHOIS visibility gate. Fail-closed on an
  unknown viewer.
  (`fix(security): NAMES/WHO must not leak a secret/private channel roster`)
- **Suspended/forbidden accounts can no longer authenticate.** `ACCOUNT FORBID`
  and account suspension only blocked the session-token paths; `IDENTIFY`,
  SASL PLAIN, and SASL EXTERNAL (certfp) still let a locked account in, and
  SCRAM-SHA-256/512 + OAUTHBEARER bypassed the check entirely (they verify from
  stored material / an IdP token and never consulted account status). A locked
  account is now rejected at the single SASL-success chokepoint for **every**
  mechanism, with the generic `SASL authentication failed` surface (suspended vs
  forbidden vs bad-credential are indistinguishable — no enumeration).
  (`fix(security): gate SASL success on account status`)
- **AEAD key stack hygiene.** The Tsumugi secured-mesh record layer left a
  plaintext ChaCha key copy un-zeroed on the stack in `sealRecord`/`openRecord`
  (every post-handshake record); now `secureZero`'d on scope exit like its
  siblings — defense-in-depth against core-dump / co-resident disclosure.
  (`fix(crypto): secure-zero the AEAD key stack copy`)

### Fixed
- **Anti-entropy no longer stalls on busy channels.** A member's causal context
  was expanded into dense per-counter dots capped at 512; on a channel where one
  replica authored >512 membership adds, Merkle anti-entropy and full-state burst
  (handshake + RESYNC-after-USR2) silently failed with `Oversize`, diverging
  freshly-connected / hot-upgraded peers. Member context is now sent as a compact
  version-vector frontier (≤64 entries) via a new, canonically-encoded burst
  record kind — added alongside the unchanged dense form so legacy peers parse
  every currently-working burst. Canonical (sorted) encoding prevents an
  anti-entropy livelock where two replicas at the same state produced different
  bytes and repaired forever.
  (`fix(mesh): compact VV-frontier member context` + `canonicalize compact encoding`)
- **Timed IRCX `ACCESS` entries now actually expire** — temporary bans/access
  grants were effectively permanent. (`fix(ircx): expire timed ACCESS entries`)
- **RTCP feedback behind a report reaches the publisher** — compound RTCP packets
  are now fully parsed. (`fix(media): parse compound RTCP`)
- **Mesh route table** decrements `nick_count` on the rename-collision path,
  fixing a false `RouteTableFull`. (`fix(mesh): decrement nick_count on renameNick`)

### Hardened
- Certificate-Transparency quorum accepts **OCSP-delivered SCTs** as a third
  RFC 6962 source. (`feat(tls): OCSP-delivered SCTs`)
- `EventSeverity` ordering + `atLeast()` are comptime-pinned so a reordering can't
  silently weaken severity gates. (`harden(event-spine): comptime-pin EventSeverity`)

### Docs
- Full reference sweep verified against source: every command reference
  (connection, messaging, queries, channels, accounts-services, oper-moderation,
  informational, IRCX), the numerics table, the IRCv3 capability reference, and
  the mesh / crypto / event-spine architecture docs. Stale prior-project naming
  removed throughout.

## 0.3.0 — "Sumi-e onboarding" (2026-07-08)

The Torii onboarding + interop features and the first Sumi-e (v1.1) server
primitive, on top of the 0.2.0 security base.

### Added
- **Passwordless login (WebAuthn / passkeys).** New `WEBAUTHN` account command:
  register a passkey and sign in with no password. Configured with a new
  `[webauthn]` block (`rp_id`, `origins`); the feature is inert until set.
  (`feat(accounts): WEBAUTHN passkey registration + passwordless login`)
- **Registration attestation verification.** Passkey registration now verifies
  the authenticator attestation statement — `none`, `packed` (self + basic/AttCA
  via the x5c leaf), and `fido-u2f` formats — with fail-closed CBOR parsing.
  Optional hardening flags `[webauthn] require_uv` and `require_attestation`
  (both default **off**, so existing passkey flows are unchanged).
  Note: x5c leaf signatures are verified but not yet anchored to a trusted
  attestation root (tamper-evidence, not hardware provenance).
  (`feat(webauthn): verify registration attestation + optional require_uv`)
- **Named conversations (topics) within a channel.** A calm, opt-in threading
  model that rides existing IRCv3 machinery — no new persistence:
  - Message tag `+orochi/topic=<label>` on channel `PRIVMSG`/`NOTICE` names the
    conversation a message belongs to (label ≤ 50 bytes; no control chars, CR,
    LF, DEL, or comma; invalid labels are stripped fail-closed).
  - Channel registry PROP `orochi.topics` — a comma-delimited list (≤ 64 labels,
    ≤ 400 bytes) that auto-grows as topics are used and is op-manageable; it
    persists and mesh-propagates through the signed `CHANNEL_PROP` CRDT store,
    exactly like pins and ephemeral settings.
  - `CHATHISTORY` accepts an optional `+orochi/topic=<label>` tag to replay only
    a single conversation; absent = all messages.
  Untagged messages and non-tag clients are a pure pass-through — byte-identical
  on the wire when the feature is unused.
  (`feat: server-side named conversations (topics) within a channel`)
- **Discord-compatible incoming webhooks.** A Discord-shaped webhook endpoint so
  existing integrations post into a channel with no code changes (Torii interop).
  (`feat(webhook): Discord-compatible incoming webhook endpoint`)
- **v1.0 "Torii" packaging.** Reproducible, signed release tooling and a
  self-host quickstart: `packaging/release.sh`, `verify-release.sh`, a Dockerfile,
  and `orochi.quickstart.toml` (`docker run` → live chat in ~60s).
  (`feat(packaging): v1.0 Torii self-host quickstart + reproducible signed release`)

### Notes
- Fully backward-compatible: every new feature is opt-in or byte-identical when
  unused. `zig build test` — 6472/6476 passing (4 pre-existing skips).
- Config: nodes need a `[webauthn]` block for passkeys; topics need no config.

---

## 0.2.0 — "TLS hardening + media" (2026-07-07)

The large body of built-but-undeployed TLS/kTLS and media-plane work, shipped to
both live nodes with zero split-brain.

### Added
- **TLS 1.3 hardening:** downgrade sentinel, path-length checks, OCSP stapling +
  delegated responders, HelloRetryRequest, certificate compression, SNI-based
  cert selection, `record_size_limit`, ticket rotation.
- **kTLS kernel offload:** TX + RX, including **RX-rekey continuity** — survive a
  client `KeyUpdate` mid-stream with zero dropped bytes.
- **Post-quantum:** X25519MLKEM768 hybrid key exchange; SLH-DSA verify generalized
  to all 12 FIPS-205 parameter sets (alongside ML-DSA).
- **Media plane — DTLS-SRTP:** dual-mode DTLS 1.2 + DTLS 1.3 (RFC 9147) terminator
  for the SFU, RFC 8122 fingerprint exchange with fail-closed peer verification,
  SFU forwarding crypto, and mutual DTLS (client-certificate capture). Opt-in,
  default-off.
- Deterministic-simulation fuzz harnesses across the new crypto surface.

---

## Earlier

Pre-0.2.0 milestones (mesh, hot-upgrade, services-as-commands, IRCX/Event Spine,
the in-house TLS stack, the media plane) predate this file; see
`git log` and `docs/` for the full history. Highlights:

- **Mesh:** Suimyaku overlay (HyParView + Plumtree + witnessed-SWIM), delta-CRDT
  channel state, wall-clock-HLC causality, cross-mesh oper grants + session
  reclaim, zero-drop `USR2` hot-upgrades that carry live TLS + mesh links across
  `execve` (Helix).
- **Services as real commands:** `REGISTER`/`CHANNEL`/`TEGAMI`/`GHOST`/`SESSION`…
  with server notices for direct replies, `FAIL` for errors, and Event Spine
  publication for service state — no NickServ/ChanServ pseudo-clients.
- **IRCX + Event Spine:** `PROP`/`ACCESS`/`EVENT`, typed operator event plane,
  host cloaking, ephemeral rooms, channel stats.
