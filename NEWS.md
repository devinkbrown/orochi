<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Orochi — NEWS

Release notes for the Orochi daemon. Newest first. Orochi is a clean-room,
pure-Zig IRC/IRCX server with a post-quantum CRDT mesh, an in-house TLS 1.3
stack, and session-preserving zero-downtime hot-upgrades. Version numbers track
`build.zig.zon`. Dates are the deploy date to the live IRCXNet nodes.

---

## 0.5.2 (2026-07-13)

Multi-shard zero-drop hot-upgrades.

- **A USR2 hot-upgrade now preserves clients on ALL reactor shards.**
  `performUpgrade` previously sealed only reactor 0's clients + listener, so a
  multi-shard node (e.g. `num_shards=4`) had to cold-restart to deploy (the guard
  refused a USR2 that would drop clients on shards 1..N-1). Now sibling reactors
  are quiesced (parked via a CAS-claimed acq_rel handshake — a shard that can't
  park in 5 s refuses the upgrade rather than dropping anyone), every shard's
  clients are sealed with CLOEXEC cleared on every carried fd, all N per-shard
  SO_REUSEPORT listener fds are carried across execve, and each client is
  re-pinned to its deterministic fd-derived shard on adoption. No capsule format
  change (the shard is derived, not carried). The `num_shards>1` refusal is
  replaced by the quiesce fail-safe. Multi-shard `upgrade_smoke` proves clients on
  every shard survive (with the wss-mid-frame / token / umode / MONITOR / SILENCE
  guarantees intact).
  - *Rollback caveat:* a USR2 rollback from this to a pre-feature binary would
    black-hole the sibling per-shard listeners — roll back with a cold restart.

## 0.5.1 (2026-07-13)

Account-attribution turned ON (secure multi-device coexistence) + an oper-elevation
fix. Deployed to the live nodes.

- **Multi-device coexistence is now live and verified.** Account-attribution
  (Design C) is enabled: a client signs a login-time residence proof, the daemon
  verifies it against the account's replicated key, and a **proven** same-account
  claim now COEXISTS across devices/nodes as the real you — while a forged claim
  from a Byzantine peer takes the conservative UID path. F1 (mesh account-forgery)
  is closed for home/warm (converged) nodes via a non-forgeable, SASL-rooted
  account-key-authority gate on ENTITY_PROP ingest (P1) + store-side account
  blanking of untrusted claims (P2). Requires the onyx client (this release's
  companion) to sign residence proofs. Known bounded residual (deferred): a cold
  node relinking through a Byzantine burst source before converging can be
  poisoned (sticky, low exposure on a trusted mesh) — the fully-sound cold-node
  anchor is future work.
- **Oper elevation survives a session reclaim.** A SASL login that reclaimed a
  detached ghost session was re-granting a zero-privilege oper over the
  freshly-elevated session (→ 481 on the next privileged action / UPGRADE); the
  live grant is now preserved (union of live+restored privileges), no downward
  clobber.

## 0.5.0 (2026-07-13)

Multi-client, session-resume, and hot-upgrade-survivability release. A user can
now be present from more than one client at once, resume a session, and — after
this release — keep browser/onyx (wss) connections alive across a hot-upgrade.
Deployed to the live nodes (eshmaki.me + ircx.us).

### Multi-client & sessions
- **A newer login no longer kills your existing live session.** The mesh
  ghost-reclaim path only retires a connection that is already tearing down
  (`!victim.closing`); a second device anywhere on the mesh now coexists (the
  bouncer model, up to `[sessions] max_per_account`) instead of disconnecting
  the first. (`src/daemon/server.zig` `reclaimGhostSession`)
- **Cross-node DM fan-out.** A DM to a user with sessions on more than one node
  now reaches every device — the origin node relays a locally-resolved DM to the
  mesh instead of delivering only to its local session. Sent-copy mirroring to
  your own other devices is consistent. (`messageOne`, `deliverRelay`)
- **Session reclaim hardening.** The replay-ring nonce is burned only on a truly
  consuming outcome (redirects/denies are idempotent, no stranded capsule);
  local `SESSION RESUME` restores before consuming the ghost (fail-closed on
  decode failure); a CSPRNG-less boot disables reclaim rather than issuing a
  constant token. (`src/proto/session_reclaim_mesh.zig`)

### Hot-upgrade survivability (Helix)
- **The session registry survives USR2 (CRITICAL).** `performUpgrade` now seals
  the `.sessions` capsule and the `.clients` capsule carries each connection's
  reclaim token — before, every hot-upgrade wiped the multi-session/bouncer
  registry and invalidated every stored resume token.
- **wss/browser clients survive a hot-upgrade.** The `.ws_session` capsule now
  carries the WebSocket deframer's partial inbound frame + tx accumulator and
  carries open adapters unconditionally — previously an active browser client was
  mid-frame at the upgrade and got dropped every time ("everyone disconnects on
  upgrade"). (`ws_session` v2)
- **Full capsule-coverage audit.** `.clients` v4 also carries client umodes (a
  dropped `+i` was becoming visible after every upgrade), the partial inbound
  line, and the plaintext SendQ tail; **MONITOR** (`.monitor_list`) and
  **SILENCE** (`.silence_list`) lists are now carried (they were silently lost
  every deploy). Every format change is versioned with a legacy decode arm +
  cross-version test; `tools/upgrade_smoke.py` now asserts wss-mid-frame + TLS +
  bouncer-token + umode/MONITOR/SILENCE survival.
- **USR2 hardening.** Refuse a hot-upgrade on a multi-shard topology (only
  reactor 0's clients seal); bounded `PendingMigrations` (cap + TTL sweep + USR2
  carry); version-tolerant `migration_relay` decode for rolling deploys.

### Mesh operator & trust
- **The network-operator `*` prefix propagates reliably.** `rebroadcastLocalOpers`
  scans all reactors (an oper on a non-zero shard was never re-propagated),
  grants are re-minted inside their TTL, and the grant lookup is case-insensitive
  — fixing an intermittently-missing remote `*`.
- **Account-attribution substrate (Design C), gated OFF.** A per-claim residence
  proof (`IDENTITY RESIDENCE`, `ACCOUNTRESIDENCE` ISUPPORT) verified against the
  replicated account key lays the groundwork to close mesh account-forgery while
  preserving multi-device — but is fail-closed pending a non-forgeable
  account-key authority gate (rooted in SASL) and the onyx signer, so behaviour
  is unchanged (conservative UID path) this release.
- `renameNick` verifies the existing nick entry is homed on the origin node
  before applying a cross-node rename.

## 0.4.0 (deployed 2026-07-13)

Deployed to the live IRCXNet nodes. A security-, TLS-, and anti-abuse-hardening
pass on top of 0.3.0, plus the new standalone `yoroi` crypto CLI.

### TLS
- **Extended Master Secret (RFC 7627) is now REQUIRED by default** on the
  hardened TLS 1.2 profile, both server and client. A ClientHello that does not
  offer the `extended_master_secret` extension is aborted (`EmsRequired`); there
  is no silent downgrade. `require_extended_master_secret` can be set false only
  for legacy interop, and even then EMS is negotiated and used whenever offered,
  and TLS 1.2 tickets are only resumed for EMS-negotiated sessions.
  (`src/crypto/tls12_server.zig:96`, `src/crypto/tls12_server.zig:581`,
  `src/crypto/tls12_client.zig:89`)
- **TLS 1.3 handshake hardening.** A HelloRetryRequest now pins the cipher suite
  it commits to — the second ClientHello may not change it — and its `key_share`
  must supply exactly the group the server asked for (`src/crypto/tls_server.zig:484`,
  `src/crypto/tls_server.zig:594`). A 0-RTT attempt is bound to a freshness
  window: the server un-obfuscates the client's `obfuscated_ticket_age` against
  the ticket's sealed `ticket_age_add` and refuses `early_data` if it falls
  outside `early_data_age_skew_ms` (default 10 s) in either direction — the
  multi-node age-window replay defense the single-process binder ring cannot
  provide; the handshake still resumes at 1-RTT (`src/crypto/tls_server.zig:186`).
  ECH now emits `retry_configs` in EncryptedExtensions in response to an ECH
  handshake so a client with a stale config can recover (`src/crypto/tls_server.zig:240`).

### Cloaking & privacy
- **Argon2id cloak-key derivation.** The `[cloak] secret` passphrase is now
  stretched through Argon2id (memory-hard, ~64 MiB + iterations per guess) with a
  fixed domain-separation salt, replacing the previous bare `SHA256(secret)`. The
  whole cloak model rests on key secrecy — the IPv4 input space is fully
  enumerable — so a low-entropy operator passphrase must not be offline
  brute-forceable. Derivation stays deterministic, so cloaked hosts remain stable
  across restarts and identical mesh-wide. **Migration:** the first boot after
  upgrade reshuffles every client's cloak ONCE, and pre-upgrade host/subnet
  `WARD` bans on the old SHA256-derived cloaks do NOT carry over
  (`previous_secret` grace covers only future rotations under the new KDF, not the
  SHA256→Argon2id transition). (`src/main.zig:472`)
- **Auth-split epoch anonymous cloaks.** New `[cloak] anon_epoch_secs` knob
  (default `86400` = 24 h). An UNAUTHENTICATED client now gets an OPAQUE cloak
  salted by the current wall-clock epoch (`floor(now/anon_epoch_secs)`), so a
  static-IP anonymous user is neither linkable across epochs nor leaks subnet
  co-membership. Logged-in clients are unaffected — they keep their stable,
  moderatable account/hierarchical cloak. `0` disables rotation (pre-2026-07
  behavior). (`src/daemon/config_format.zig:646`, `src/proto/cloak.zig:187`)

### Anti-abuse
- **Live-ward enforcement.** A newly-added or mesh-propagated `WARD` now acts on
  already-connected clients immediately instead of only refusing their next
  reconnect — a network ban bites during a live raid, not one reconnect later.
  The sweep reuses the same matcher as the registration checkpoint (facets +
  previous-cloak-key fallback); oper sessions and S2S links are exempt.
  (`src/daemon/server.zig:18713`)

### Tooling
- **`yoroi` — a standalone, openssl-parity crypto CLI.** `zig build` now also
  produces `zig-out/bin/yoroi`, a pure-Zig toolkit over the same crypto substrate
  the daemon uses. Verbs: `x509`, `genpkey`, `pkey`, `req`, `dgst`, `verify`,
  `rand`, `ciphers`, `asn1parse` (with `s_client`/`s_server`/`enc`/`ocsp`/`crl`
  reserved, exit 3). Scriptable exit codes: `0` ok, `1` failed, `2` usage, `3`
  not implemented. Focused tests: `zig build test-cli`.
  (`src/cli/yoroi_main.zig:15`, `build.zig:458`)

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
- Groundwork for a dedicated adversarial **exploit/attack test harness** —
  protocol fuzzing and abuse-path regression tests aimed at the parser, auth, TLS,
  and admission surfaces (`docs/research/exploit-suite-blueprint.md`).

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
