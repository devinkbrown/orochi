# Orochi Versus Ophion Gap Audit - 2026-06-15

This is the canonical current gap document. It replaces the stale gap/planning
documents deleted in the same cleanup:

- `docs/audits/2026-06-14-ircx-ircv3-irc-feature-gap-audit.md`
- `docs/planning/14-ircx-remainder.md`
- `docs/planning/21-protocol-gaps.md`
- `docs/planning/22-irc-gap-sweep.md`
- `docs/planning/23-ircv3-upstream-research.md`
- `docs/reference/ircx/CONFORMANCE.md`

## Scope

- Orochi source: audit baseline `main` at `72ad029`; repaired through the
  2026-06-15 implementation pass on `main`.
- Ophion reference: `/home/kain/ophion` at `15040367`.
- Method: read source first, use older docs only as historical hints, and keep
  only gaps that still exist in the current source.
- Exclusions: STARTTLS, WEBIRC, ident, and password/hostmask `/OPER` are not
  parity targets for Orochi unless that product decision changes.

## Already Implemented - Do Not Duplicate

These were frequent stale-document claims but are live now:

- Channel `OID`, `created_unix`, `topic_time`, and `World.cloneChannel`.
- `CREATE`, cloneable/full-channel auto-clone paths, `KNOCK +u`, and `LISTX`
  metadata wiring for creation/topic times, subject, language, and registration.
- CAP LS/LIST/REQ/END flow, backend-gated SASL advertisement, REGISTER/VERIFY
  account commands, message-tag validation, SETNAME capability gating, MONITOR
  dynamic notifications, and core event-playback storage paths.
- IRCX `ACCESS` and services `CHANNEL ACCESS`/`AKICK` command handlers exist.
  Their remaining gaps are enforcement, persistence, and Ophion numeric/semantic
  parity, not total absence.
- `require_secured` exists for S2S and MeshPass responder enforcement exists.
  The remaining S2S issue is stronger identity/origin enforcement, not lack of
  any security switch.

## Priority 0 / 1 Repair Queue

1. S2S origin integrity and peer pinning.
2. Services durability and live boot replay.
3. IRCv3 history/capability correctness.
4. IRCX AUTH/SACCESS/PROP/EVENT/MODEX/LISTX parity.
5. Runtime config, PROXY, TLS reload/verification, metrics/admin, and media
   hardening.

## Repair Status After 2026-06-15 Implementation Pass

Closed in the repair pass:

- Direct-owned S2S state frames now reject mismatched origins, count rejected
  frames, and log the drained audit signal in both secured and plaintext S2S
  loops. Peer pinning and `[mesh].trust_roots` are wired into secured S2S.
- Mesh channel state now carries parameter modes (`+k`, `+l`, `+j`, `+f`),
  private/hidden state, and IRCX extended flags, with split-recovery burst,
  MLOCK-preserving inbound apply, and server/link regression coverage.
- S2S message relay now preserves `STATUSMSG` minimum rank and reuses local
  channel/direct-message policy gates for inbound relay delivery.
- `LIST C/T`, CHATHISTORY `BATCH` gating, TAGMSG typing/reaction replay,
  edit/redact recipient capability filters, extended-monitor event caps,
  metadata visibility reads, MARKREAD-on-JOIN, standalone typing delivery, SASL
  mechanism honesty, and extban store-time validation are wired and tested.
- IRCX live surfaces now cover `MODE <nick> ISIRCX`, `AUTH`, `SACCESS` /
  `ACCESS *`, channel `ACCESS` join overrides, prefixed channel handling,
  MODEX `806/807`, EVENT aliases, CREATE existing-channel rejection/basic modes,
  and LISTX prefix parity.
- Services now persist account email verification state, replay registered
  channels into live `+r`, replay MLOCK/AKICK/WARD, apply services access
  automode, kick current AKICK matches, add WARD compatibility aliases, and gate
  sensitive oper commands by named privileges.
- Runtime config now wires PROXY trusted accept handling, `mesh.trust_roots`,
  `media.max_upload_bytes`, `media.max_frame_bytes`, `sasl.enabled`,
  `sasl.realm`, TLS chain validation, native-media sender binding coverage, and
  atomic stats-file export. `listen.webtransport` is parsed and explicitly
  logged as not implemented.

## Repair Status After 2026-06-15 Agent Pass

A follow-up agent pass began with a read-first re-verification of every section
against current source. That verification found several "still open" items had
already been closed by the prior commit and were stale in this doc (see
"Corrected stale findings" below). The remaining genuine gaps were then closed
in disjoint, individually test-verified commits.

Closed in this pass:

- **Secured S2S CRDT stream is now encrypted and link-authenticated.** The
  Tsumugi PQ-hybrid AKE derived per-direction keys but never applied them, so the
  post-handshake CRDT stream (MESSAGE/MEMBERSHIP/CHANNEL_MODE_*/TOPIC/NICKCHANGE)
  traveled in plaintext over secured links. It is now wrapped in a length-prefixed
  ChaCha20-Poly1305 AEAD record layer keyed on the `Established` send/recv keys
  with per-record nonce counters bound as AAD; tamper or desync drops the link.
- **Cross-shard IRCX DATA/REQUEST/REPLY/WHISPER** now relay over mesh (previously
  cross-shard `WHISPER` silently returned `ERR_NOSUCHNICK` and channel `DATA`
  never reached remote members). The relay schema gained the four verbs plus
  `data_tag`/`recipient`; inbound delivery re-applies local speech/NOWHISPER/
  NOCOMICDATA policy with multi-hop dedup and fails closed without flooding peers.
- **SACCESS GRANT bypass + persistence.** `enforceServerAccess` now checks GRANT
  first (GRANT-overrides-DENY, matching Ophion), and SACCESS entries persist to
  the durable `bans` family and replay at boot before connections are accepted.
- **CREATE clone/template** now accepts the optional source-channel third
  parameter and clones its modes via `world.cloneChannel`.
- **TLS certificate hot reload on REHASH** re-reads and atomically swaps cert/key
  material into a server-owned reload generation; failures keep current certs.
- **ACME IPv6 nameservers** are wired (AF_INET6 UDP query path); previously
  IPv6-only resolver environments failed.
- **Ops/deployment assets:** hardened `etc/systemd/orochi.service` (ExecReload =
  SIGUSR2 hot upgrade), `tools/runtime_smoke.py` fresh-boot smoke test, and a
  `zig build package` step.

Corrected stale findings (already implemented before this pass; the doc was
behind the code):

- Channel PROP **does** propagate over mesh: live `PROP SET/DELETE` fan out via
  `announceChannelProp` → `sendChannelProp` to every established peer with HLC
  clocks and inbound LWW apply.
- MODEX already uses numerics `806/807`; IRCX `AUTH` is registered and bridges to
  the SASL/account backend; `SACCESS` is registered with a real store and
  enforcement; `MODE <nick> ISIRCX`, MODEX channel-prefix parsing, and the whole
  IRC/IRCv3/history/tags section (LIST C/T, CHATHISTORY batch gating, TAGMSG
  replay, edit/redact filtering, extended-monitor/metadata visibility, MARKREAD
  on JOIN, SASL mechanism honesty, extban validation) were already done and
  tested. Services durability (email verify, `+r` replay, AKICK, MLOCK, WARD) and
  named oper-privilege gates were likewise already complete.

Still open (genuine future work, larger or cross-component):

- **Full Ophion-class live session migration** over mesh: the `migration_relay` /
  `session_migrate` modules exist and are tested but are not wired to a live S2S
  frame or the reclaim path. `SESSION RESUME` remains reclaim/redirect-oriented.
- **End-to-end per-frame signed envelopes** for routed/multi-hop frames. Secured
  links now AEAD-encrypt + authenticate point-to-point; multi-hop origin signing
  is still open.
- **Live HTTP `/metrics`/admin endpoint** (file-export + internal Prometheus text
  exist; a live endpoint is a convenience, not a correctness gap).
- **Datagram-level native-media sender authentication** (TOFU address binding
  exists; per-stream token auth needs a coordinated browser-codec wire change).
- Account/user/member PROP propagation (channel PROP already propagates),
  EVENT subject-mask on category subscriptions.

Intentional divergences / out of scope (NOT gaps): EVENT numerics `808-825`
(Orochi uses the `NOTE EVENT` wire form by design), `RPL_LISTXPICS 813` (no
picture feature), `sasl.realm` wire emission, `listen.webtransport`, CA
client-auth (CertFP model instead), and DCC proxy/filehost (documented exclusion).

## Repair Status After 2026-06-15 Implementation Pass

Closed in the repair pass:

- Direct-owned S2S state frames now reject mismatched origins, count rejected
  frames, and log the drained audit signal in both secured and plaintext S2S
  loops. Peer pinning and `[mesh].trust_roots` are wired into secured S2S.
- Mesh channel state now carries parameter modes (`+k`, `+l`, `+j`, `+f`),
  private/hidden state, and IRCX extended flags, with split-recovery burst,
  MLOCK-preserving inbound apply, and server/link regression coverage.
- S2S message relay now preserves `STATUSMSG` minimum rank and reuses local
  channel/direct-message policy gates for inbound relay delivery.
- `LIST C/T`, CHATHISTORY `BATCH` gating, TAGMSG typing/reaction replay,
  edit/redact recipient capability filters, extended-monitor event caps,
  metadata visibility reads, MARKREAD-on-JOIN, standalone typing delivery, SASL
  mechanism honesty, and extban store-time validation are wired and tested.
- IRCX live surfaces now cover `MODE <nick> ISIRCX`, `AUTH`, `SACCESS` /
  `ACCESS *`, channel `ACCESS` join overrides, prefixed channel handling,
  MODEX `806/807`, EVENT aliases, CREATE existing-channel rejection/basic modes,
  and LISTX prefix parity.
- Services now persist account email verification state, replay registered
  channels into live `+r`, replay MLOCK/AKICK/WARD, apply services access
  automode, kick current AKICK matches, add WARD compatibility aliases, and gate
  sensitive oper commands by named privileges.
- Runtime config now wires PROXY trusted accept handling, `mesh.trust_roots`,
  `media.max_upload_bytes`, `media.max_frame_bytes`, `sasl.enabled`,
  `sasl.realm`, TLS chain validation, native-media sender binding coverage, and
  atomic stats-file export. `listen.webtransport` is parsed and explicitly
  logged as not implemented.

Still open or intentionally partial (superseded by the Agent Pass section above;
kept for history):

- Full signed envelopes for routed/multi-hop message frames remain open; the
  current pass closes direct-owned state origin rejection and audit visibility.
- `SESSION RESUME` is still reclaim-oriented, not full Ophion-class live session
  migration with caps/channels/marks/history cursors over mesh.
- Server-level IRCX SACCESS/ACCESS state is process-local. Account/user/member
  PROP persistence/propagation, full EVENT hook/numeric parity, and complete
  DATA/REQUEST/REPLY/WHISPER mesh semantics remain partial.
- `RPL_LISTXPICS 813`, complete CREATE/clone template parity, ACME renewal/hot
  cert reload, live HTTP `/metrics`/admin, datagram-level media authentication,
  and packaged deployment/systemd smoke assets remain future work or deliberate
  scope decisions.

## Mesh And S2S

### Unsigned Cross-Node Payloads

`src/substrate/suimyaku/s2s_frame.zig` carries only type and payload. Message,
membership, topic, list, and mode frames carry asserted `origin_node` values but
not per-frame signatures. `OPER_GRANT` has stronger validation than normal user
and channel state. This leaves remote membership, channel modes, and routed
messages dependent on the link trust boundary rather than verifiable origin.

Repair target:

- Add a signed envelope or per-frame signature for MESSAGE, MEMBERSHIP,
  CHANNEL_MODE_FLAGS, CHANNEL_LIST, CHANNEL_PROP, TOPIC, and NICKCHANGE.
- Reject frames whose claimed origin does not match the verified peer identity.
- Carry the verified origin into policy decisions and audit logs.

### Secured S2S Still Allows Weak Deployment

`mesh.require_secured` can reject plaintext S2S, but the default is false.
`expected_remote` exists in secured link config, yet current server construction
does not fully pass a pinned remote identity into every inbound/outbound path.

Repair target:

- Treat peer identity pinning as a first-class config path.
- Fail closed when a secured mesh peer is configured but cannot be verified.
- Add tests for plaintext refusal and wrong-peer rejection.

### Mesh Channel State Is Incomplete

Boolean channel sync covers only selected flags. Parameter and extended modes
are still local-only or partially local-only: `+k`, `+l`, `+j`, `+f`, private /
hidden state, and several IRCX extended flags. Split recovery has the same
missing state families as normal sync.

Repair target:

- Add mesh frames for parameter modes and IRCX extended flag state.
- Preserve MLOCK and local policy authority when applying remote state.
- Add split-recovery tests for param modes, list modes, and IRCX flags.

### STATUSMSG And Speech Policy Are Lossy Over S2S

Local `PRIVMSG @#chan` / `+#chan` parsing exists, but relay sends only the bare
channel target. Inbound S2S channel delivery also does not reapply the full local
speech policy: no-CTCP, no-format, opmoderate, and status-rank delivery are not
equivalent to local channel send handling.

Repair target:

- Carry minimum channel rank in the message relay schema.
- Reuse one shared local/remote channel-send policy function.
- Add S2S tests for `STATUSMSG`, `+C`, `+T`, `+U`, and no-format stripping.

### Direct Message Policy Is Not Symmetric

Inbound relay direct messages check registration and silence-like gates, but do
not match local direct-message policy for user `+g`/ACCEPT and user `+C`.
Unknown-nick routing can also flood mesh peers before a route is known.

Repair target:

- Reuse the local direct-message policy on inbound relays.
- Add a route-query or no-flood default for unknown remote nicks.

### Session Resume Is Reclaim, Not Full Migration

`SESSION RESUME` can reclaim local and mesh tokens, but it does not restore the
full client state expected from Ophion-class bouncer migration. Helix handoff
support exists, but transport of live session state over mesh is still unwired.

Repair target:

- Define portable session-state frames for channels, away/account state,
  marks, caps, and pending history cursor.
- Wire Helix-style state import/export to mesh resume.

## IRC, IRCv3, History, And Tags

### `LIST` `C` / `T` Filters Still Use Zero Ages

`handleList` parses ELIST filters but passes zero `created_ago`, `topic_age`,
and current time values. `world.ChannelView` exposes real `created_unix` and
`topic_time`, so the missing piece is handler wiring.

Repair target:

- Feed wall-clock age data into the LIST matcher.
- Add tests for `LIST C<`, `C>`, `T<`, and `T>` filters.

### CHATHISTORY / Bouncer Replay Emits `BATCH` Without `batch`

History replay paths can emit `BATCH` while only gating on chathistory-style
capabilities. Ophion gates batch frames on the `batch` capability itself.

Repair target:

- Require `batch` before sending `BATCH`.
- Fall back to non-batch replay when a client has history caps but lacks
  `batch`.

### TAGMSG Reactions / Typing Are Not Fully Stored Or Replayed

Reaction and typing tags are handled live, but stored history/event playback does
not preserve the client-tag fields needed to replay channel TAGMSG events with
Ophion-compatible behavior.

Repair target:

- Extend history entries with command type and client tags.
- Record and replay eligible TAGMSG reactions/typing notifications.

### EDIT / REDACT Notifications Are Over-Broadcast

Senders are capability-checked, but channel recipients are not filtered by the
matching draft edit/redact capabilities before notification delivery.

Repair target:

- Filter per recipient for `draft/message-editing` and
  `draft/message-redaction`.
- Add mixed-capability channel tests.

### Extended MONITOR And Metadata Visibility Are Too Broad

`extended-monitor` delivery can include event families without checking the
event-specific capability. `metadata-2` visibility tokens are stored but not
enforced consistently on reads.

Repair target:

- Require both `extended-monitor` and each event family's capability.
- Enforce metadata visibility on every read path, not just write/storage.

### MARKREAD And Typing Delivery Have Capability Edges

Ophion sends stored read markers on JOIN. Orochi has MARKREAD storage paths but
does not push the marker automatically on join. Draft typing delivery can also
miss recipients that support `draft/typing` but not `message-tags`.

Repair target:

- Emit channel/account MARKREAD state on JOIN to capable clients.
- Add a standalone `draft/typing` delivery path when `message-tags` is absent.

### SASL Mechanism Reporting Overstates SCRAM-SHA-512

Live CAP SASL supports PLAIN, EXTERNAL, and SCRAM-SHA-256. Some numerics still
advertise SCRAM-SHA-512. Ophion has SCRAM-SHA-512 support.

Repair target:

- Either implement SCRAM-SHA-512 or remove it from every live numeric/listing.
- Add a test that CAP and numeric mechanism listings agree.

### Extban Validation Lags Ophion

Orochi advertises `EXTBAN=$,acgmrz`; `$z:<fp>` and `$o:<token>` parse paths are
not fully semantically enforced, and unknown/malformed `$` masks can degrade to
literal host globs.

Repair target:

- Validate extban kinds before storing them.
- Implement the missing `$z`/`$o` semantics or stop accepting them.
- Reject malformed extbans rather than silently treating them as host masks.

### DCC Is Parser-Only

CTCP DCC detection exists, but there is no DCC proxy/filehost behavior analogous
to Ophion's optional Python modules.

Repair target:

- Decide whether DCC proxy/filehost is in scope for Orochi.
- If in scope, add explicit command/module surfaces; if out of scope, document
  it as an intentional exclusion.

## IRCX

### `MODE ISIRCX` Variant Is Narrower

Orochi supports `MODE ISIRCX`; Ophion accepts both `MODE ISIRCX` and
`MODE <nick> ISIRCX`.

Repair target:

- Accept the nick-qualified form and preserve the existing unqualified form.

### IRCX `AUTH` Is Parser-Only

`src/proto/ircx_auth.zig` exists, but the IRCX module does not register a live
`AUTH` command. Ophion maps AUTH onto SASL/account authentication behavior.

Repair target:

- Register `AUTH`.
- Bridge PLAIN/EXTERNAL/SCRAM behavior to the existing SASL/account backend.
- Keep the IRCX numerics consistent with the actual live mechanisms.

### Server-Level `SACCESS` / `ACCESS *` Is Missing

The parser models SACCESS-like access operations, but there is no command
registration, storage, or enforcement for server-level IRCX access lists.

Repair target:

- Add a server-level access store and command registration.
- Define enforcement points before exposing the feature.

### Channel `ACCESS` Semantics Differ

Orochi deny gates run before IRCX access auto-status. Ophion lets access levels
override some join denials, depending on the list entry and channel state.

Repair target:

- Reconcile deny-first behavior against Ophion's access override matrix.
- Add join tests for deny, allow, auto-op, invite-only, and key/limit cases.

### `PROP` Coverage Is Partial

Channel built-ins exist, but account entities, durable account/user properties,
full user profile providers, ONJOIN/ONPART behavior, and user/member/account
property propagation are incomplete.

Repair target:

- Define durable stores for account/user/member property namespaces.
- Add property propagation over mesh.
- Add ONJOIN/ONPART hooks if they remain an IRCX target.

### `EVENT` Is A Partial Event Spine

Current EVENT support covers operator categories, broadcast, and observation.
It does not yet match Ophion's CHANGE/DELETE/CLEAR/STATUS behavior, subject
masks, broad hook coverage, or numeric fidelity across the 808/809/810 and
821-825 families.

Repair target:

- Add an EVENT conformance table from current Ophion behavior.
- Expand event categories and numerics only with live hooks behind them.

### DATA / REQUEST / REPLY / WHISPER Mesh Parity Is Incomplete

Local DATA-family commands exist. Cross-node propagation and some Ophion-style
request/reply semantics are still incomplete.

Repair target:

- Add typed-message relay frames or extend the existing message relay schema.
- Preserve verb, tag, sender, target, and policy result across nodes.

### MODEX Numeric And Parser Parity Differs

Orochi currently uses 820/821 for MODEX listing, while Ophion uses 806/807.
Parser support also needs to be checked for every accepted channel prefix and
named-mode spelling.

Repair target:

- Match Ophion numerics or document a deliberate Orochi divergence.
- Add parser tests for `#`, `&`, and prefixed channel names.

### LISTX Prefix / Numeric Parity Still Differs

LISTX now uses real channel metadata, but parity gaps remain: accepted channel
prefixes, picture/list numeric `813`, and exact result family behavior.

Repair target:

- Accept all live channel prefixes.
- Add or explicitly exclude `RPL_LISTXPICS 813`.

### CREATE / OID / CLONE Semantics Differ

Orochi has OID and clone support, but Ophion-compatible behavior differs:
requested initial modes are not fully applied by CREATE, existing-channel
handling differs, and clone/template state differs.

Repair target:

- Reject existing CREATE targets when Ophion does.
- Apply requested initial modes.
- Decide whether Orochi's richer clone state is intentional or should match
  Ophion more closely.

## Services And Operator State

### REGISTER / VERIFY Email State Is Not Durable

Verification tokens are process-local, and account records do not persist email
verification state during registration. Ophion persists account email data.

Repair target:

- Store email and verification state in the account backend.
- Make tokens restart-safe or expire/reissue cleanly after restart.

### Registered Channels Are Not Replayed Into Live `+r`

`chanregs` persist, but boot does not replay them into the live world. `+r` is
only marked on new register/drop hooks.

Repair target:

- Iterate persisted channel registrations during boot.
- Materialize registered channels or at least mark live channels as registered.

### Services `CHANNEL ACCESS` Is Not Live Automode

Services access entries authorize service commands, but join-time op/voice/owner
status is wired to the separate IRCX access store.

Repair target:

- Decide whether services access and IRCX access should merge or bridge.
- Apply services access on join with tests for founder/op/voice levels.

### AKICK Persistence Does Not Restore Enforcement

AKICK records persist, but the live join gate checks only the process-local
mirror populated by live add/delete commands. Adding an AKICK also does not kick
currently present matching users.

Repair target:

- Rebuild the live AKICK mirror from persistent services state at boot.
- Kick current matching members when AKICK is added.

### MLOCK Is Process-Local

`CHANNEL SET MLOCK` stores mode locks in a server map, not the durable channel
record, so locks vanish across restart/hot rebuild.

Repair target:

- Add MLOCK fields to the durable channel record.
- Replay and enforce locks after boot.

### WARD / KLINE / DLINE / XLINE Parity Is Incomplete

The Warden registry is in-memory and local. Legacy K/D/G/X command names are
classified or parser-modeled in places, but not registered as live persistent
ban commands matching Ophion's ban database.

Repair target:

- Persist WARD entries and decide mesh propagation semantics.
- Register compatibility aliases or document WARD as the only supported surface.

### Oper Privilege Gates Are Too Broad In Places

Sensitive commands like `USERIP` and `UPGRADE` still use broad oper status
instead of named privileges such as `oper_spy` or `server_restart`.

Repair target:

- Audit every oper command against `src/daemon/oper.zig` privileges.
- Add tests for denied opers in limited classes.

## Config, TLS, Runtime, Media, And Ops

### Parsed But Not Wired Config Keys

The current remaining parsed-but-not-live keys are:

- `listen.webtransport`
- `mesh.trust_roots`
- `media.max_upload_bytes`
- `media.max_frame_bytes`
- `sasl.enabled`
- `sasl.realm`

`media.enabled` is live now and should not be listed as unwired.

### PROXY Protocol Has No Trusted Accept Path

`src/proto/proxy_protocol.zig` parses PROXY protocol, but there is no trusted
pre-IRC accept path equivalent to Ophion's trusted-proxy handling.

Repair target:

- Add listener-level PROXY v2 consumption before IRC/TLS/WebSocket framing.
- Gate it by trusted proxy source IPs.

### TLS Verification / Reload Parity Is Partial

TLS listeners and CertFP possession proof exist. A generic X.509 verifier
wrapper still has an integration TODO, revocation/CT parsing is not wired into
handshakes, and client certificates are not CA-chain client-auth.

Repair target:

- Wire the verifier path used by outbound/admin surfaces.
- Decide whether CA client-auth is in scope or keep CertFP-only as intentional.
- Add hot cert reload coverage with TLS listener continuity.

### ACME Is Out-Of-Band

`orochi acme-issue` writes cert/key and exits. There is no daemon renewal loop or
hot TLS reload path, and IPv6 nameservers are skipped in the current runner.

Repair target:

- Add renewal scheduling or document external ACME as the supported path.
- Add a hot reload command/path for refreshed TLS material.

### Metrics / Admin HTTP Parity Is Missing

Orochi can write static stats files and render Prometheus text internally, but
there is no live `/metrics` HTTP endpoint or web admin dashboard comparable to
Ophion's optional modules.

Repair target:

- Add a gated metrics endpoint or document file-export-only as intentional.
- Decide whether web admin belongs in Orochi or external tooling.

### Media Runtime Hardening Remains

Orochi has SFU control, RTP/STUN, native OPVOX/OPVIS UDP, and bridge headers.
Runtime media sizing is still partly comptime-bound, and native media sender
learning by stream id lacks per-datagram crypto authentication. S2S media
origin policy depends on the broader signed-origin work above.

Repair target:

- Wire media max frame/upload config.
- Authenticate datagram sender claims.
- Add mesh media policy tests after signed S2S frames land.

### Ops Tooling Parity Is Open

Orochi has an upgrade smoke test but lacks a comparable deployment/systemd asset
set and tarball smoke surface.

Repair target:

- Add systemd/deployment examples once the live install target is settled.
- Add smoke tests that cover a packaged runtime, config load, TLS, and upgrade.

## Documentation Follow-Ups

This cleanup updates the most obviously stale command/config/ISUPPORT reference
claims alongside the new audit. Future code repairs should update this document
first or delete the completed bullet in the same commit as the fix.
