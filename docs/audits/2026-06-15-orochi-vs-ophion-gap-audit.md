# Orochi Versus Ophion Gap Audit - 2026-06-15

This is the current source-verified gap document for comparing Orochi against
Ophion. It replaces the older overlapping gap/planning notes and should be
updated in the same commit as any future parity fix.

## Scope

- Orochi source: `/home/kain/orochi` at `c471a06`.
- Ophion reference: `/home/kain/ophion` at `15040367`.
- Method: compare current source and tests first, then use docs as navigation.
- Exclusions: STARTTLS, WEBIRC, ident, password/hostmask `OPER`, TS6/SJOIN,
  DCC proxy/filehost, and CPython/MAPI module parity are not Orochi product
  targets unless that decision changes.

## Do Not Reopen These Fixed Items

These were stale findings in older docs. Current Orochi source has live wiring
and tests for them:

- Config/runtime: `listen.webtransport`, `listen.proxy_protocol`,
  `listen.trusted_proxies`, `mesh.trust_roots`, `mesh.connect`,
  `media.max_upload_bytes`, `media.max_frame_bytes`, `sasl.enabled`,
  `sasl.realm`, and `[metrics]` all project into runtime config. WebTransport,
  PROXY trusted accept handling, live Prometheus `/metrics`, media caps, and
  SASL disable/realm behavior are not parser-only anymore.
- Transport/security: WebTransport is implemented as a QUIC + HTTP/3 +
  Extended CONNECT listener and bridges IRC bytes to the daemon. TLS certificate
  hot reload on REHASH and ACME IPv6 nameserver support exist.
- Mesh/S2S: secured S2S records are encrypted/authenticated; direct-origin
  state frames are signed; multi-hop MESSAGE, CHANNEL_PROP, and ENTITY_PROP
  carry origin signatures across re-forward; `SESSION_MIGRATE` frames and
  staged session handoff exist.
- IRCv3/history: LIST `C`/`T`, CHATHISTORY batch gating, TAGMSG typing/reaction
  storage/replay, edit/redact recipient capability filtering, event playback,
  extended-monitor capability gating, metadata visibility, MARKREAD on JOIN,
  no-implicit-names, channel-rename, labeled-response, standard-replies,
  multiline, read-marker, message editing, and message redaction are wired.
- SASL reporting: live lists are limited to wired mechanisms. SCRAM-SHA-256,
  SCRAM-SHA-512, and — over TLS 1.3 — SCRAM-SHA-512-PLUS (RFC 9266 tls-exporter
  channel binding, verified server-side against the gs2 header) are all live and
  advertised (the latter only once the session's exporter is available).
- IRCX/services: `AUTH`, `SACCESS` / `ACCESS *`, channel `ACCESS` enforcement,
  `MODE <nick> ISIRCX`, MODEX `806/807`, LISTX prefix handling, CREATE
  existing-channel rejection/template clone behavior, DATA/REQUEST/REPLY/WHISPER
  mesh relay, EVENT subject globs, services verification persistence, registered
  channel replay, AKICK/MLOCK/WARD replay, automode, and named oper privileges
  are implemented.
- Post-`c471a06` closures (rewritten per the closing rule at the bottom of this
  file): the `draft/search` CAP and `SEARCH` command are live — cap
  `dispatch.zig:350`, command `modules/messaging.zig:61` (`25eaf06`); SCRAM-SHA-512
  is a live SASL mechanism advertised in the sasl cap value `dispatch.zig:315`
  (`143295f`); and patterned `$z:<fingerprint>` and `$o:<class>` extbans are parsed
  and matched, `extban.zig:62,81` (`505b80a`). The `NETWORKICON` ISUPPORT token is
  now advertised from `[network] icon_url` when set (Ophion `n_url` parity),
  `server.zig` `buildIsupportTokens`. Bare-form-only extban claims and the
  "SEARCH missing" / "SCRAM-512 not live" findings no longer apply.
- 2026-06-16 parity cycle (implemented + reviewed; full suite `6977/6981`, 4
  skipped): a TLS 1.3 exporter (RFC 8446 §7.5 / 9266) + **SCRAM-SHA-512-PLUS**
  channel binding; **SESSION-TOKEN** SASL (TLS-only issuance, SHA-256 store,
  constant-time compare); **OAUTHBEARER** (clean-room JWT — algorithm bound to the
  configured key type, no `alg=none`/confusion, federated identities never
  auto-opered) + **ANONYMOUS** (gated, privilege-less guest); per-datagram
  **native-media MAC** (`[media].native_media_require_mac`); in-daemon **ACME
  renewal** (atomic flag + reactor-0 hot-swap); and secured-link **`SQUIT`**
  confirmed symmetric + tested.

## Real Missing Or Incomplete Features

Only genuinely-open, deferred, or by-design-excluded items remain below; the
fixed-items list above covers everything implemented.

### IRCv3 and SASL Parity

- **`draft/file-upload` / `FILEHOST` is missing by design.** Ophion has
  `m_filehost`. Orochi currently documents DCC/filehost as intentionally absent.
  If file sharing becomes an Orochi target, this needs a native design rather
  than resurrecting DCC proxy semantics.
- **`oper-tag` has no Ophion grounding.** The Ophion reference has no `oper-tag`
  cap or message tag, so there is nothing to port; left out until a concrete spec
  exists. (`network-icon` is implemented as the `NETWORKICON` ISUPPORT token — see
  the fixed items above.)

### Ophion-Specific Capability Names

Orochi sometimes implements the behavior under Orochi-native names instead of
the Ophion CAP names:

- `ophion/session-sync`: Orochi has `SESSION` and `SESSION_MIGRATE`, but does
  not advertise this Ophion-specific client capability.
- `ophion/ladon-media`: Orochi has media, native OPVOX/OPVIS UDP, and
  WebTransport, but not the Ophion LADON client capability value or
  `LADONMEDIA=1` compatibility surface.
- `ophion/prop-notify`: Orochi delivers PROP-change notifications gated on IRCX
  mode (there is no separate capability — being in IRCX mode is the gate; opers
  are auto-placed in IRCX on SASL login), with signed PROP/metadata propagation.
  If Ophion-client compatibility is required, add an alias or a compatibility
  mode explicitly.
- `tls`: Ophion exposes STARTTLS through `m_starttls`; Orochi intentionally uses
  implicit TLS listeners only.

### IRCX Parity

- **EVENT numeric fidelity is intentionally different today.** Orochi uses the
  `NOTE EVENT` wire form and subject globs; Ophion has the 808/809/810 and
  821-825 numeric families. Treat this as a compatibility gap only for clients
  that need Ophion numerics.
- **LISTX picture numeric `813` is not implemented.** Orochi has no channel
  picture feature, so `RPL_LISTXPICS 813` stays excluded unless a picture store
  is added.
- **Property-provider parity (provider-by-provider).** Core PROP, metadata-2,
  channel/user/member/entity propagation, and signed mesh re-forward exist. The
  live Orochi providers are registered in
  `src/proto/ircx_prop_providers.zig:143-162` (computed) over the store in
  `src/proto/ircx_prop_store.zig`. Mapping to Ophion's named provider modules:

  | Orochi provider(s) | Scope | Visibility | Ophion provider module |
  |---|---|---|---|
  | `name`, `topic`, `subject`, `language`, `creation_time`, `topic_setter`, `membercount`, `memberlimit`, `registered` | channel | public | `m_ircx_prop_channel_builtins` |
  | `ownerkey`, `hostkey`, `voicekey`, `memberkey` | channel | secret, per-tier read (OWNERKEY→owner, HOSTKEY→op, VOICEKEY→voice, MEMBERKEY→any member; opers always). Orochi has no `opkey` — `hostkey` is the op tier; `voicekey` is settable by op+ | `m_ircx_prop_ownerkey` / `m_ircx_prop_opkey` |
  | `onjoin` | channel | public (join timestamp) | `m_ircx_prop_onjoin` |
  | `onpart` | channel | public (part timestamp) | `m_ircx_prop_onpart` |
  | `member_of` | user | public (membership list) | `m_ircx_prop_member_of` |
  | `account` | user | public | account binding |
  | `user_profile` | user | public (`display/real/title/location/note`) | `m_ircx_prop_user_profile` (subset) |

  GeoIP keys (implemented): `COUNTRY`, `REGION`, `CITY`, `ASN`, `ASORG` are now
  exposed as read-only user PROP providers (`ircx_prop_providers.zig`), gated
  self-or-oper to match the WHOIS geo policy so a cloaked user's IP-geolocation is
  not world-readable. Remaining residual: Ophion's individual profile keys (`URL`,
  `GENDER`, `PICTURE`, `BIO`, `EMAIL`) beyond `display/real/title/location/note`.
- **IRCX oper extras — command-by-command mapping.** Orochi has native oper
  moderation commands and privilege gates under English names. Mapping Ophion's
  IRCX oper extras:

  | Ophion oper extra | Orochi equivalent | Status |
  |---|---|---|
  | `GAG` (silence) | `SHUN` / `UNSHUN` live oper silence (`oper_security.zig:147-148`); services `SACCESS` GAG-type access entries | covered, native surface |
  | `OPFORCE` | `FORCEOP` / `FORCEDEOP` (+ `FORCEJOIN` / `FORCEPART`), `services_ext.zig:48-51` | covered, renamed |
  | IRCX vhost tooling | `VHOST` command (`feature_misc.zig:49` → `handleVhost`) | covered |
  | `ANONKILL` (anonymized kill) | `KILL` only (`oper_security.zig:139`); no anonymized variant | intentionally absent |
  | godmode (hidden-oper) | no equivalent; Orochi has no hidden-oper concept | intentionally absent |

  The Ophion command names themselves are not aliased — same custom-not-clone
  stance as the Ophion-Specific Capability Names section above.

### Media And LADON

- **LADON media compatibility is not implemented.** Orochi media is not a LADON
  module port. It does not expose Ophion's `MEDIAFRAME`, `LADONADMIN`,
  `ophion/ladon-media` CAP value, or LADON media property/mode vocabulary as a
  compatibility layer.
- **SFU room sizing (config-driven runtime cap implemented).** `[media].max_participants`
  (default 64, range 1..256) is enforced at room join; the per-room (heap-allocated)
  inline roster ceiling is 256, native call leg 64. The roster stays inline/comptime
  by design (allocation-free hot path) — true unbounded runtime sizing would need a
  heap-roster redesign and is deliberately not done.
- **Kagura reorder window (config-driven implemented).** `[media].reorder_window_frames`
  (default 64, range 1..64) sets the runtime reassembly window, clamped to the
  comptime `window_cap`. The ring `window_cap`/`max_payload` ceilings stay comptime
  by design.
- **Native-media MAC end-to-end needs the client change.** The server side is
  implemented (see fixed items + `docs/reference/native-media-mac.md`); full
  coverage still needs the matching Nexus/Ocean client to compute the tag.

### Mesh, Ops, And Runtime

- **Web admin/dashboard is absent.** Orochi has static stats export and live
  Prometheus `/metrics`; it does not ship Ophion-style optional webadmin/Python
  module equivalents.
- **Plugin/module ecosystem parity is intentionally not present.** Ophion's C
  modules and CPython modules are not an Orochi target. If extensibility is
  needed, document the intended native/WASM surface separately and track it as an
  Orochi feature, not as C MAPI parity.

## Documentation Rules

- Do not list a key as parser-only unless `config_format.zig`, `config_boot.zig`,
  `main.zig`, and `server.zig` all confirm it is not projected or consumed.
- Do not infer missing IRCv3 support from this audit alone. Check
  `docs/reference/protocol/caps.md`, `dispatch.zig`, and the relevant
  `server.zig` handler/tests.
- Keep Ophion compatibility names separate from Orochi-native functionality. A
  feature can be implemented and still lack an Ophion-compatible CAP, command, or
  numeric surface.
- When closing one of the gaps above, remove or rewrite the bullet in this file
  in the same change.
