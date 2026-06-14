# Orochi IRCX / IRCv3 / IRC Feature Gap Audit

Date: 2026-06-14
Branch scanned: `integ`

Scope: read-only source audit of `/home/kain/orochi` using 30 delegated audit scopes plus local grep review, combined with the earlier unwired/incomplete surface audit from the same date. No daemon source was changed for this report.

## Repair Run Status — landed on `main` @ `bcb61e6` (full suite 6606/6610 pass, 0 fail, 4 skip)

MeshPass shared-secret VERIFICATION on the responder (`bcb61e6`): the Tsumugi AKE responder now compares the inbound MeshPass (carried inside the encrypted, signed M1) against its own `[mesh].mesh_pass` and rejects on mismatch with `error.MeshPassMismatch`. Previously the responder only enforced an inbound *length* cap (Batch 3 `meshcap`) and then discarded the bytes — so a peer that knew the realm/prekeys but not the shared secret could still establish a link. Safety properties chosen to avoid mesh-flap on rollout: (1) the compare runs ONLY after the M1 signature verifies, so an unauthenticated peer can never probe the secret; (2) constant-time byte compare (`constantTimeEqlBytes`); (3) **fail-OPEN** when the responder's own `mesh_pass` is empty/unset — an upgraded node still links with a not-yet-configured peer; (4) **fail-CLOSED** only on a real mismatch, including when a configured responder receives an empty MeshPass. Reachable in production: `main.zig:219` config → `server.zig:3504 .mesh_pass = self.config.mesh_pass` → `SecuredLink.cfg` → `tsumugi_session.initResponder(cfg)` → `Responder.init` → the new gate in `Responder.recv`. Gated by four in-process 2-node handshake tests (matching → link; mismatch → rejected; unconfigured responder → fail-open accept; configured responder + empty peer pass → rejected). Full suite green.

draft/event-playback COMPLETE (`e213f35`): added the two cross-channel event types — NICK (recorded with the OLD prefix into every channel the user is in) and QUIT (recorded into each of the leaver's channels in `broadcastQuit`'s loop) — via a `recordHistoryEventSender` explicit-sender variant. event-playback now records the FULL IRC event set: TOPIC, PART, JOIN, KICK, MODE, NICK, QUIT — all cap-gated, replayed verbatim. The feature is done.


draft/event-playback EXTENDED to full channel-event coverage (`fdccd85`, `8e822f2`, `f131f9c`): the event renderer was generalized to `:sender CMD <body>` (body = full post-command text), so any event line replays verbatim. Recorded event types now: TOPIC, PART, JOIN, KICK, MODE — each via `recordHistoryEvent` at its broadcast site, cap-gated to `draft/event-playback` clients (others get messages only). MODE captures the applied modestring + params at the single channel-mode broadcast point. NICK is cross-channel and intentionally excluded from per-channel history. This is the complete client-facing event-playback feature.


draft/event-playback LANDED (`617b500`): was the one genuinely-big remaining client-facing gap (cap defined in `cap.zig` but unadvertised/unwired). Wired end to end — the Lotus history entry + `chathistory_cmd.Message` gained a `command` field (default `PRIVMSG`, static-lifetime, stored by reference not duped); the batch writer renders per-command; channel TOPIC changes record as TOPIC events (`recordHistoryEvent`); CHATHISTORY + bouncer-rewind replay event entries ONLY to clients that negotiated `draft/event-playback` (others get messages only); cap added to dispatch `CapId` + advertised. TOPIC is the first event type — MODE/JOIN/PART can follow the same path. Done incrementally with lotus/chathistory green at each step. (NB: this is the only "big item" from the planning-doc sweep that was a real gap; everything else was already implemented.)


Planning-doc gap sweep (`8160991`): worked the IRCX/IRC items in `planning/14-ircx-remainder.md`, `21-protocol-gaps.md`, `22-irc-gap-sweep.md`. MOST listed "big items" are ALREADY DONE (the docs are stale): channel OID + `created_unix` + `World.next_oid` (world.zig:212/295/1406); CLONEABLE `+d` / CLONE `+E` auto-clone-on-full (server.zig:6100-6209); SASL EXTERNAL + SCRAM-SHA-256 advertised + routed (dispatch.zig:301/1456); `$m` mute + `$z` secure extbans (extban.zig); LISTX/ELIST filter tokens (`elist.zig`); metadata-2 cap-gate; KNOCK `+u`. LANDED two genuine gaps: `$o` oper-status extban (the one standard extban missing from `NodeKind`; mostly for `+e`/`+I` since opers already bypass `+b`); IRCX PROP user `MEMBER_OF` provider (computed `userBuiltinGet`, WHOIS-filtered channel list). DEFERRED (genuinely big, not false-advertisable as a stub): `draft/event-playback` — the cap is defined in `cap.zig` but unadvertised/unwired; doing it right means extending the CHATHISTORY/Lotus store (entries are `{msgid,sender,text,timestamp}` with NO command-type field, so events can't be distinguished from messages), recording channel events (JOIN/PART/MODE/TOPIC) at their sites, and cap-gated replay rendering — a history-subsystem sub-project. PROP `user_profile` provider also deferred (no clear canonical data source — needs a decision on what it maps to).


Major item LANDED (`f2aea06`): cross-reactor `publishOperEvent` fan-out — oper events (SERVER_LINK, the opmoderate POLICY feed, KILL, ANNOUNCE) now reach opers on every shard, not just the publishing reactor. See the detailed entry below (with the correction of a phantom "multi-shard send-flush bug" that was actually a wrong test needle).


Mode-letter fix #2 (`dc69cfb`): channel ext flag **OPMODERATE reassigned `O`→`U`** (the sibling collision flagged after NOCOMICDATA). `O` is the enum-backed oper-only channel mode (only-opers-may-join, `ERR_OPERONLYCHAN` 520); raw `MODE +O` resolved to the enum first, so opmoderate was **unreachable/dead** — its speech-gate routing existed but the flag could never be set (also absent from CHANMODES/MODEX; audit §"MODEX" item 229). Reassigned to `U` per `mode_rearchitecture.md`, leaving `O` as oper-only; advertised `U` in CHANMODES; consistency test updated. The previously-dead enforcement is now exercised by a test: in a `+m`+`U` channel a muted member's PRIVMSG is delivered to ops only (rank≥2), not rejected. FOLLOW-UP (deferred): `mode_rearchitecture.md` wants held messages surfaced via an Event-Spine `chan.moderation.held` signal rather than the current raw op delivery — a semantic refinement, not a letter issue. The mode-letter space is now collision-free for the live ext flags ([[feedback_orochi_mode_letter_collisions]]).


Mode-letter fix (`c20f94b`): channel ext flag **NOCOMICDATA reassigned `Y`→`V`** — `Y` is the network-operator member-status PREFIX letter (`PREFIX=(YQqov)*!.@+`, `chanmode.oper_mode_letter='Y'`), so it was double-claimed across PREFIX and a channel mode (ambiguous MODE parse). New letter `V` (free, unreserved) applied across all six in-sync definition sites (chanmode_ext mode_specs+render_specs, svc_template, ircx_modex, ircx_modex_cmd) and **now advertised in CHANMODES** (was settable/rendered but unadvertised). The dormant enforcement is now wired: a `+V` channel refuses comic-chat `DATA` from non-op members with `ERR_NOCOMICDATA` (531, previously no live caller); ops/founder/network-opers bypass. NOTE: the sibling collision OPMODERATE on `O` (also double-claimed — `mode_rearchitecture.md` wants `U`) is left for a deliberate follow-up.


Batch 5 (direct verified fixes on the live HEAD, one-at-a-time full-suite green — the parallel-worktree wave was abandoned as unreliable, see Batch 4 note). Landed: usermode `+r`-on-login (`24ab5dd`); PROP GET/SET/CLEAR case-insensitive verbs (`7e73c4b`); S2S `deliverRelay` source-prefix spoof guard (`bc17861`) + `+a` authonly relay slice (`c7b3755`); `+g`/ACCEPT callerid DM gate with 716/717/718, plus 718 carrying the sender's `user@host` as a distinct token, ophion/charybdis layout (`7572afd`, `4b2b47e`); IRCX ACCESS DENY now enforced at JOIN via `matchHostmask` (`474`, deny-wins; `matchHostmask` previously had no live caller) (`4b2b47e`), and its positive counterpart ACCESS GRANT auto-applies member status on JOIN (FOUNDER/OWNER/HOST/GRANT/VOICE → `~`/`.`/`@`/`+`, IRCX auto-op/-voice, mirroring the tiered-KEYS grant block) (`a6091f1`); EVENT Spine SERVER_LINK mirror — peer link/unlink now `publishOperEvent(.server_link, …)` at all four S2S lifecycle sites, live-path tested on the oper-CONNECT path (`008eafb`); IRCv3 cap-gate on oper `NOTE EVENT` lines — `publishOperEvent` now renders both a tagged and a plain form and delivers the `@event-*` variant only to `message-tags` subscribers (was: every oper got tag-prefixed lines regardless of cap) (`aea4f41`).

Re-assessed from the worktree wave and found ALREADY LIVE on this HEAD (independently landed; the worktree commits were redundant): WHOIS secret/private-channel hiding (`channelHiddenFromWhois`, with its own test); IRCX opt-in `421` gate across the command surface (`needs_ircx`); MODEX PRIVATE/HIDDEN routing (synth `MODE +p/+h` → `setPrivate`/`setHidden`). Still deferred (NOT mechanical): MODEX OPMODERATE `U` / FREETARGET `F` / DISFORWARD `D` query rows (need the MODE engine to actually enforce those letters first, per `mode_rearchitecture.md` — advertising-without-enforcement risk); NICK-change propagation over the S2S mesh (wire change, mesh-flap risk); ISUPPORT `isupport.Builder` chunker (superseded by `protocol_inventory.currentIsupport()`); IRCX ACCESS GRANT-overrides-DENY precedence (intentionally NOT done — deny-wins is kept as the security default; GRANT auto-status on JOIN itself is now live, `a6091f1`); cross-reactor `publishOperEvent` fanout — NOW LANDED (`f2aea06`). `publishOperEvent` only iterated the publishing reactor's client table, so under `num_shards>1` opers on other reactors never received oper notices (SERVER_LINK/POLICY/KILL/ANNOUNCE). Fixed with a `DeliverMsg.broadcast_category` fabric message + a `drainFabric` broadcast handler (each reactor delivers the plain form to its own category-subscribers on its own thread) + a `publishOperEvent` fan-out to other shards (waking via `reactors[shard].wake`). Off-reactor message-tags opers get the plain form (always valid); single-shard is a no-op (fabric null). Cross-shard RECEIVE verified by instrumentation (a broadcast from shard 0 was received+processed on shard 1's reactor); a `num_shards=2` threaded test guards the path. CORRECTION: an earlier note here claimed a "multi-shard send-flush bug" (oper can't receive its own EVENT BROADCAST) — that was WRONG, a wrong test needle: EVENT BROADCAST announces are `NOTE EVENT ANNOUNCE :<sender-mask>: <message>`, so a `:<message>` needle never matched. Server delivery was correct under sharding all along. (NB: this sandbox's SO_REUSEPORT routes all loopback accepts to one shard, so cross-shard receipt can't be deterministically exercised by a socket test here — only mechanism-verified.)

Batch 4 added (from the worktree wave): account-registration `custom-account-name` cap advertise + pre-registration `FAIL REGISTER COMPLETE_CONNECTION_REQUIRED` (acctreg); `+Z` (quiet) channel-list propagation over S2S as an additive `ListKind` variant (zquiet). NOTE on that wave: most parallel worktree workers landed on a stale/divergent base and could not be merged (their fixes — `deliverRelay` spoof-guard+`+a`, MODEX 1–3, usermode `+r`, EVENT SERVER_LINK+cap-gate, PROP case-insensitive verbs, `+g`/ACCEPT — remain correct specs to re-run against this HEAD via the proven `git worktree add … main` + codex loop). Only acctreg + zquiet were on the current base and are verified green here.



Batch 3 added: SessionStore leak fixed via caller-provided buffer (sessredo — kills the leak AND the multi-shard race the first attempt introduced); REDACT unknown-msgid spoof fix + EDIT `message_editing` cap + `+draft/typing`/`+draft/unreact` live paths (draftredo, with the ~11 broken FAIL-tests repaired); MeshPass inbound length cap on the responder (meshcap — the one SAFE mesh hardening). AKICK join-gate enforcement remains quarantined (svc_akick match fix incomplete — TODO).

Captured-but-not-yet-coded backlog (auditor specs, ready for future codex tracks): usermode `+r`-on-login (SAFE), `+g`/ACCEPT 716/717/718; MODEX PRIVATE/HIDDEN field-divergence + OPMODERATE setter + query F/D/O (one `ircx_modex.mode_table` patch); EVENT SERVER_LINK mirror + cap-gate event tags; S2S `deliverRelay` source-prefix spoof guard (SAFE logic-only) + `+a` relay slice + `+Z`-quiet propagation; PROP case-insensitive verb matching; 4 paste-ready threaded tests authored. Deferred (risky/wire): secinterop news-TLS, mesh param-mode (+k/+l/+j/+f) replication, MARKREAD sibling fan-out, OID-on-CREATE, IRCX ACCESS-enforce-on-JOIN.



Batch 2 added: SASLINFO EXTERNAL + CHANNEL ACCESS/AKICK *commands* (services2); ISUPPORT boot fail-fast (isupportfix); DM-history keyed by account (chathist2); secret-PROP HOSTKEY/OWNERKEY join-grant + PROP GET/SET/CLEAR verbs (propkey); WHOX real IP/oper-level (gated) + classic-WHO away/oper flags + malformed-LIST (wholist); IRCv3 `bot` message tag + tighter channel `+C` CTCP detection (botfix).

Quarantined tests (skip + TODO, code shipped): MONITOR >64-watcher fanout (66-conn harness limit); CHANNEL AKICK join-gate enforcement (the command/storage works; the mirror into the in-memory `chan_akick` join gate has a mask/case matching bug — `svc_akick` dual-store).



Fixed and merged to `main` (each reviewed by a `zig-code-reviewer` pass that caught bugs the isolated tests missed):

- **Same-account same-nick / remote-DM sibling fanout** — already fixed by `c09594d`; verified live.
- **S2S relay policy (P2)** — SQUIT now finds+closes secured peers on reactor 0 (`enqueueCloseOnOwner`); relayed DMs honor recipient `+R`/SILENCE + session-sync sibling fanout; remote aggregate channel-mode update can no longer clear local `+n/+t/+O/+A` (policy mask). STATUSMSG-over-S2S and per-event origin signatures remain deferred (wire change, HIGH mesh-flap risk).
- **CAP/SASL (P3)** — live `CAP LIST`, value-aware `CAP REQ` (`sasl=EXTERNAL`), SASL `905`/`907`/`908` fidelity, backend-gated `sasl` advertise.
- **IRCv3** — WHO/WHOX double-CRLF, `+i` invisibility (WHO/WHOX/ISON/LUSERS), WHOIS secret-channel filter, WHOWAS count, WHOX requested-field order; TAGMSG server-tag stripping + inbound tag validation; CTCP auto-reply + user `+C`; CHATHISTORY membership gate / LATEST selector / BETWEEN direction / draft batch-type / MARKREAD cap.
- **IRCX (P4)** — opt-in enforcement (`421` ISIRCX gate); DATA via `channelSpeechGate` + STATUSMSG targets; EVENT rejects unknown categories + `event_subscribe` priv gate.
- **Services / oper (P6)** — **GHOST ownership check (CRITICAL: was a network-wide disconnect primitive)**; ACCOUNTSET lifecycle-flag lockdown; REGISTER `*`; VERIFY `<account> <code>`; **oper bindings fail-closed (HIGH: empty/typo class no longer → `OperPrivileges.full`)**; USERIP oper-gate + real IP; per-oper REHASH privs; named-priv gates (DRAIN/CLOSE/GLOBAL/DEBUG); SASLINFO EXTERNAL; CHANNEL ACCESS/AKICK wired.
- **Channel modes** — `$m` mute (join allowed, speak blocked), `$z` secure ban context.
- **MONITOR/metadata/config** — MONITOR fanout best-effort (can't abort registration); metadata-2 cap; SETNAME echo cap-gate; `[media].enabled` enforced + `disabled_features`.
- **Docs** — CONFORMANCE/caps/CHANMODES/numerics/_index/planning drift corrected.

Deferred (with specs) for careful follow-up, NOT on `main`:
- `sessfix` (SessionStore leak) — the reusable-scratch fix introduced a multi-shard race; needs the caller-buffer variant.
- `draftfix` (REDACT spoof fix + EDIT/standard-replies cap gates) — cap-gating broke ~11 existing FAIL-asserting tests; re-land with the tests updated.
- `secinterop` news-TLS flip — keep the v6-DNS half; the flip silently breaks news without trust-anchor plumbing.
- HIGH-risk mesh items (MeshPass responder check beyond the safe inbound length cap, plaintext-S2S `require_secured`, origin signatures) — wire/handshake changes, mesh-flap risk.
- `services2`, `botfix`, `propkey`, `wholist`, `chathist2`, `isupportfix` — completed in worktrees, pending review+merge in the next verified batch.

Process note: codex workers' threaded socket tests SKIP under the `workspace-write` sandbox (loopback blocked), so worker "tests pass" meant "skipped" — the parent must run the full suite to catch real failures. The fleet also hit a machine ceiling (~33 concurrent `zig build`) that corrupts the threaded-test signal via port/fd exhaustion; verify in a quiet environment.

## Executive Summary

Orochi has a large amount of IRC, IRCv3, IRCX, services, and mesh code, but several surfaces are ahead of their live wiring. The most important pattern is not "missing parser"; it is parser/model/helper code existing without live daemon enforcement, or CAP/ISUPPORT/docs advertising behavior that is only partial.

Highest-risk findings:

1. Same-account same-nick multi-client is disabled in live registration. The intended allowance is behind `if (false)`, so the second SASL-authenticated client still gets `433` (`src/daemon/server.zig:4557`). This directly matches the observed multi-client failure.
2. Mesh/S2S admission and origin verification are incomplete. MeshPass is encoded but not checked on the responder side (`src/crypto/tsumugi_handshake.zig:254`, `:634`), and normal message/membership relay frames are not origin-verifiable (`src/substrate/suimyaku/message_relay.zig:17`, `src/proto/membership_event.zig:1`).
3. Remote/direct relay policy is inconsistent. Remote DMs bypass local `+R`/SILENCE/session-sync fanout (`src/daemon/server.zig:3979`), remote topic/mode updates bypass local authority checks (`src/daemon/server.zig:5259`, `:5273`, `:5162`, `:5170`), STATUSMSG is flattened over S2S (`src/daemon/server.zig:14839`, `:3973`), and some channel-policy replication omits quiet lists/parameter modes.
4. IRCX command opt-in is not enforced. `ConnState.ircx` exists, but registry dispatch receives no IRCX bit (`src/daemon/server.zig:4441`, `src/daemon/registry.zig:56`), so registered legacy clients can use IRCX commands without sending `IRCX`.
5. CAP/ISUPPORT false advertising exists. Examples: `CAP LIST` missing from live dispatch; `CAP REQ sasl=EXTERNAL` NAKs; SASL is advertised regardless of backend; `ELIST` works but is not advertised; `UTF8ONLY` is only partially enforced; `CHANMODES` omits accepted modes.
6. Services and oper security have real privilege/persistence gaps. `ACCOUNTSET flags` lets a password holder set lifecycle flags; `REHASH` reloads all opers with full privileges; several services stores are volatile while docs present service-like persistence.
7. IRCX `ACCESS`, `PROP`, `EVENT`, `DATA`, `REQUEST`, `REPLY`, and MODEX are live but incomplete. The most serious are ACCESS entries not being enforced, DATA bypassing normal channel speech gates, and EVENT categories/privileges not being wired.
8. Many pure modules are not live commands: `WATCH`, IRCX `AUTH`, `SACCESS`, `XLINE`, `SNOMASK`, `GETKEY`, `RECOVER/RELEASE`, `GLOBOPS`, `JUPE`, and more.

## Immediate Runtime Bugs

- Same-account same-nick registration is disabled: intended allowance is under `if (false)`, so same-account clients still receive `433 Nickname is already in use` (`src/daemon/server.zig:4557`). Nearby tests expect same-account same-nick behavior (`src/daemon/server.zig:17845`).
- `SESSION RESUME` does not restore session state. Detached sessions store only `client`, `token`, `signon_ms`, and `attached` (`src/daemon/sessions.zig:24`); disconnect removes nick/channel world state (`src/daemon/server.zig:4093`); resume only removes the ghost and sends a note (`src/daemon/server.zig:12524`).
- `SessionStore.sessions()` leaks snapshots by appending every duplicate slice into `session_snapshots` (`src/daemon/sessions.zig:160`), and session-sync calls it during DM fanout (`src/daemon/server.zig:3775`).
- Remote DMs bypass same-account sibling fanout. Local DMs fan out to sibling sessions (`src/daemon/server.zig:14915`), but relay DMs deliver only to `world.findNick(target)` (`src/daemon/server.zig:3979`).
- Bouncer replay is join-time and marker-dependent only (`src/daemon/server.zig:5957`, `:7731`); `SESSION RESUME` explicitly says buffered replay is later (`src/daemon/server.zig:12494`).

## Confirmed Local `+nt` Behavior

- Fresh local channels default to `+nt` (`src/daemon/world.zig:253`).
- Local `+n` is enforced by the local channel speech path (`src/daemon/server.zig:14083`).
- Local `+t` is enforced by the local TOPIC handler (`src/daemon/server.zig:14753`).
- The observed "`+nt` not working" class is therefore not an absence of local default/enforcement. The stronger evidence points at remote/S2S and nonstandard command paths bypassing or overwriting equivalent policy.

## Core IRC Gaps

### User Modes And Visibility

- `+i` invisible is stored but not honored by `ISON`, `WHO <nick>`, `WHOIS`, or `LUSERS` (`src/daemon/server.zig:6672`, `:6829`, `:6921`, `:11067`).
- `+g`/ACCEPT is incomplete. `+g` exists and ACCEPT mutates state, but direct-message delivery checks only `+R` and SILENCE (`src/proto/usermode.zig:149`, `src/daemon/server.zig:8351`, `:14894`, `:14904`).
- Server-managed `+r`, `+z`, and `+x` are cataloged but not set in live login/TLS/cloaking paths (`src/proto/usermode.zig:146`, `src/daemon/dispatch.zig:876`, `src/daemon/server.zig:7015`).
- Classic WHO omits oper/away fields while WHOX handles some of them (`src/daemon/server.zig:6811`, `src/proto/who.zig:303`).
- USERHOST exposes oper status without honoring `+H` hide-oper (`src/daemon/server.zig:6696`).

### WHO / WHOX / WHOIS / WHOWAS

- WHO/WHOX output appends extra blank IRC lines because builders already include CRLF and `server.zig` appends another CRLF (`src/proto/who.zig:157`, `:219`; `src/daemon/server.zig:6825`, `:6850`, `:6725`).
- WHOIS channel list leaks secret/private membership because it only honors target user `+p hide_chans`, not channel visibility/common membership (`src/daemon/server.zig:6936`, `:7025`).
- WHO/WHOX ignores visibility gates used by NAMES/auditorium (`src/daemon/server.zig:6805`, `:6829`, `:15092`).
- Advertised WHOX is partial: field order is canonical, not requested order; IP and oper-level fields are hardcoded placeholders (`src/proto/whox.zig:53`, `:150`, `:206`).
- WHOWAS comment says `[count]`, but handler ignores param 2 and queries a fixed 16 slots (`src/daemon/server.zig:7314`).
- WHOWAS docs claim `RPL_WHOWASREAL 360`; live builder emits `314`, optional `312`, `369`, and `406` (`docs/reference/commands/queries.md:60`, `src/proto/whowas_reply.zig:128`).

### Channel Modes And Lists

- `+n`/`+t` and many local policies exist, but S2S and IRCX paths bypass some enforcement.
- STATUSMSG is bypassed across S2S. Local delivery honors status prefixes, but relay strips the status target and remote nodes deliver to every local member (`src/daemon/server.zig:14770`, `:14824`, `:14839`, `:3973`).
- `+Z` quiet list is local-only over S2S. It is advertised/enforced locally, but list propagation supports only `b/e/I` (`src/proto/protocol_inventory.zig:56`, `src/proto/channel_list_event.zig:21`, `src/daemon/server.zig:4751`).
- Advertised `$m` extban semantics are wrong: parser labels it mute/quiet, but `+b $m:mask` goes through ban checks and blocks JOIN (`src/proto/extban.zig:61`, `:164`; `src/daemon/world.zig:973`, `:1106`).
- `+p` is accepted/rendered but under-advertised and has incomplete LIST/LISTX behavior (`src/daemon/server.zig:6339`, `src/daemon/world.zig:871`, `src/proto/protocol_inventory.zig:56`).
- Remote membership projection can satisfy `+n` membership without local join gates like `+i/+k/+l/+S/+O/+A/+b` being applied (`src/daemon/server.zig:5062`, `:5093`, `:5127`, `:5687`).
- Remote aggregate channel modes can overwrite local policy flags. Local MODE enforces chanop/oper and MLOCK, but remote `CHANNEL_MODE_FLAGS` is applied wholesale through `setChannelModeFlagBits()`, including policy flags like `+n`, `+t`, `+O`, and `+A` (`src/daemon/server.zig:5162`, `:5170`, `:5993`, `:6004`, `:6111`).
- Remote topic changes bypass local `+t`. Local TOPIC checks membership and blocks non-ops when `+t` is set, but remote topic changes pass freshness checks then mutate local world state via `applyRemoteTopic()` (`src/daemon/server.zig:5259`, `:5273`, `:14749`, `:14753`).
- Remote relay trusts asserted `source_prefix` more than local projection does. Projection drops remote members colliding with local nicks, but relay rendering still trusts the inbound prefix (`src/daemon/world_projection.zig:14`, `src/daemon/server.zig:3918`).
- `LIST` parses `C`/`T` time filters, but live channel views pass `created_ago = 0`, `topic_age = 0`, and omit created/topic timestamps (`src/daemon/server.zig:6858`, `src/proto/elist.zig:149`, `src/proto/list.zig:82`).
- Malformed `LIST` filters silently become an unfiltered visible-channel list (`src/proto/list.zig:131`, `src/proto/elist.zig:94`, `src/daemon/server.zig:6858`).
- `LISTX` is live but incomplete: no query limit/truncation `816`, missing created/topic/subject/language/registered metadata, and filters can be misleading (`src/daemon/server.zig:6883`, `:6894`, `src/proto/listx.zig:171`, `:239`).

### CTCP / DCC / Client Protocol

- CTCP parser/builders exist for ACTION/VERSION/PING/TIME/CLIENTINFO/SOURCE/DCC, but live `PRIVMSG`/`NOTICE` routing never calls the CTCP parser or emits auto-replies (`src/proto/ctcp.zig:42`, `:254`; `src/daemon/server.zig:14534`, `:14743`).
- DCC is parsed only as CTCP; there is no live DCC policy or blocking (`src/proto/ctcp.zig:56`, `:317`; `src/daemon/server.zig:14894`).
- User `+C` no-ctcp is settable but not enforced on direct messages (`src/proto/usermode.zig:150`, `src/daemon/server.zig:6565`, `:14343`).
- Channel `+C` CTCP detection is partial: it only blocks bodies that start/end with SOH and exempts any body beginning with `ACTION` (`src/daemon/server.zig:15743`).
- IRCv3 bot mode is partial: `+B` and WHOIS 335 exist, but the `bot` message tag is not emitted (`src/daemon/server.zig:275`, `:16958`).
- NOTICE auto-reply behavior is stricter than docs: live code drops some NOTICE errors, while docs still list numeric errors (`src/daemon/server.zig:14543`, `:14765`; `docs/reference/commands/messaging.md:16`).

## IRCv3 Gaps

### CAP Negotiation

- Live CAP dispatch lacks `CAP LIST`; only `LS`, `REQ`, and `END` are handled (`src/daemon/dispatch.zig:465`, `:481`, `:485`).
- Live `CAP REQ` matches tokens literally, so value-bearing requests like `sasl=EXTERNAL` NAK even though helper code supports value-aware matching (`src/daemon/dispatch.zig:545`, `:561`, `:575`; `src/proto/cap_values.zig:102`, `:128`, `:139`).
- SASL is advertised unconditionally as `sasl=PLAIN,EXTERNAL,SCRAM-SHA-256`, even when no account DB/checkers are configured (`src/daemon/dispatch.zig:292`, `src/main.zig:241`, `src/daemon/server.zig:4010`, `:12136`).
- STS value is emitted even for bare `CAP LS`, while helper/docs imply CAP 302-value behavior (`src/proto/cap.zig:465`, `src/daemon/dispatch.zig:515`, `:519`, `:534`).
- `cap-notify` is advertised, but dynamic `CAP NEW`/`DEL` is static-only/not wired (`src/daemon/dispatch.zig:355`, `src/proto/cap_notify.zig:121`, `:132`).
- There are two CAP registries. Live uses `src/daemon/dispatch.zig`; `src/proto/cap.zig` advertises different names/values and stale docs cite it as source of truth (`src/proto/cap.zig:372`, `:395`; `docs/reference/protocol/caps.md:3`).

### SASL And Account Registration

- `[sasl].enabled` is parsed but ignored; main gates only on `sasl.account_db` (`src/daemon/config_format.zig:530`, `src/main.zig:241`).
- SASL failures collapse `.too_long` to 904 instead of preserving 905 (`src/proto/sasl_mechrouter.zig:166`, `src/daemon/dispatch.zig:1404`).
- Unsupported mechanisms do not emit 908 with a mechanism list (`src/daemon/dispatch.zig:1374`, `src/proto/sasl_mechrouter.zig:11`, `src/proto/numeric.zig:232`).
- Registered-client SASL reauth returns 462 instead of SASL-specific 907 or a SASL 3.2 reauth path (`src/daemon/dispatch.zig:1342`).
- `REGISTER *` is not implemented as "use current nick"; it passes raw `*` into account validation (`src/daemon/server.zig:11902`, `src/daemon/services.zig:972`).
- `draft/account-registration` is advertised without `custom-account-name`, even though custom account names are allowed (`src/daemon/dispatch.zig:350`, `src/daemon/server.zig:11902`).
- Pre-registration `REGISTER` is blocked by generic registered-only access and returns 451, not draft `FAIL REGISTER COMPLETE_CONNECTION_REQUIRED` (`src/daemon/registry.zig:238`, `src/daemon/modules/accounts.zig:72`, `src/daemon/server.zig:4452`).
- `VERIFY` is `VERIFY <code>` and derives account from login, not draft `VERIFY <account> <code>` (`src/daemon/server.zig:8063`, `:8075`).
- `REGISTER <email>` does not persist email, and verification tokens are memory-only (`src/daemon/server.zig:11918`, `src/daemon/services.zig:431`, `src/daemon/account_verify.zig:64`).

### Message Tags, Labeled Response, Batch

- `labeled-response` is advertised, but labels are dropped before live registered dispatch (`src/daemon/dispatch.zig:358`, `:1124`; `src/daemon/server.zig:1457`, `:1468`, `:1476`, `:4409`).
- Live message tag parsing slices `tags_raw` but does not validate keys/values/count/duplicates/client-only prefix rules (`src/daemon/server.zig:382`, `:396`, `:426`).
- `TAGMSG` relays raw non-client tags and can spoof server tags to `message-tags` recipients (`src/daemon/server.zig:399`, `:14363`, `:14379`, `:14395`).
- Tagged PRIVMSG/NOTICE sender negotiation is not enforced; recipient `message-tags` controls relay (`src/daemon/server.zig:14589`, `:307`, `:308`).
- `batch` is advertised, but client `BATCH` is only special-cased for `draft/multiline`; no general client-batch command exists (`src/daemon/dispatch.zig:336`, `src/daemon/server.zig:4421`, `:4425`, `:14698`).
- `standard-replies` is advertised, but `FAIL`/`NOTE` output is unconditional (`src/daemon/dispatch.zig:353`, `src/daemon/server.zig:13592`).
- `draft/channel-context` is advertised, but tags are relayed as generic `+` tags; validator is unused (`src/daemon/dispatch.zig:368`, `src/daemon/server.zig:304`, `:14363`, `src/proto/draft_channel_context.zig:75`).
- `EXTBAN=$,acgmrz` advertises `$z`, but live ban contexts do not set `secure`; the parser supports `$z` and `ClientContext.secure`, while `banContextFor()` leaves it false on live join/send checks (`src/proto/protocol_inventory.zig:83`, `src/proto/extban.zig:47`, `:146`, `src/daemon/server.zig:15514`, `:5560`).

### CHATHISTORY, MARKREAD, Bouncer

- CHATHISTORY access control is too weak: only `draft/chathistory` cap is checked, not channel existence/membership/privacy/policy (`src/daemon/server.zig:7821`, `:7847`).
- DM history is keyed by nick pairs, not account/cert identity, risking history conflation after nick reuse (`src/daemon/server.zig:7657`, `:14929`).
- `CHATHISTORY LATEST <selector>` ignores the selector (`src/proto/chathistory_cmd.zig:44`, `:101`; `src/daemon/server.zig:7847`).
- `BETWEEN` normalizes order and loses requested direction (`src/daemon/server.zig:7881`).
- `TARGETS` batch type is `chathistory-targets`, but the spec expects `draft/chathistory-targets` (`src/daemon/server.zig:7811`, `:19925`).
- CHATHISTORY/bouncer replay emits batches without requiring/checking `.batch` (`src/daemon/server.zig:7822`, `:7939`, `:7736`, `:7752`).
- MARKREAD is not cap-gated (`src/daemon/server.zig:7584`), not sent on JOIN before end-of-NAMES (`src/daemon/server.zig:5944`), and does not propagate to all clients of the user (`src/daemon/server.zig:7604`).
- MARKREAD implementation supports timestamp-only markers, while docs mention timestamp or msgid (`src/proto/read_marker.zig:59`, `:93`; `docs/reference/commands/messaging.md:60`).

### Metadata, Notify, Presence

- `draft/metadata-2` is advertised but partial: no cap check in handler, visibility hardcoded to `"*"`, store visibility model unused (`src/daemon/dispatch.zig:351`, `src/daemon/server.zig:10860`, `src/proto/metadata_store.zig:40`).
- `extended-monitor` over-delivers event-specific data without requiring event-specific caps (`src/proto/extended_monitor.zig:62`, `src/daemon/server.zig:14263`, `:14257`).
- MONITOR online fanout can drop all online notifications above 64 watchers because errors return before flushing queued replies (`src/daemon/server.zig:7515`, `src/proto/monitor.zig:56`, `:380`).
- Extended-monitor fanout truncates to 128 watchers (`src/daemon/server.zig:14267`, `src/proto/monitor.zig:258`).
- `SETNAME` self echo is not cap-gated (`src/daemon/server.zig:11502`, `:11503`).

### Draft Edit/React/Typing

- `draft/typing`, `draft/react`, and `draft/reply` are advertised, but TAGMSG only gates on `message-tags`, and per-recipient draft cap checks are missing (`src/daemon/dispatch.zig:333`, `src/daemon/server.zig:14363`, `:14390`).
- `+draft/typing` is parsed by helpers but live activity only handles `+typing` (`src/proto/msgedit.zig:366`, `src/daemon/server.zig:14398`).
- `+draft/unreact` is parsed but has no live activity/tally path (`src/proto/activity.zig:65`).
- EDIT accepts commands without requiring sender cap, broadcasts raw tagged PRIVMSG without recipient edit/message-tag gating, and hardcodes revision `1` (`src/daemon/server.zig:10993`, `:3810`).
- REDACT accepts unknown/invalid msgids, ignores failed `history.redact`, and broadcasts anyway (`src/daemon/server.zig:10921`, `src/proto/msgedit.zig:206`).
- TAGMSG/EDIT/REDACT do not relay over S2S while normal PRIVMSG/NOTICE do (`src/substrate/suimyaku/message_relay.zig:11`, `src/daemon/server.zig:3935`, `:14830`).

## IRCX Gaps

### Discovery, Opt-In, AUTH

- Discovery exists (`IRCX`, `ISIRCX`, `MODE ISIRCX`, 800), but opt-in is not enforced for live IRCX commands (`src/daemon/server.zig:4290`, `:10667`, `src/daemon/modules/ircx.zig:47`).
- `ircx_gate.zig` is unused and incomplete; it omits live IRCX `DATA`, `REQUEST`, `REPLY`, and `LISTX` and tests `LISTX` as non-IRCX (`src/proto/ircx_gate.zig:35`, `:193`).
- IRCX `AUTH` is parser-only, not registered (`src/proto/ircx_auth.zig:91`, `src/daemon/modules/ircx.zig:47`, `src/daemon/dispatch.zig:1250`).
- `RPL_IRCX 800` advertises `PLAIN,SCRAM-SHA-256,SCRAM-SHA-512,EXTERNAL`, but legacy parser recognizes `ANON`, `PLAIN`, `GateKeeper`, `GateKeeperPassport` (`src/daemon/server.zig:10677`, `src/proto/ircx_auth.zig:24`).
- AUTH syntax docs/parser disagree on abort and sequence (`docs/reference/ircx/ircx-protocol-ophion.md:37`, `src/proto/ircx_auth.zig:99`, `:56`, `:252`).

### DATA / REQUEST / REPLY / WHISPER

- `REQUEST` and `REPLY` are aliases for `DATA`; no request state/preauthorization exists (`src/daemon/modules/ircx.zig:50`, `src/daemon/server.zig:10730`).
- `OWN` and `HST` reserved tags are both allowed for any channel operator; owner and host/op tiers are not separated (`src/daemon/server.zig:10717`, `src/daemon/chanmode.zig:358`).
- `+Y`/NOCOMICDATA exists but does not affect DATA (`src/proto/chanmode_ext.zig:65`, `src/daemon/server.zig:10704`, `src/proto/numeric.zig:222`).
- DATA bypasses normal channel speech policy (`+m`, `+M`, bans, quiets, no-CTCP, status authority) because it does not call `channelSpeechGate` (`src/daemon/server.zig:10731`, `:14283`).
- DATA does not recognize STATUSMSG targets like `@#chan` (`src/daemon/server.zig:14771`, `:10709`).
- IRCX typed messages are local-only over S2S (`src/substrate/suimyaku/message_relay.zig:11`, `src/daemon/server.zig:10736`, `:10788`).

### ACCESS / PROP

- `SACCESS` / `ACCESS *` is parser-only and not registered (`src/proto/ircx_saccess.zig:1`, `:137`, `src/daemon/modules/ircx.zig:54`).
- IRCX `ACCESS` entries are stored/listed but not enforced; `matchHostmask` has no live daemon caller (`src/proto/ircx_access_store.zig:287`, `src/daemon/server.zig:10380`).
- ACCESS syntax/levels differ from docs and draft: channel-only parser, no `$`/`*` objects, aliases differ (`src/proto/ircx_access_store.zig:76`, `:417`, `:500`).
- PROP does not implement documented `GET`/`SET`/`CLEAR` verb forms (`docs/reference/ircx/ircx-protocol-ophion.md:90`, `src/proto/ircx_prop_store.zig:489`).
- Secret PROP filtering makes HOSTKEY/OWNERKEY join grants unable to read secrets (`src/proto/ircx_prop_store.zig:381`, `:420`, `src/daemon/server.zig:5921`, `:10584`).
- Built-in/computed PROP support covers only NAME/OID/CREATION/MEMBERCOUNT/MEMBERLIMIT; provider registry is unused (`src/proto/ircx_prop_store.zig:102`, `src/daemon/server.zig:10479`, `src/proto/ircx_prop_providers.zig:143`).
- PROP/ACCESS are in-memory only and not bridged to durable services storage (`src/daemon/server.zig:1669`, `:1992`, `:2129`, `src/daemon/services.zig:57`, `:623`).
- S2S sync covers channel PROP only, not ACCESS or user/member props (`src/proto/s2s_frame.zig:42`, `src/proto/channel_prop_event.zig:22`, `src/daemon/server.zig:10641`).

### EVENT

- Live EVENT parser ignores unknown categories instead of using the stricter standalone parser (`src/daemon/server.zig:8904`, `:9300`, `src/proto/ircx_event_cmd.zig:79`, `:91`).
- Documented `event_subscribe` privilege is not enforced; handler only checks oper boolean (`src/daemon/modules/ircx.zig:45`, `src/daemon/server.zig:9259`, `src/daemon/oper.zig:36`).
- Most Event Spine categories are inert; callsites only emit KILL, OPER_ACTION, and ANNOUNCE (`src/daemon/event_spine.zig:9`, `src/daemon/server.zig:7305`, `:9281`, `:13531`, `:13604`).
- S2S link events go to `MESH LOG`, not `EVENT SERVER_LINK` (`src/daemon/server.zig:3331`, `:3400`, `:4036`, `:13899`, `:14017`).
- EVENT replies are native raw lines, not draft 806-810 numerics, while docs conflict (`src/daemon/server.zig:9293`, `:9308`, `docs/reference/ircx/ircx-draft-pfenning-04.md:48`).
- Event tags are not cap-gated on `message-tags` (`src/daemon/event_spine.zig:292`, `src/daemon/server.zig:13611`).
- `event-playback` and `event_subscription.zig` are not live EVENT behavior (`src/proto/cap.zig:395`, `src/daemon/event_subscription.zig:1`, `src/daemon/root.zig:87`).

### MODEX / Channel Extensions

- MODEX `PRIVATE`/`HIDDEN` set extended flags but behavior reads separate `Channel.private`/`Channel.hidden` fields set by raw `MODE +p/+h` (`src/proto/ircx_modex.zig:102`, `src/daemon/server.zig:15597`, `src/daemon/world.zig:201`, `src/daemon/server.zig:6340`).
- `OPMODERATE +O` behavior exists but is effectively unreachable: raw `+O` is core `oper_only`, and MODEX lacks OPMODERATE name (`src/proto/chanmode_ext.zig:66`, `src/daemon/server.zig:6307`, `:14301`, `src/proto/ircx_modex.zig:100`).
- MODEX query omits `F/D/O` names even though `+F/+D` affect forwarding (`src/proto/chanmode_ext.zig:66`, `src/daemon/server.zig:6486`, `:5832`, `src/proto/ircx_modex.zig:100`).
- OID exists via PROP, but CREATE does not return it (`src/daemon/world.zig:207`, `:1396`, `src/daemon/server.zig:10487`, `:10792`).
- CLONEABLE auto-clone is live, but CREATE takeover semantics differ from docs (`src/daemon/server.zig:5890`, `:10799`, `src/daemon/world.zig:796`).
- `%#/%&` channel prefixes are accepted by world validation but not MODEX target validation; nick `'`/`^` prefix handling is not IRCX-specific (`src/daemon/world.zig:1470`, `src/proto/ircx_modex.zig:382`, `src/daemon/server.zig:15631`).

## S2S / Mesh Gaps

- Legacy TS6/RFC server protocol is intentionally absent (`SERVER`, `SID`, `UID`, `SJOIN`, text netburst). This matches clean-room docs (`docs/BRIEF.md:50`, `:76`, `docs/dev/zig016-notes.md:68`).
- MeshPass/admission is not enforced on responder side (`docs/planning/09-s2s-protocol.md:67`, `src/daemon/server.zig:3297`, `src/crypto/tsumugi_handshake.zig:254`, `:634`).
- User message and channel membership relay are not origin-verifiable (`src/substrate/suimyaku/message_relay.zig:17`, `:87`, `src/proto/membership_event.zig:1`).
- Both secured and plaintext links drain/deliver ordinary frames (`src/daemon/server.zig:3337`, `:3391`); oper grants are the exception with secured-link/key verification (`src/daemon/server.zig:3357`, `:11607`).
- Plaintext S2S remains part of the live relay path. Startup can fall back to plaintext on node identity/key errors, and relay paths handle both secured and plaintext peers (`src/main.zig:183`, `src/daemon/server.zig:3337`, `:3414`, `:3847`).
- `SQUIT` cannot close secured links because it searches only `entry.value.s2s`, not `s2s_secured` (`src/daemon/server.zig:8970`, `:9042`, `:9055`).
- Remote direct-message routes fall back to flooding when no route is known (`src/substrate/suimyaku/route_table.zig:300`, `:518`, `src/substrate/suimyaku/s2s_peer.zig:952`, `src/daemon/server.zig:14858`).
- Remote channel policy replication is partial: quiet `+Z` and param modes like `+k/+l/+j/+f` are not fully in burst/list propagation (`src/daemon/server.zig:5110`, `src/proto/channel_list_event.zig:1`, `src/daemon/server.zig:4751`, `:6352`, `:6452`).

## Services And Oper Gaps

### Accounts / Services

- NickServ/ChanServ pseudo-client aliases exist only as proto helpers, not live dispatch. `PRIVMSG NickServ ...` falls through to nick lookup (`src/proto/services_alias.zig:50`, `src/daemon/server.zig:14858`, `src/daemon/modules/accounts.zig:82`).
- `GHOST` authenticates target nick as account name, so it only works when nick equals account (`src/daemon/server.zig:12246`, `src/daemon/services.zig:481`).
- `ACCOUNTSET flags` lets password holders set lifecycle/admin flags like suspended/forbidden/noexpire (`src/daemon/server.zig:12215`, `src/daemon/services.zig:503`, `:146`).
- `CHANNEL ACCESS`, `CHANNEL AKICK`, and `CHANNEL TRANSFER` parse/backend exist but are not wired in `handleChannel` (`src/proto/chanserv_cmd.zig:72`, `src/daemon/services.zig:623`, `:682`, `src/daemon/server.zig:12305`, `:12353`).
- Live `AKICK`, `RESV`, `AUTOJOIN`, `GROUP`, `MLOCK`, `VERIFY`, and `SEEN` are partly process-local/volatile (`src/daemon/server.zig:1629`, `:1635`, `:1658`, `:9472`, `:9589`, `:12359`).
- `SASLINFO` omits EXTERNAL even when EXTERNAL is wired (`src/main.zig:253`, `src/daemon/server.zig:12140`).
- Account/service commands are discoverable even when `account_services` backend is absent (`src/daemon/modules/accounts.zig:69`, `src/daemon/modules/introspect.zig:79`, `src/daemon/server.zig:11896`, `:11938`).

### Oper / Admin

- REHASH reloads every configured oper as `OperPrivileges.full`, dropping group/title limits (`src/daemon/config_boot.zig:185`, `:208`, `src/daemon/server.zig:13650`).
- Several high-impact oper commands gate only on boolean oper, not named privileges: DRAIN, CLOSE, GLOBAL, OPERMOTD SET, DEBUG (`src/daemon/registry.zig:256`, `src/daemon/server.zig:7237`, `:7247`, `:8202`, `:7946`, `:9087`).
- USERIP is not oper-gated and returns `default_host`, not real IPs (`src/daemon/modules/oper_security.zig:145`, `src/daemon/server.zig:8386`).
- XLINE/UNXLINE/STATS x exist in `svc_xline.zig` but are not live commands (`src/daemon/svc_xline.zig:1`, `:90`, `:271`, `src/daemon/modules/oper_security.zig:116`, `src/daemon/server.zig:7543`).
- KLINE/DLINE/GLINE/UNKLINE are classified/docs-complete but not live commands; WARD is the live path (`src/daemon/command_class.zig:125`, `src/daemon/modules/oper_security.zig:122`, `src/daemon/server.zig:11019`).
- RESTART is behaviorally shutdown; it shares `handleDie` and relies on supervision to restart (`src/daemon/server.zig:8409`).

## Config, Deployment, And Security Interop

- `[media].enabled = false` is parsed but not enforced; startup unconditionally starts media UDP planes, with port 0 meaning ephemeral bind (`etc/orochi.reference.toml:306`, `src/daemon/config_format.zig:516`, `src/daemon/config_boot.zig:53`, `src/daemon/server.zig:2042`, `:2054`).
- `COMMANDS` can hide disabled features, but config never populates `disabled_features`, so MEDIA remains discoverable by default (`src/daemon/registry.zig:264`, `src/daemon/modules/introspect.zig:79`, `src/daemon/server.zig:1111`).
- PROXY protocol parser exists but accept path uses `getpeername()` and no trusted PROXY pre-IRC consumption exists (`src/proto/proxy_protocol.zig:1`, `src/daemon/server.zig:3154`, `:1392`).
- ACME is CLI/out-of-band; no daemon renew or TLS cert hot-reload path was found (`src/main.zig:106`, `:293`, `:434`, `src/daemon/server.zig:13618`, `src/daemon/acme_cli.zig:1`).
- STARTTLS, WEBIRC, and ident/identd are intentional exclusions, not accidental omissions (`src/daemon/server.zig:1213`, `src/daemon/dispatch.zig:1238`, `docs/BRIEF.md:76`).
- ISUPPORT config rewrite is mostly correct, but build failure is ignored and can leave static values (`src/daemon/server.zig:965`, `src/main.zig:170`, `:176`, `src/daemon/dispatch.zig:1499`).
- Media runtime limits remain partially unmapped. Config docs state `media.max_upload_bytes` and `media.max_frame_bytes` are parsed but not mapped into current server config, while room capacity is still compile-time (`docs/reference/config.md:315`, `src/daemon/media_room.zig:14`, `:19`).
- Native media transport has minimal per-datagram authentication: UDP frames are accepted by `stream_id`, sender address is learned, and bytes are forwarded without per-datagram cryptographic sender authentication on that leg (`src/daemon/native_media_transport.zig:108`, `src/daemon/native_media_link.zig:191`, `:212`).
- Geo/news outbound TLS can run degraded: `http_fetch` verifies when trust anchors are configured, but Geo/news paths can run without anchors and `news_insecure_tls` defaults true (`src/daemon/http_fetch.zig:74`, `src/daemon/geo_services.zig:328`, `src/daemon/config_format.zig:108`, `etc/orochi.reference.toml:121`).
- ACME DNS resolution skips IPv6 nameservers (`src/daemon/acme_runner.zig:490`, `:493`).
- The general TLS client verifier wrapper still has an X.509 integration TODO, even though other TLS client/server paths perform their own chain or CertFP-specific checks (`src/crypto/tls.zig:519`, `:528`, `src/crypto/tls_client.zig:1242`, `src/crypto/tls_server.zig:467`).

## Pure Modules Not Wired To Live Commands

High-value parser/model/helper code not reachable through the live registry:

- `WATCH`: `svc_acctnotify.zig` and `watch_list.zig` model WATCH/numerics, but no live `WATCH` command exists (`src/daemon/svc_acctnotify.zig:1`, `:35`, `:382`; `src/daemon/watch_list.zig:1`, `:47`).
- IRCX `AUTH`: parser/builders exist, no live command (`src/proto/ircx_auth.zig:1`, `:91`, `:113`; `src/daemon/modules/ircx.zig:45`).
- `SACCESS` / `ACCESS *`: parser exists, no live registration (`src/proto/ircx_saccess.zig:1`, `:137`; `src/daemon/modules/ircx.zig:47`).
- `XLINE`/`UNXLINE`/`STATS x`: pure oper feature exists, not registered (`src/daemon/svc_xline.zig:1`, `:90`, `:271`).
- Additional exported-only helpers with no live server/module references include account access/flags/meta/silence, channel flags/roles/settings/transfer/entrymsg, GETKEY, GLOBOPS, JUPE, MLOCK, PASSWD, RECOVER/RELEASE, RWHO, SNOMASK, and XOP (`src/daemon/root.zig:221`, `src/daemon/svc_getkey.zig:1`, `src/daemon/svc_globops.zig:1`, `src/daemon/svc_jupe.zig:1`, `src/daemon/svc_recover.zig:1`, `src/daemon/svc_snomask.zig:1`).
- `SERVLIST`/`SQUERY` are missing live commands; only SERVLIST numerics exist (`src/proto/numeric.zig:45`, `src/daemon/modules/manifest.zig:23`).
- `SNOMASK`, `HOST`, and `CHGHOST` are command-classified or server-to-client helpers but not live client commands (`src/daemon/command_class.zig:125`, `:143`).
- `WALLOPS` is not a live command; current replacement appears to be `EVENT BROADCAST`, but older parity/reference docs still imply command parity (`src/daemon/command_class.zig:119`, `src/daemon/modules/oper_security.zig:122`, `src/daemon/server.zig:9073`, `docs/reference/commands/ircx.md:96`).
- `SUMMON` and password `OPER` are registered but intentionally disabled/stubbed. `SUMMON` returns disabled and `OPER` directs users to SASL/account-bound elevation (`src/daemon/modules/feature_misc.zig:36`, `src/daemon/modules/oper_security.zig:122`, `src/daemon/server.zig:11299`).

## Documentation Drift

- `docs/reference/ircx/CONFORMANCE.md` contradicts itself: progress notes say features are live while tables mark them missing (`docs/reference/ircx/CONFORMANCE.md:10`, `:21`, `:33`, `:36`, `:48`).
- Legacy Ophion IRCX docs in Orochi tree still describe C `modules/m_ircx_*.c` as implementation truth (`docs/reference/ircx/ircx-protocol-ophion.md:6`, `:14`, `docs/reference/ircx/m_ircx_auth.md:5`).
- IRCv3 planning docs mark completed caps as missing, including WHOX, cap-notify, labeled-response, STS, multiline (`docs/planning/21-protocol-gaps.md:21`, `:24`, `docs/planning/23-ircv3-upstream-research.md:27`, `:38`).
- CAP docs cite non-live `src/proto/cap.zig`, with stale SASL/STS/TLS claims (`docs/reference/protocol/caps.md:3`, `:15`, `:25`, `:28`).
- ISUPPORT/CHANMODES docs disagree with live `CHANMODES=beIZ,k,lfj,imnstCTNMSgWOA` (`docs/reference/protocol/isupport.md:25`, `docs/reference/protocol/modes.md:3`, `docs/architecture/02-world-dispatch-modules.md:107`, `src/proto/protocol_inventory.zig:56`).
- `22-irc-gap-sweep.md` marks mode work missing that source now implements (`docs/planning/22-irc-gap-sweep.md:106`, `:111`, `:148`).
- Numerics docs undercount live emitted numerics and conflict on 477/484/485 names (`docs/reference/protocol/numerics.md:148`, `src/proto/numeric.zig:200`, `:207`, `:208`).
- Command reference source line anchors are widely stale, including queries, operators, mesh, command index, and IRCX pages.
- `docs/reference/commands/_index.md` marks `GROUP` as a placeholder even though it is registered and handled (`docs/reference/commands/_index.md:52`, `src/daemon/modules/user_query.zig:60`, `src/daemon/server.zig:7818`).
- `docs/reference/commands/_index.md` omits registered `CERTLIST` and `CERTDEL` (`src/daemon/modules/accounts.zig:85`, `docs/reference/commands/_index.md:117`).
- Some config-reference "not wired" rows are stale. `listen.ws` now maps through `config_boot.zig`, while `listen.webtransport` still appears parser/proto-only (`docs/reference/config.md:312`, `src/daemon/config_boot.zig:45`).
- `limits.num_shards` single-reactor docs are stale; current main passes configured shard count and threaded reactor startup exists (`docs/reference/config.md:149`, `docs/planning/24-multithreading.md:13`, `src/main.zig:145`, `src/daemon/server.zig:2790`).
- Module-system planning is stale where it says the registry is not wired into the live server; current dispatch consults `module_manifest.Live` (`docs/planning/17-module-system.md:24`, `src/daemon/server.zig:4388`, `docs/architecture/00-overview.md:59`).

## Test Coverage Gaps

- IRCv3 cap/notification behavior lacks socket-level tests for `CAP LS/REQ/LIST/END`, ACK/NAK atomicity, cap-notify NEW/DEL, away-notify, account-notify, echo-message, CHGHOST/vhost notifications.
- SASL PLAIN/SCRAM are well covered in unit/dispatch tests but not through live threaded sockets; only mTLS/EXTERNAL surfaced in server tests.
- IRCX lacks integrated tests for opt-in denial, SACCESS/GAG effects, LISTX, DATA/REQUEST/REPLY, and several partial ACCESS/PROP behaviors.
- Services/account commands are mostly backend-tested, not end-to-end command-tested: REGISTER, VERIFY, IDENTIFY, DROP, GHOST, CHANNEL, AKICK, RESV, FORCE*, TEMPMODE, CLONES, SEEN, VHOST.
- S2S needs multi-node E2E tests for remote JOIN/PART/MODE/TOPIC/PROP/NICK surfacing, SQUIT secured links, link collisions, netsplit/netjoin batches, secure Tsumugi S2S, GRANT/REVOKE propagation, and remote-policy denial.
- Bouncer/session-sync needs threaded `SESSION RESUME`/mesh reclaim tests, replay denial/expiry, redirect vs local grant, backlog interaction, and same-account same-nick registration.
- Remote relay into local `+n`, `+m`, `$m`, `+Z`, `+M`, `+C`, and `+T` channels should use the same speech-gate semantics as local send.
- Remote topic changes should be tested against local `+t`/authority rules.
- Remote aggregate mode flags should be tested against local `+nt` and MLOCKed modes.
- Remote direct messages should be tested for recipient `+R`, SILENCE, away behavior, history, and `orochi/session-sync`.
- `$z` extban needs TLS and non-TLS live-context tests once `secure` is set in the ban context.
- Docs need an assertion manifest mapping every "implemented/live" claim to a server E2E test or explicit "parser/backend only" status.

## 30 Audit Scopes Run

1. RFC commands/numerics/SERVLIST/SQUERY/WALLOPS.
2. CAP registry and CAP negotiation.
3. Message tags/labeled-response/batch.
4. SASL and account-registration.
5. CHATHISTORY/read-marker/bouncer replay.
6. Draft edit/react/reply/typing/redaction.
7. Numerics and RFC reply shapes.
8. MONITOR and presence caps.
9. Channel modes/list modes/extbans.
10. User modes/visibility.
11. ISUPPORT accuracy.
12. WHO/WHOX/WHOIS/WHOWAS queries.
13. LIST/LISTX/ELIST.
14. IRCX discovery/session opt-in.
15. IRCX AUTH/package negotiation.
16. IRCX DATA/REQUEST/REPLY/WHISPER.
17. IRCX EVENT/Event Spine.
18. IRCX ACCESS/PROP.
19. IRCX MODEX/channel extensions.
20. Services/NickServ/ChanServ compatibility.
21. Oper/server management.
22. CTCP/DCC/client protocol.
23. S2S protocol and mesh.
24. TLS/STS/PROXY/WEBIRC/ident interop.
25. Bouncer/multiclient/session-sync.
26. Vendor/nonstandard caps and commands.
27. Documentation staleness.
28. Test coverage gaps.
29. Config gating and false advertising.
30. Pure modules/not-wired sweep.
