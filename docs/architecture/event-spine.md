# Orochi Event Spine

*The typed, mesh-propagated operator/observer event bus as implemented in the current source tree.*

Orochi replaces the untyped snote/wallops broadcast channels of classic IRC with a typed **Event Spine**: daemon subsystems publish structured events, operator (and, for one type, ordinary) sessions subscribe by category or by subject glob, the events are rendered as chatsvc-faithful `:<server> EVENT <target> <body>` lines, and every event is fanned network-wide over the signed S2S link so opers on every node see it. The pure event model owns no allocation and keeps no global state — the daemon supplies subscriber storage, publish sinks, and render buffers ([src/daemon/event_spine.zig](../../src/daemon/event_spine.zig)).

## Two subscription planes, one delivery path

The spine carries two deliberately-separate subscription planes plus a targeted feed:

- **Category plane** — the `EventCategory` taxonomy (KILL, FLOOD, SECURITY, …). Severity-aware, subject-glob filterable, and the plane that rides the `OPER_EVENT` wire. Operator-only.
- **IRCX EVENT plane** — the Ophion-compatible `CHANNEL`/`MEMBER`/`USER`/`MEDIA` types, token-routed by the leading TYPE token of the event body. Severity-agnostic, additively overlaid on the category plane. `MEDIA` is the one type an ordinary client may subscribe to (its own channels' call presence).
- **OBSERVE feed** — a per-oper standing glob over client lifecycle records (connect/quit/nick/join/part/host/oper), carrying the subject's *real* host. Rides its own `OBSERVE_EVENT` wire.

Both wire planes share the same daemon triad: a local cross-shard fan-out (`deliverX-local`), a mesh fan to every peer (`meshBroadcastX`), and an inbound decode-and-deliver (`drainX`). For oper events the triad is `deliverOperEventLocal` + `meshBroadcastOperEvent` + `drainOperEvents`; for OBSERVE it is `deliverObserveLocal` + `meshBroadcastObserveEvent` + `drainObserveEvents` ([src/daemon/server.zig](../../src/daemon/server.zig)).

| Layer | Source | Role |
| --- | --- | --- |
| Pure event model | `src/daemon/event_spine.zig` | `EventCategory`/`EventSeverity` enums, `CategoryMask`, `IrcxEventType`, subscriber slots, line rendering, and message-tag building. Allocation-free. |
| History ring + counters | `src/daemon/event_history.zig` | `EventHistory(N)` RwLock ring backing `EVENT REPLAY` (+ disk snapshot), and `EventStats` atomic per-category/severity counters backing `EVENT STATS`. |
| Flood-collapse | `src/daemon/event_collapse.zig` | `CollapseTable(N)` that suppresses identical low-severity storms and emits one summary per window. Never collapses `>= warn`. |
| Daemon integration | `src/daemon/server.zig` | The `EVENT` command surface, the publish/deliver/mesh/drain triad, subject/severity filtering, OBSERVE registry, and security-event emission. |
| OPER_EVENT codec | `src/proto/oper_event.zig` | Compact `{category:u6, severity:u8, origin_server, message}` frame (tag `0x14`). |
| OBSERVE_EVENT codec | `src/proto/observe_event.zig` | Compact `{action, origin_server, nick, user, host, account?, detail}` frame (tag `0x15`). |

## Categories and severities

`EventCategory` is an `enum(u6)` of thirteen variants: `connect`, `disconnect`, `server_link`, `flood`, `error`, `announce`, `oper_action`, `kill`, `spam`, `debug`, `policy`, `service`, `security` ([src/daemon/event_spine.zig](../../src/daemon/event_spine.zig)). Each has an uppercase wire `code()` (e.g. `OPER_ACTION`) and a lowercase `token()`. `EventCategory.parse` matches either form case-insensitively, but is deliberately **alias-free**: it never resolves the IRCX draft names `CHANNEL`/`MEMBER`/`USER`, so the token-routed IRCX plane can never fold back into the category mask (a regression the tests pin explicitly).

`EventSeverity` is ordered low→high — `debug`, `info`, `notice`, `warn`, `error`, `critical` — so `@intFromEnum(sev) >= min` is a valid threshold test. `parse` accepts the tag names plus the alias `warning → warn`.

`CategoryMask` is a `u64` bitset over the categories with `add`/`remove`/`include`/`exclude`/`contains`/`intersects`. `categoryMaskFromTokens` builds a mask from config tokens (case-insensitive names or the special `ALL`) and backs `[[opers]] presubscribe`. The parallel `IrcxEventMask` (a `u8`) tracks the four IRCX types; `IrcxEventType.fromMessage` classifies an event body by its leading TYPE token, which is the authoritative, wire-stable routing key for IRCX subscribers.

## Publish path

`publishOperEvent` is the thin wrapper (subject defaults to the message text); `publishOperEventSubject` is the core path ([src/daemon/server.zig](../../src/daemon/server.zig)). In order it:

1. **Flood-collapse gate.** `event_collapse.admit(category, severity, message, now)` — a suppressed low-severity repeat returns early and is dropped from delivery, mesh, history, *and* stats (the later summary captures it).
2. **History + stats.** Records into the node-wide `event_history` ring and bumps the `event_stats` counters, stamped with this server's name.
3. **Local delivery.** `deliverOperEventLocal(serverName, …)` renders and delivers to every locally-subscribed session on this shard, then hands the body+subject+origin to every *other* shard's inbox via the reactor fabric (`DeliverMsg.broadcast_category`/`broadcast_severity`/`broadcast_subject`/`broadcast_origin`); the receiving shard re-renders for its own subscribers in `drainFabric`, so it never re-fans (loop-safe).
4. **Mesh broadcast.** `meshBroadcastOperEvent` sends a signed `OPER_EVENT` to every *established* peer link (secured and plaintext), flushing each link's outbound buffer.

A subscriber matches when `sessionWantsEvent` is satisfied: the IRCX plane is tried first (token-routed, severity-agnostic, additive), else the category bit must be set **and** `severityWanted(severity)` passes **and** the per-category subject glob matches (default scope `*`). `MEDIA` events carry an extra gate — `mediaEventAllowed` requires a non-oper to be a member of the event's channel, preserving member-only media visibility.

The publishers are thin renderers over this core: `raidAlert`/`spamtrapCheck` (`.flood`), `publishServerLink` (`.server_link`), `publishUserConnectEvent`/`publishUserDisconnectEvent` (`.connect`/`.disconnect`), `publishMemberEvent`/`publishUserNickEvent`/`publishUserEvent` (`.oper_action`), `publishChannelEvent` (`.announce`), `publishMediaEvent` (`.service`), `publishModerationHeld`/`publishHistoryPolicyDeny` (`.policy`), and `publishSecurityBlock`/`publishSecurityAdmissionRefusal` (`.security`). Signed privileged moderation events include the same `proof=<id>` token stored by `AUDIT`, letting subscribers correlate live Event Spine traffic with `AUDIT PROOF <id>` evidence. Pre-registration anti-abuse gates also publish `SECURITY` events when they refuse a source for reputation, connection-rate throttle, or clone-limit policy, so those drops land in `EVENT REPLAY` instead of remaining accept-loop only.

## Live subscription

At SASL oper elevation a session's category mask is seeded **only** from its `[[opers]] presubscribe` bits (0 = nothing; a cross-mesh grant carries no presubscribe, so a remote oper starts empty and must opt in) ([src/daemon/server.zig](../../src/daemon/server.zig)). Runtime control is `EVENT ADD|DEL <category…|ALL>`, dispatched in `handleEvent`: a token that parses as an IRCX type (`CHANNEL`/`MEMBER`/`USER`/`MEDIA`) is handled on the IRCX plane; otherwise it falls through to `handleEventCategoryOp`, which toggles category bits via `CategoryMask.include`/`exclude` and echoes the new set with `replyEventCategories`. `EVENT LIST` shows both the IRCX subscriptions (draft numerics `RPL_EVENTSTART`/`RPL_EVENTLIST`/`RPL_EVENTEND`) and, for opers, the category set plus the severity floor. `EVENT CLEAR` with no argument drops IRCX subscriptions, the category mask, subject masks, and resets the severity floor to `debug`.

## Severity filtering

`EVENT SEVERITY <debug|info|notice|warn|error|critical>` sets a **per-session minimum** on the category plane (`handleEventSeverity`); with no argument it reports the current floor. The floor is threaded through all three delivery paths — the local render in `deliverOperEventLocal`, the cross-shard fan (`DeliverMsg.broadcast_severity`, re-checked in `drainFabric`), and the mesh drain — and enforced in `sessionWantsEvent` via `session.severityWanted`. It is intentionally category-plane only; the IRCX plane is severity-agnostic. Default floor is `debug` (shows everything), so a plain subscription is unchanged.

## History and EVENT REPLAY

`EventHistory(512)` is a bounded, RwLock-guarded ring of recent events, written from any reactor thread and from the mesh drain (`record` at both publish sites), so every push/collect takes the internal lock ([src/daemon/event_history.zig](../../src/daemon/event_history.zig)). Strings are copied into fixed in-slot buffers (origin ≤ 64, message ≤ 400 bytes) — no external ownership. `collect(filter_category, min_severity, out)` copies matching events newest-first under the lock into caller storage, so rendering happens lock-free.

`EVENT REPLAY [JSON] [category|ALL] [count]` (oper-only, `handleEventReplay`) collects up to `count` (clamped 1-200, default 30) events at or above the session's severity floor, then renders them oldest->newest as NOTICEs. The default form uses a relative-age prefix (`[5m ago] KILL/warn <origin> ...`) so entries read as history, not live traffic. `EVENT REPLAY JSON ...` uses the same filters but emits machine-readable NOTICE payloads: a `type=event-replay` header, one bounded `type=event` object per retained event, and a `type=event-replay-end` trailer.

The ring **is** persisted to disk: `serializeInto`/`load` use an `OEH1`-magic little-endian snapshot. `loadEventHistory` restores it at boot and `saveEventHistory` rewrites it on the stats cadence, gated to reactor 0 (the writer is `O_TRUNC`, not atomic, so a single writer avoids interleaved writes while the shared ring still captures every shard's events). This is wired to the `[oper] event_history_path` config; unset means in-memory only (per-process lifetime). REPLAY therefore survives a USR2 hot-upgrade and a cold restart.

## EVENT STATS and flood-collapse

`EventStats` holds lock-free atomic (`std.atomic.Value(u64)`) per-category,
per-severity, and total counters, incremented at the same two `record` sites as
the history ring ([src/daemon/event_history.zig](../../src/daemon/event_history.zig)).
`EVENT STATS` (oper-only, `handleEventStats`) reports the total since boot, the
live ring depth, and the nonzero per-category/per-severity breakdown.
`EVENT STATS JSON` returns the same counters as one NOTICE whose trailing
parameter is a stable JSON object: `total`, `history_depth`, `categories`, and
`severities`; all known category and severity keys are present, including zeros,
so operator UIs can poll it without scraping prose. Counters are
**process-lifetime and deliberately not persisted** (the useful "since this
boot" semantics), unlike the history ring which is.

`CollapseTable(64)` is RwLock-guarded and keyed on `(category, FNV-1a hash of message)` ([src/daemon/event_collapse.zig](../../src/daemon/event_collapse.zig)). `admit` delivers the first `default_threshold` (8) identical copies in a `default_window_ms` (10 s) window, then suppresses the rest; slots evict LRU when full. Two safety invariants: **severity `>= warn` is never collapsed** (a kill/ward/security/error storm always reaches opers in full), and **only exact repeats** (same category + identical message) collapse, so distinct events (different nick/channel) are unaffected. `flush` runs on the stats tick (reactor 0) and emits one summary per elapsed window that suppressed at least one event; that summary is published as `.flood`/`.warn` so it bypasses its own collapser (no self-collapse).

## Structured IRCv3 message-tags

`buildEventTags` produces `orochi.io/category=KILL;orochi.io/severity=warn` from the fixed `code()`/`token()` tables (already tag-safe, no escaping needed) ([src/daemon/event_spine.zig](../../src/daemon/event_spine.zig)). `renderEventTagged` prepends `@<tags> ` to the `:<origin> EVENT <target> <body>` line; empty tags degrade to the plain `renderEvent`. Tags are built once per event and delivered **only** to clients that negotiated the `message-tags` cap — everyone else gets the plain line, so there is no behavior change for non-negotiating clients. This is wired into both the same-shard render (`deliverOperEventLocal`) and the cross-shard fan-out (`drainFabric`). The renderer defensively rejects control bytes in the body, an unsafe target atom, and a too-small output buffer.

## OBSERVE targeted feed

`EVENT OBSERVE <mask> [actions…] | OFF | LIST` records a per-oper standing glob and action filter in the daemon's `observe` registry ([src/daemon/server.zig](../../src/daemon/server.zig)). `notifyObservers(action, subject)` fires the triad: `deliverObserveLocal` (this node's watchers, all shards) plus `meshBroadcastObserveEvent` (signed `OBSERVE_EVENT` to every peer). The subject is built by `observeSubject`, which uses the **real, uncloaked host** — observation is an operator-trust surface — so the frame rides the signed S2S path only. The fired `observe_mod.Action` variants are `connect`, `quit`, `nick`, `join`, `part`, `host_change`, `oper_up`. A peer's inbound records are decoded by `drainObserveEvents`; `decodeObserveEvent` validates the action ordinal variant-by-variant and preserves a null account distinctly from an empty one.

## Cross-mesh propagation and origin binding

`OPER_EVENT`/`OBSERVE_EVENT` are one-shot **notifications**, not convergent CRDT facts: peers do not store them; each delivers to its own subscribers. They are fanned **directly** origin→peer (single hop, never re-broadcast — re-broadcasting would loop the mesh), so the origin *is* the handshake-authenticated sender. The wire `origin_server` field is therefore treated as untrusted: `trustedOrigin(link, claimed)` returns `link.remoteName()` (the authenticated peer name), ignoring the spoofable wire value and logging a diagnostic on mismatch; a pre-handshake link with no name falls back to the claim ([src/daemon/server.zig](../../src/daemon/server.zig), commit `43c1f59`). It is wired into `drainOperEvents`, `drainObserveEvents`, and `drainKills`, and the trusted origin also writes the `remote_kill` MESH LOG audit row. The drains additionally validate the category ordinal against the defined variants (a hostile peer could send any in-range `u6`) and clamp an out-of-range severity to the top level rather than `@enumFromInt`-ing blindly.

## Wire frames

The Event Spine adds two S2S frame tags to the codec described in [mesh-s2s.md](mesh-s2s.md):

| Frame | Tag | Payload |
| --- | ---: | --- |
| `OPER_EVENT` | `0x14` | `{category:u6, severity:u8, origin_server, message}` — a network-wide category-plane notification ([src/proto/oper_event.zig](../../src/proto/oper_event.zig)). |
| `OBSERVE_EVENT` | `0x15` | `{action, origin_server, nick, user, host, account?, detail}` — a watched-subject lifecycle record; `host` is the real host, so it is carried on the signed path only ([src/proto/observe_event.zig](../../src/proto/observe_event.zig)). |

Both codecs are bounded per-field (so a hostile peer cannot pin large buffers), borrow their input on decode, and reject control bytes so a peer can never smuggle a CR/LF into the rendered `:<origin> EVENT …` line. As with any frame addition, an older peer's decoder rejects an unknown tag as malformed and re-dials, so all mesh nodes must run a tag-aware binary together.

## Operator commands

`EVENT` is the single command surface (`handleEvent`); opers are gated by the `event_subscribe` privilege, and ordinary clients may use only the IRCX subcommands and only for `MEDIA`.

| Subcommand | Behavior |
| --- | --- |
| `EVENT LIST [type]` | List IRCX subscriptions (draft numerics); opers also see the category set + severity floor. |
| `EVENT ADD <type\|category\|ALL> [mask]` | Subscribe: an IRCX type (with optional subject mask) or one/more categories. `MEDIA` is client-subscribable; other IRCX types and all categories are oper-only. |
| `EVENT CHANGE <type> [mask]` | Update an IRCX subscription's subject mask. |
| `EVENT DEL\|DELETE <type\|category\|ALL>` | Unsubscribe from an IRCX type or categories. |
| `EVENT CLEAR [type]` | Clear one IRCX type, or (no arg) all IRCX + category subscriptions, subject masks, and the severity floor. |
| `EVENT SEVERITY [level]` | Oper-only. Set or report the per-session minimum severity for the category plane. |
| `EVENT REPLAY [JSON] [category\|ALL] [count]` | Oper-only. Re-send recent history-ring events (severity-floored, oldest->newest); `JSON` returns bounded event objects for operator UIs. |
| `EVENT STATS [JSON]` | Oper-only. Per-category/severity counters since boot + live ring depth; `JSON` returns a stable object for operator UIs. |
| `EVENT BROADCAST :<message>` | Oper-only. The former WALLOPS, folded into the spine as an `.announce` event. |
| `EVENT OBSERVE <mask> [actions…] \| OFF \| LIST` | Oper-only. Manage the standing lifecycle-observation subscription (real hosts). |
