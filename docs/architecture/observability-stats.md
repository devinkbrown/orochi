# Orochi observability: channel stats and status feed

*The per-channel statistics engine and the public status feed as implemented in the current source tree.*

Orochi replaces ophion's `m_chanstats` with a native, in-process engine that aggregates live channel activity into per-channel counters and emits self-describing JSON for a static dashboard, plus a separate `status.json` public health feed. Both are pure data producers: no sockets, no SQLite. The daemon feeds the aggregate from its history chokepoints and flushes on a throttled cadence into a directory nginx serves at `/stats/`. The engine lives in [src/daemon/chanstats.zig](../../src/daemon/chanstats.zig); the daemon wiring and the status feed live in [src/daemon/server.zig](../../src/daemon/server.zig).

## Per-channel statistics engine

`ChanStats` owns a name→`ChannelAgg` map ([src/daemon/chanstats.zig:95](../../src/daemon/chanstats.zig#L95)). Three recorders drive it, all taking wall-clock unix-ms (`platform.realtimeMillis()`):

- `recordMessage` counts a channel message, bumps the hour-of-day bucket, the 7×24 weekday heatmap, and the current day, tokenizes the text into word-frequency counts, and updates the author's `UserAgg` with question/exclamation/URL/monologue behaviour metrics ([src/daemon/chanstats.zig:162](../../src/daemon/chanstats.zig#L162)). Hour and weekday derive from the timestamp in UTC ([src/daemon/chanstats.zig:168](../../src/daemon/chanstats.zig#L168)).
- `recordEvent` increments `joins`/`parts`/`quits`/`kicks` ([src/daemon/chanstats.zig:217](../../src/daemon/chanstats.zig#L217)).
- `recordTopic` appends to a bounded topic history ([src/daemon/chanstats.zig:228](../../src/daemon/chanstats.zig#L228)).

The engine is **bounded by construction**: per-channel user (4096) and word (8192) tables are capped, and when a table is full only already-tracked keys update, so a hostile flood cannot pin unbounded memory ([src/daemon/chanstats.zig:18](../../src/daemon/chanstats.zig#L18), [src/daemon/chanstats.zig:147](../../src/daemon/chanstats.zig#L147), [src/daemon/chanstats.zig:258](../../src/daemon/chanstats.zig#L258)). Day history caps at 60, topics at 40.

The daemon feeds the aggregate from its `recordHistory*` chokepoints: `chanstatsMessage` handles local and relayed channel PRIVMSGs, `chanstatsEvent` handles JOIN/PART/QUIT/KICK/TOPIC ([src/daemon/server.zig:12873](../../src/daemon/server.zig#L12873), [src/daemon/server.zig:12886](../../src/daemon/server.zig#L12886)). Both are no-ops unless `[stats] chanstats_dir` is set ([src/daemon/server.zig:1408](../../src/daemon/server.zig#L1408)), and `chanstatsMessage` skips ephemeral rooms so those messages leave no durable footprint ([src/daemon/server.zig:12879](../../src/daemon/server.zig#L12879)). Because relayed messages feed the same path, the aggregate captures channel activity from across the mesh that reaches this node.

### Outputs

`writeJson` prunes dead channels (below), then writes one `index.json` plus one `<slug>.json` per channel into `chanstats_dir` ([src/daemon/chanstats.zig:310](../../src/daemon/chanstats.zig#L310)). A channel is only emitted once it reaches `min_messages` (default 1), keeping fly-by one-liners out of the index ([src/daemon/chanstats.zig:333](../../src/daemon/chanstats.zig#L333)). `renderChannel` is split from the file write so it can be unit-tested by parsing the output back ([src/daemon/chanstats.zig:474](../../src/daemon/chanstats.zig#L474)). Every file is written via a temp-file + rename so nginx never serves a half-written file ([src/daemon/chanstats.zig:742](../../src/daemon/chanstats.zig#L742)).

A per-channel `<slug>.json` (from `renderChannel`, top-N capped at 30 users / 40 words):

```json
{
  "channel": "#root",
  "generated_at": 1700000000,
  "first_seen": 1699990000,
  "last_active": 1700000000,
  "present": 12,
  "last_speaker": "kain",
  "totals": {"messages": 842, "words": 5120, "active_users": 37,
             "joins": 60, "parts": 22, "quits": 14, "kicks": 1, "topic_changes": 3},
  "hours": [0,0,1, "…24 hourly totals…"],
  "days": [{"date": "2026-06-28", "messages": 120}, "…"],
  "heatmap": [[0,0,"…24…"], "…7 weekday rows…"],
  "top_users": [{"nick": "kain", "messages": 210, "words": 1400, "last_active": 1700000000,
                 "questions": 12, "exclamations": 30, "urls": 4, "monologue": 6}, "…"],
  "top_words": [{"word": "orochi", "count": 88}, "…"],
  "topics": [{"ts": 1699999000, "setter": "kain", "topic": "build channel"}, "…newest first…"],
  "records": {"busiest_day": {"date": "2026-06-30", "messages": 300}, "peak_hour": 20}
}
```

Note `present` is the live member count (below), while `active_users` is the all-time distinct-author count — before commit `b2232d2` consumers misread the latter as presence.

## Slug generation (must byte-match the client)

`slugify` lowercases, strips a leading channel prefix (`#`/`&`/`+`/`!`), keeps `[a-z0-9._-]`, maps every other byte to `_`, and neutralises a leading dot ([src/daemon/chanstats.zig:649](../../src/daemon/chanstats.zig#L649)). The slug is the join key between the served index and the per-channel file, so the server `slugify` and the client `channelToSlug` in the dashboard must produce byte-identical output or a card 404s. The pinned test vectors are `#root`→`root`, `#foo/bar`→`foo_bar`, `#../etc/passwd`→`_._etc_passwd`, `&.hidden`→`_hidden`, and `#`→null ([src/daemon/chanstats.zig:1063](../../src/daemon/chanstats.zig#L1063)); the same neutralisation guarantees a slug can never be `.`, `..`, or contain a path separator, so a crafted channel name can never escape the data dir.

## Persistence across restart / USR2

The served JSON is top-N capped (lossy), so it cannot be the persistence source. Instead the **whole aggregate** is serialized to a compact versioned binary snapshot, `.chanstats.snapshot`, written atomically alongside the JSON on every flush and reloaded once at boot, so per-channel stats survive a cold restart or a USR2 hot-upgrade ([src/daemon/chanstats.zig:803](../../src/daemon/chanstats.zig#L803), [src/daemon/chanstats.zig:365](../../src/daemon/chanstats.zig#L365)). `serialize`/`deserialize` are split from the file I/O so the round-trip is unit-testable in memory ([src/daemon/chanstats.zig:812](../../src/daemon/chanstats.zig#L812), [src/daemon/chanstats.zig:868](../../src/daemon/chanstats.zig#L868)), using little-endian length-prefixed framing (`putInt`/`putBytes`/`Cursor`).

The format is a 4-byte magic followed by an explicit format-version byte. The current magic is **`OCS2`** with version `1`; it supersedes the original `OCS1` from commit `0d33676`, which was bumped precisely to add the version byte after the magic ([src/daemon/chanstats.zig:762](../../src/daemon/chanstats.zig#L762)). A reader distinguishes "wrong file" (bad magic, e.g. a leftover `OCS1`) from "newer format" (good magic, higher version) and starts empty in either case — a one-time analytics reset is harmless. Loading is best-effort: a missing/short/corrupt blob leaves the aggregate empty, and a partial parse keeps already-restored channels. Load caps every re-read table at the same live ceiling, and rejects a snapshot listing the same channel twice, so a hostile snapshot cannot exceed limits or leak memory ([src/daemon/chanstats.zig:886](../../src/daemon/chanstats.zig#L886), [src/daemon/chanstats.zig:938](../../src/daemon/chanstats.zig#L938)). The daemon calls `loadChanstats` once at boot, gated on `chanstats_dir` + `crypto_io` ([src/daemon/server.zig:20285](../../src/daemon/server.zig#L20285)).

## Index: spark series, network daily series, live presence

`index.json` carries a top-level `users_online` plus a `network_days` series and a per-channel card list. Each card includes a compact `spark` array — the last up-to-14 daily message counts, oldest→newest — so the index renders per-card trends with no extra fetch ([src/daemon/chanstats.zig:346](../../src/daemon/chanstats.zig#L346)). `network_days` is the per-day message total merged across every tracked channel, computed into a bounded day-sorted set and emitted for the last 14 days ([src/daemon/chanstats.zig:371](../../src/daemon/chanstats.zig#L371)).

```json
{
  "generated_at": 1700000000,
  "network": "IRCXNet",
  "node": "eshmaki.me",
  "users_online": 214,
  "network_days": [{"date": "2026-06-28", "messages": 4200}, "…last 14…"],
  "channels": [
    {"channel": "#root", "messages": 842, "active_users": 37, "present": 12,
     "last_active": 1700000000, "topic": "build channel", "spark": [120,90,110,"…"]}
  ]
}
```

The live figures are injected by the server at flush time through a `NetInfo` struct so the engine stays world-agnostic and testable ([src/daemon/chanstats.zig:280](../../src/daemon/chanstats.zig#L280)). `users_online` is the mesh-wide user total from `meshUserCount`, which sums this node's local nicks plus each established peer link's `remoteNickCount` ([src/daemon/server.zig:19202](../../src/daemon/server.zig#L19202)). The per-channel `present` is provided by a `presence_fn` bound to `globalMemberCount` (local + mesh roster). Both are read under the same `world.lockWrite` the flush already holds, so presence is consistent with the recorder feed even on a multi-reactor node ([src/daemon/server.zig:3771](../../src/daemon/server.zig#L3771)).

## Dead-channel prune

A channel's stats used to persist forever, so transient/probe channels lingered in the index and directory long after their last member left. `writeJson` now calls `pruneDeadChannels` before rendering ([src/daemon/chanstats.zig:422](../../src/daemon/chanstats.zig#L422)). A channel is dead when it no longer exists — **unregistered AND empty** (zero local + mesh members). A dead channel's `<slug>.json` is deleted, its aggregate freed, and it drops from the map, so it vanishes from the index and from `network_days` too. A registered channel survives even while momentarily empty; a currently-populated one always survives.

Existence is decided by the optional `exists_fn` callback ([src/daemon/chanstats.zig:291](../../src/daemon/chanstats.zig#L291)). The server binds it to a predicate that returns true when `globalMemberCount > 0` or `Services.channelIsRegistered` reports a durable `.chanregs` record ([src/daemon/server.zig:3780](../../src/daemon/server.zig#L3780), [src/daemon/services.zig:2158](../../src/daemon/services.zig#L2158)). When `exists_fn` is absent — tests and headless callers with no world context — **nothing is pruned**, preserving backward-compatible behaviour. Pruning is two-phase (collect up to 64 dead keys, then remove) so the map is never mutated mid-iteration, and it is best-effort so a file-delete error never blocks the flush.

## Public status feed: `status.json`

The same flush also emits `status.json` beside the channel stats ([src/daemon/server.zig:3795](../../src/daemon/server.zig#L3795)). `buildStatusJson` is a pure, testable builder that renders into a caller buffer; `writeStatusJson` wraps it with the same atomic temp-file + rename as the rest ([src/daemon/server.zig:4052](../../src/daemon/server.zig#L4052), [src/daemon/server.zig:4043](../../src/daemon/server.zig#L4043)). Each node writes its own file from its own perspective.

```json
{
  "generated_at": 1700000000,
  "network": "IRCXNet",
  "node": "eshmaki.me",
  "description": "Orochi flagship node",
  "icon_url": "https://example.test/orochi.png",
  "discoverable": true,
  "uptime_seconds": 86400,
  "users_online": 214,
  "activity": {"channels": 12, "messages": 2048, "active_channels_24h": 5, "last_active": 1700000000},
  "mesh": {"quorum": true, "partitioned": false, "components": 1},
  "accounts": {"key_transparency": {"enabled": true, "entries": 42, "root": "..." }},
  "history": {"targets": 12, "entries": 2048, "tombstones": 17, "root": "..."},
  "peers": [
    {"name": "ircx.us", "state": "up", "up": true, "rtt_ms": 38, "since_seconds": 3600},
    {"name": "stale.node", "state": "down", "up": false, "rtt_ms": null, "since_seconds": 120}
  ]
}
```

Node identity is `network` + `node` (`serverName`). `description`, `icon_url`,
and `discoverable` are operator-controlled directory metadata from `[network]`;
`discoverable` is explicit opt-in, so private meshes can publish local health
without asking public crawlers to index them. `uptime_seconds` is derived from
`boot_unix`; `users_online` is again `meshUserCount` ([src/daemon/server.zig:4054](../../src/daemon/server.zig#L4054)). The `activity` object is a compact liveness
summary from the same bounded `ChanStats` aggregate used by `index.json`, counting
only channels that meet the public index threshold and exposing last activity for
directory ranking. The `mesh` envelope reflects the live partition detector —
`quorum`, `partitioned`, and `components` come from `partition_quorum`/
`partition_split`/`partition_components`, which `updatePartitionTransitions`
maintains on every link up/down ([src/daemon/server.zig:4066](../../src/daemon/server.zig#L4066)). The `accounts.key_transparency` object exposes the live account
credential transparency root/size when services are attached, and `history`
reports retained Lotus CHATHISTORY target, entry, and tombstone counts plus a
deterministic BLAKE3 root over sorted targets and retained entries.

The `peers` array is built from the live `peer_health` registry ([src/daemon/server.zig:2657](../../src/daemon/server.zig#L2657), [src/daemon/link_health.zig:286](../../src/daemon/link_health.zig#L286)). For each used slot it emits the peer name, a `state` string mapped by `peerStatusString` (`established`→`up`, `connecting`/`handshaking`→`connecting`, `draining`, `down`), a boolean `up`, the smoothed `rtt_ms` (the EWMA `ewma_rtt_ms`, or `null` before the first sample), and `since_seconds` — the time in the current state from `LinkHealth.since` ([src/daemon/server.zig:4029](../../src/daemon/server.zig#L4029), [src/daemon/link_health.zig:54](../../src/daemon/link_health.zig#L54), [src/daemon/link_health.zig:99](../../src/daemon/link_health.zig#L99)). Two tests cover the shape and the state mapping ([src/daemon/server.zig:28783](../../src/daemon/server.zig#L28783), [src/daemon/server.zig:28824](../../src/daemon/server.zig#L28824)).

Because the feed reads from `peer_health` and the partition state, it stays correct across a zero-drop USR2. A preserved (never-dropped) mesh link resumes already established, so the fresh-establishment hook never fires for it; `adoptInheritedS2sLink` therefore re-runs the peer-up registration — `publishServerLink`, `markPeerHealth(.established)`, `publishPeerCount`, `updatePartitionTransitions` — so `status.json` reflects the preserved peer immediately after the upgrade instead of showing an empty peer list ([src/daemon/server.zig:14937](../../src/daemon/server.zig#L14937)).

## Cadence and gating

Both files write on the shared `[stats] stats_interval_ms` cadence (default 30 s), throttled by `chanstats_last_write_ms`, and only when `chanstats_dir` and `crypto_io` are both configured ([src/daemon/server.zig:3763](../../src/daemon/server.zig#L3763), [src/daemon/server.zig:1410](../../src/daemon/server.zig#L1410)). The flush runs inside the timer completion under `world.lockWrite`, so it is serialized against the recorder feed on a multi-reactor node and exactly one flush happens per interval.
