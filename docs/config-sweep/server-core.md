# Orochi daemon core hardcoded operational/tuning constant sweep

This read-only survey maps daemon-core operational constants to existing or proposed TOML controls.

Scope: `src/daemon/server.zig`, `src/daemon/dispatch.zig`, `src/daemon/client.zig`
(accept-loop, timeout sweep, and listener logic all live in `server.zig`).
Excludes IRC numerics, wire/protocol-fixed sizes, enum discriminants,
struct-layout array widths, and pure test literals.

Existing schema sections (`config_format.zig` Schema): `[node] [listen] [oper]
[mesh] [limits] [media] [sasl] [cloak]`.

Legend: rows whose proposed key already exists in the schema are tagged
*(schema-backed)*. The literal is the hardcoded default in `Config`/code and is
mapped through `config_boot.zig`. Other rows are not yet liftable via TOML.

---

## [listen]

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| server.zig:686 | `Config.host` | `"127.0.0.1"` | bind address for IRC/S2S listeners | `listen.host` *(schema-backed; default "127.0.0.1")* | string | 127.0.0.1 | – |
| server.zig:541 | `default_host` | `"localhost"` | fallback host string used when no host supplied | `listen.host` (reuse) | string | localhost | – |
| server.zig:687 | `Config.port` | (required, no default) | IRC listener TCP port | `listen.irc` *(schema-backed; required)* | uint(port) | – | 1..65535 |
| server.zig:722 | `Config.s2s_port` | `0` (disabled) | Suimyaku mesh S2S listener port (0=off) | `listen.s2s` *(schema-backed; default 0)* | uint(port) | 0 | 0..65535 |

## [limits]

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| server.zig:688 | `Config.backlog` | `128` | listen() accept backlog depth | `limits.backlog` *(schema-backed)* | uint | 128 | 1..32767 |
| server.zig:693 | `Config.max_clients` | `1024` | hard cap on concurrent connections; client table pre-reserves this many slots | `limits.max_clients` *(schema-backed)* | uint | 1024 | 1..32767 |
| server.zig:696 | `Config.registration_timeout_ms` | `30_000` | drop conns that never finish NICK+USER within window | `limits.handshake_timeout` *(schema-backed; default 30s)* | duration | 30s | >=1s |
| server.zig:700 | `Config.ping_interval_ms` | `120_000` | idle silence before server sends unsolicited PING | `limits.ping_interval` *(schema-backed; default 120s)* | duration | 120s | >=1s |
| server.zig:702 | `Config.ping_timeout_ms` | `60_000` | grace after server PING before "Ping timeout" drop | `limits.ping_timeout` *(schema-backed; default 60s)* | duration | 60s | >=1s |
| server.zig:706 | `Config.max_clones_per_ip` | `0` (unlimited) | max concurrent conns from one exact IP | `limits.max_clones_per_ip` *(schema-backed)* | uint | 0 | 0..65535 |
| server.zig:709 | `Config.max_clones_per_net` | `0` (unlimited) | max concurrent conns across /24 (v4) or /64 (v6) | `limits.max_clones_per_net` *(schema-backed)* | uint | 0 | 0..65535 |
| server.zig:712 | `Config.reputation_refuse_threshold` | `0` (disabled) | decaying-penalty score at which accept is refused | `limits.reputation_refuse_threshold` *(schema-backed)* | uint | 0 | 0..1000000 |
| server.zig:714 | `Config.reputation_half_life_ms` | `60_000` | half-life of IP-reputation penalty decay | `limits.reputation_half_life` *(schema-backed; default 60s)* | duration | 60s | >=1s |
| server.zig:531 | `timer_interval_ms` | `2_000` | period of the io_uring timeout-sweep timer (drives reg/ping/idle enforcement granularity) | `limits.sweep_interval` (NEW) | duration | 2s | 100ms..60s |
| dispatch.zig / sasl_mechrouter.zig | `MAX_RAW_MESSAGE` | `512` | max decoded SASL AUTHENTICATE payload bytes for preregistration SASL and IRCX AUTH. The TOML value can lower, but not raise above, the fixed protocol buffer. | `limits.sasl_decode_max_bytes` *(schema-backed; default 512)* | uint | 512 | 64..512 |
| config_format.zig:239 | `Config.nick_delay_ms` | `0` (disabled) | hold window for released nicks after owner exits; prevents nick-camping; `0` = disabled | `limits.nick_delay` *(schema-backed)* | duration | 0 | 0..– |

## [io] (new): io_uring and transport tuning

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| server.zig:689 | `Config.ring_entries` | `32` | io_uring submission/completion queue depth | `io.ring_entries` *(schema-backed; default 32)* | uint | 32 | 8..4096 |
| server.zig / `runOnce` | `Config.cqe_batch` | `256` | max CQEs reaped per event-loop drain (`cqes` array in loop) | `io.cqe_batch` *(schema-backed; default 256)* | uint | 256 | 16..4096 |
| server.zig:537 | `default_reply_bytes` | `8192` | per-connection send buffer size (`ConnState.send_buf`) — borderline (struct buffer, but perf/queue-meaningful) | `io.send_buf_bytes` (NEW) | uint | 8192 | 512..262144 |
| server.zig:538 | `default_recv_bytes` | `4096` | per-connection recv buffer size (`ConnState.recv_buf`) — borderline | `io.recv_buf_bytes` (NEW) | uint | 4096 | 512..262144 |

## [node]

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| server.zig:728 | `Config.node_id` | `1` (placeholder) | sovereign mesh identity; keys registry/CRDT/gossip; seeds snowflake generator | `node.id` *(schema-backed; required, min 1)* | uint | 1 | 1..(u64 max) |
| server.zig:739 | `Config.mesh_pass` | `""` | shared mesh auth password for plaintext S2S | `mesh.mesh_pass` *(schema-backed)* | string | "" | – |

## [reputation] (new): IP-reputation penalty weights

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| server.zig:534 | `reg_timeout_penalty` | `50.0` | reputation penalty added when a conn never completes registration (scan signature) | `reputation.registration_timeout_penalty` (NEW) | float | 50.0 | 0..1000 |
| server.zig:536 | `clone_refuse_penalty` | `25.0` | reputation penalty added when accept refused by clone limiter | `reputation.clone_refuse_penalty` (NEW) | float | 25.0 | 0..1000 |

## Borderline and informational hardcoded identity strings

These values likely belong in config but are placeholders today.

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| server.zig:540 | `server_name` | `"orochi.local"` | server name in numerics/prefixes/ERROR lines — borderline (identity, not tuning) | `node.server_name` (NEW) | string | orochi.local | – |
| dispatch.zig:20 | `SERVER_NAME` | `"orochi.local"` | server name in dispatch-layer replies (isolation/test path mirror) — borderline | `node.server_name` (reuse) | string | orochi.local | – |
| dispatch.zig:21 | `NETWORK_NAME` | `"Orochi"` | network name advertised in ISUPPORT — borderline (identity) | `node.network_name` (NEW) | string | Orochi | – |

## [class.<name>] (new): Per-connection policy classes

Source: `Policy`/`ClassDef` at `src/daemon/conn_class.zig`, config parsing at `src/daemon/config_format.zig:247`, registry bootstrap at `src/daemon/config_boot.zig`, live inspection at `STATS Y` (numeric 218 RPL_STATSYLINE).

A **connection class** is a named bundle of per-connection resource, admission, and flood policy. It matches at client registration by IP/CIDR, TLS status, account auth, oper status, and ident/host globs. The first class in file order whose match criteria are all satisfied wins; a catch-all (no criteria) is fallback. Two built-in classes always exist: `user` (regular clients) and `server` (mesh S2S links). Per-class limits override the matching `[limits]` global values; `0` means "inherit global". Size parameters accept `K`/`M`/`G` suffixes; durations are strings (`"30s"`).

| Concept | What it controls |
|---------|------------------|
| Match criteria | `match` (IPv4/IPv6 CIDR array), `match_tls` (implicit-TLS only), `match_account` (SASL-auth only), `match_oper` (opered clients only), `match_ident` / `match_host` (glob patterns on username/hostname) |
| Resource policy | `sendq` (outbound queue ceiling; growable up to this limit), `recvq` (inbound line buffer ceiling; 0 = inherit physical default), `max_clients` (cap on class membership), `max_per_ip` (concurrent connections per IP within class) |
| Per-connection limits | `max_channels` (JOIN cap; 0 = inherit chanlimit), `max_targets` (PRIVMSG targets; 0 = inherit maxtargets), `monitor` (MONITOR entries; 0 = inherit monitorlimit), `silence` (SILENCE masks; 0 = inherit silencelimit) |
| Timeout policy | `ping_interval`, `ping_timeout`, `register_timeout` (durations; 0 = inherit `[limits]` global) |
| Flood control | `flood_lines` (max inbound lines per window; 0 = no limit), `flood_window` (duration; defaults to 10s if only flood_lines set); exempt via `flood_exempt` |
| Admission gates | `require_tls` (refuse non-TLS), `require_sasl` (refuse unauthenticated); `nick_delay_exempt` (bypass nick-delay hold) |

See `docs/reference/config.md` (`[class.<name>]` section) and `etc/orochi.reference.toml` for full parameter table and examples.

---

## Excluded constants (intentionally not lifted)

- `client.zig` MAX_*_BYTES (nick/uid/host/topic/mask/realname/account/label/oper-class)
  and `dispatch.zig` MAX_* + MAX_PARAMS=15 — protocol/struct-layout fixed sizes.
- `dispatch.zig` CAP reply buffers (`[8]CapReply`, `[2048]`, `[512]` storage) and
  `[3]u8` numeric code buffer — IO-scratch / struct layout, not operational tuning.
- `server.zig:539` `default_line_bytes = MAX_LINE_BODY + 2` — RFC line-length derived.
- `secs * 1000`, `/ 1000` uptime/expiry math; snowflake masks; numeric enum codes.
- Test-only literals: `budget_ms`/`max_polls*25`/`20_000` (server.zig:7806),
  `recvUntil(..., 200)` timeouts, `local_epoch_ms = 2000/3000` in tests.
