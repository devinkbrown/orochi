# Orochi configuration reference

*Complete operator-facing reference for the daemon TOML format.*

This reference is verified against `Config` and `parseToml` in `src/daemon/config_format.zig:29`, `src/daemon/config_format.zig:310`, and the live boot projection in `src/daemon/config_boot.zig:18`.

Orochi is a pure-Zig 0.16 clean-room IRC daemon and a bespoke successor to C ophion, not a clone. The daemon target is 64-bit only (`build.zig:20`, `build.zig:24`), uses implicit TLS rather than STARTTLS (`src/main.zig:216`, `src/main.zig:219`), and uses Zig-native OroStore persistence rather than LMDB (`src/daemon/store.zig:1`, `src/daemon/store.zig:3`).

Use `etc/orochi.reference.toml` as the runnable example and copy from it when building an instance config. Two keys are required: `[node].id >= 1` and `[listen].irc != 0`. Missing either makes `parseToml` fail (`src/daemon/config_format.zig:478`).

## Format rules

The config file is TOML v1.0 (`src/daemon/config_format.zig:3`). Missing keys keep typed defaults (`src/daemon/config_format.zig:4`, `src/daemon/config_format.zig:9`). Integer fields use the ranges in `parseToml`; out-of-range values return `ParseError` (`src/daemon/config_format.zig:542`). Durations are quoted strings using `ms`, `s`, `m`, or `h`, must be non-zero, and are converted to milliseconds (`src/daemon/config_format.zig:556`).

The parser supports string indirection for any string value: `env:NAME` and `@file:path` (`src/daemon/config_format.zig:486`). The CLI boot path wires both resolvers through `ResolverCtx`, so config strings can pull from the process environment or from files relative to the daemon working directory (`src/main.zig:8`, `src/main.zig:23`, `src/main.zig:64`).

The live mapping is conservative: only non-empty or non-zero values overlay onto `server.Config` (`src/daemon/config_boot.zig:15`). TLS and STS are projected separately because `server.Config` does not own those parser structs (`src/daemon/config_boot.zig:92`, `src/daemon/config_boot.zig:119`).

## Required keys

| Key | Requirement | Source |
|---|---:|---|
| `[node].id` | Required, integer >= 1 | `src/daemon/config_format.zig:319`, `src/daemon/config_format.zig:479` |
| `[listen].irc` | Required, port 1..65535 | `src/daemon/config_format.zig:338`, `src/daemon/config_format.zig:480` |

## `[node]`

Source: struct fields at `src/daemon/config_format.zig:50`, parsing at `src/daemon/config_format.zig:318`, S2S identity wiring at `src/main.zig:141`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `id` | integer | `0` before validation | required, `>= 1` | Sovereign node id used by the runtime config (`src/daemon/config_boot.zig:60`) and mesh identity paths. |
| `public_key` | string or null | unset | any string | Parsed and stored for node identity metadata; not directly overlaid by `mapToServerConfig`. |
| `secret_key` | string or null | unset | any string | If set, `main.zig` derives a node identity and enables PQ-secured S2S (`src/main.zig:147`). |

## `[network]`

Source: struct at `src/daemon/config_format.zig:56`, parsing at `src/daemon/config_format.zig:326`, mapping at `src/daemon/config_boot.zig:20`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `name` | string | `"Orochi"` | any string | Network name advertised in ISUPPORT `NETWORK=` and the welcome burst (`src/main.zig:129`). |
| `server_name` | string or null | `"orochi.local"` | any hostname | This node's own server name — the source prefix of all server-originated lines (welcome numerics, the `!weather`/`!news` bot replies, ERROR/PING) and the identity presented to S2S peers. MUST be unique per node in a mesh so replies/identities don't collide (`src/proto/protocol_inventory.zig` `setServerName`). |
| `description` | string or null | unset | any string | Per-node description shown in VERSION/WHOIS and gossiped to mesh peers (`src/daemon/config_format.zig:67`, `src/daemon/config_boot.zig:22`). |
| `icon_url` | string or null | unset | URL string | IRCv3 network icon: when set, advertised as the `NETWORKICON=<url>` ISUPPORT token (clients may render the logo); omitted when unset. Ophion `n_url`/NETWORKICON parity (`src/daemon/server.zig` `buildIsupportTokens`, `src/daemon/config_boot.zig`). |

## `[motd]`

Source: struct at `src/daemon/config_format.zig:62`, parsing at `src/daemon/config_format.zig:329`, mapping at `src/daemon/config_boot.zig:21`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `text` | string or null | unset | any string | MOTD body served by `MOTD`; newlines are split into MOTD lines. Supports `@file:` at parser level. |

The MOTD is a **per-connection template** expanded by `src/proto/motd_template.zig`
before being split into lines. When omitted or empty, the server serves a
personalized built-in default.

Substitutions use `{key}`; unknown keys are left verbatim, and `{{` / `}}` emit
literal braces. The available keys are `{nick}`, `{account}`, `{host}`,
`{network}`, `{server}`, `{version}`, `{time}`, `{date}`, `{users}`, `{opers}`,
and `{channels}`, plus `{greeting}` (a time-of-day greeting) and `{weather}` /
`{news}` (see `[weather]` / `[news]`).

Conditionals take the form `{if:COND}…{else}…{/if}`, where `COND` is `oper`,
`account`, `secure`, `weather`, or `news` (the last two are true when that line is
available); conditionals nest. For example:
`{if:account}Welcome back, {account}!{else}Please register.{/if}`

## `[admin]`

Source: struct at `src/daemon/config_format.zig:69`, parsing at `src/daemon/config_format.zig:332`, mapping at `src/daemon/config_boot.zig:22`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `location` | string | `"Orochi IRC network"` | any string | ADMIN command location line (`src/daemon/server.zig:916`). |
| `email` | string | `"admin@orochi.local"` | any string | ADMIN command contact email (`src/daemon/server.zig:916`). |

## `[weather]`

Localized weather for the MOTD `{weather}` placeholder. The daemon reads `source`
(a `key=value` file refreshed by an external updater) and renders it in the units
the region uses (`src/proto/weather_units.zig`; `src/daemon/server.zig` `handleMotd`).


| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `{weather}` MOTD line. |
| `source` | string or null | unset | path | `key=value` file (`temp_c`, `wind_kph`, `precip_mm`, `desc`, `location`, `country`); read fresh per `MOTD`. Supports `@file:`. |
| `location` | string or null | unset | any string | Display location override (else the file's `location`). |
| `country` | string or null | unset | ISO code | Country for unit selection (else the file's `country`). |
| `units` | string or null | unset (`auto`) | `auto`/`metric`/`imperial`/`uk` | Unit override. `auto` = by country: US + territories → °F/mph; GB → °C/mph; else °C/km/h. |

## `[news]`

Headlines for the MOTD `{news}` placeholder.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `{news}` MOTD line. |
| `source` | string or null | unset | path | File with one headline per line; the first `count` are joined with `" | "`. Supports `@file:`. |
| `count` | integer | `3` | `1..20` | Number of headlines to show. |

## `[geo]`

The live in-channel `!weather`/`!news` bot (see
[commands/fantasy-bot.md](commands/fantasy-bot.md)). When enabled, the daemon
fetches `wttr.in` (weather) and the bundled RSS feeds (news) on a background
thread and serves them to channel fantasy commands. All sources are key-free.

Source: struct at `src/daemon/config_format.zig` (`Geo`), mapping at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | — | Enable the `!weather`/`!news` bot. |
| `news_insecure_tls` | bool | `true` | — | Skip TLS verification for the public read-only news feeds, so the best-effort clean-room TLS reaches more hosts. Weather is plain HTTP and unaffected. |
| `cmd_cooldown_ms` | integer | `3000` | `0..600000` | Minimum interval between bot replies in a single channel (anti-flood). 0 disables. |
| `default_location` | string or null | unset | any string | Fallback `!weather` location when a user has no GeoIP / `location` metadata. |
| `news_cache_dir` | string or null | unset | path | Directory of headline files written by `tools/news_update.sh` (one headline per line, `src_<key>.txt` / `cc_<cc>.txt`). When set, `!news` reads these files instead of fetching live — robust full coverage of every feed regardless of the in-daemon TLS reach. |

## `[listen]`

Source: struct at `src/daemon/config_format.zig:75`, parsing at `src/daemon/config_format.zig:336`, mapping at `src/daemon/config_boot.zig:24`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `host` | string | `"127.0.0.1"` | any string accepted by bind helpers | Bind address for runtime listeners (`src/daemon/config_boot.zig:25`). |
| `irc` | port integer | `0` before validation | required, `1..65535` | Plain IRC listener port. Current parser requires this even for TLS-first deployments. |
| `ws` | port integer | `0` | `0..65535` | Secure-WebSocket browser listener intent. `mapToServerConfig` overlays it into `ws_enabled`/`ws_port`; the listener stands up when TLS certificates are loaded, or with testing-only `ws_plain` (`src/daemon/config_format.zig:462`, `src/daemon/config_boot.zig:45`, `src/main.zig:350`, `src/daemon/server.zig:1862`). |
| `webtransport` | port integer | `0` | `0..65535` | UDP WebTransport/HTTP3 listener port. `mapToServerConfig` overlays it into `webtransport_port`, and `main.zig` starts `webtransport_listener.zig` when TLS certificate/signing material and the IRC listener are available (`src/daemon/config_boot.zig:45`, `src/main.zig:472`, `src/main.zig:494`). |
| `ws_plain` | bool | `false` | `true` or `false` | Testing-only plain WebSocket mode. Only used when `ws` is non-zero; production browser clients require TLS (`src/daemon/config_format.zig:139`, `src/daemon/config_boot.zig:54`). |
| `proxy_protocol` | bool | `false` | `true` or `false` | Enable HAProxy PROXY v1/v2 header consumption before IRC/TLS/WebSocket framing, gated by `trusted_proxies` (`src/daemon/config_format.zig:141`, `src/daemon/config_boot.zig:46`, `src/daemon/server.zig:4107`). |
| `trusted_proxies` | array of strings | `[]` | IP literals | Source IPs allowed to supply PROXY headers; empty disables trusted PROXY handling even if `proxy_protocol` is true (`src/daemon/config_format.zig:144`, `src/daemon/server.zig:3614`, `src/daemon/server.zig:3633`). |
| `s2s` | port integer | `0` | `0..65535` | Server-to-server mesh listener; `0` disables it (`src/daemon/config_boot.zig:26`, `src/daemon/server.zig:1046`). |
| `media` | port integer | `0` | `0..65535` | UDP media transport plane port; `0` means ephemeral (`src/daemon/config_boot.zig:27`, `src/daemon/server.zig:963`). |
| `native_media` | port integer | `0` | `0..65535` | Native OPVOX/OPVIS media UDP port; `0` means ephemeral (`src/daemon/config_boot.zig:28`, `src/daemon/server.zig:971`). |
| `media_host` | string | `"127.0.0.1"` | any string | Advertised media candidate host/IP (`src/daemon/config_boot.zig:29`, `src/daemon/server.zig:965`). |

## `[mesh]`

Source: struct at `src/daemon/config_format.zig:109`, parsing at `src/daemon/config_format.zig:346`, secured S2S wiring at `src/main.zig:141`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `realm` | string | `"local"` | any string | Realm fed into node identity derivation for secured S2S (`src/main.zig:149`). |
| `trust_roots` | array of strings | `[]` | hex/base64 Ed25519 public keys | Parsed, mapped to `server.Config.mesh_trust_roots`, decoded at server init, and used as the expected secured-S2S peer key allowlist (`src/daemon/config_format.zig:177`, `src/daemon/config_boot.zig:101`, `src/daemon/server.zig:2272`, `src/daemon/server.zig:3833`). |
| `mesh_pass` | string or null | unset | any string | Shared passphrase carried into S2S handshake config when node identity is configured (`src/main.zig:152`, `src/daemon/server.zig:1074`). |
| `connect` | array of strings | `[]` | `host:port` strings | Peers auto-dialed at boot and retried while down; IPv6 hosts must be bracketed (`src/daemon/config_format.zig:179`, `src/daemon/config_boot.zig:105`, `src/daemon/server.zig:2249`). |
| `require_secured` | bool | `false` | `true`/`false` | Refuse plaintext S2S: reject inbound plaintext peers and never dial plaintext outbound. When secured S2S is unavailable, all S2S is dropped rather than falling back to clear (`src/main.zig` mesh wiring, `src/daemon/server.zig` handleAccept / initiateS2sConnectToAddr). |

Plaintext S2S applies when no node identity is configured and `require_secured` is false; secured S2S is enabled by `[node].secret_key` (`src/main.zig:141`, `src/main.zig:153`).

## `[dnsbl]`

Source: `Dnsbl` struct + parsing in `src/daemon/config_format.zig`; resolver in `src/daemon/dnsbl_resolver.zig`; construction in `src/main.zig`; enforcement in `src/daemon/server.zig` (`enforceDnsbl`).

Connect-time DNS blocklist. Each non-loopback client IP is checked against the configured zones on a background resolver thread (off the accept path), and a listed IP is enforced at registration. **Fail-open**: an IP whose lookup has not resolved by registration — or that no zone lists — is always admitted (a blocklist never refuses an IP it has not confirmed as listed). Operators and loopback are exempt. Uses the system resolver (`/etc/resolv.conf`); inert when that yields no nameservers or no zones are configured.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true`/`false` | Master switch; the resolver is built only when enabled with at least one zone. |
| `zones` | array of strings | `[]` | DNSBL zone hostnames | Blocklist zones queried per IP (A-record `127.0.0.x` = listed). The first zone that lists the IP wins, e.g. `["zen.spamhaus.org", "dnsbl.dronebl.org"]`. |
| `action` | string | `"refuse"` | `refuse` / `ward` | Enforcement for a listed IP: `refuse` closes the connection; `ward` additionally records a node-scope Warden ban so the block persists across the IP's reconnects. |

## `[mail]`

Source: `Mail` struct + parsing in `src/daemon/config_format.zig`; sender in `src/daemon/mail_sender.zig`; construction in `src/main.zig`; REGISTER delivery in `src/daemon/server.zig`.

Outbound SMTP submission relay. When enabled with a relay host + sender, account email-verification codes are delivered out-of-band through the relay on a background thread, so REGISTER can verify email ownership. Disabled (default) = no mail (REGISTER records emails as unverified). A submission CLIENT to an existing relay, never the daemon's own MTA.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true`/`false` | Master switch; the sender is built only when enabled with `relay_host` + `from`. |
| `relay_host` | string | unset | hostname | Submission relay (resolved via DNS A record). |
| `relay_port` | integer | `587` | `1..65535` | `587` = STARTTLS; `465` = implicit TLS. |
| `starttls` | bool | `true` | `true`/`false` | `false` selects port-465 implicit TLS (TLS from connect). |
| `from` | string | unset | email address | Envelope sender + `From:` header. |
| `user` / `pass` | string or null | unset | relay credentials | Optional AUTH PLAIN credentials. |
| `insecure_skip_verify` | bool | `false` | `true`/`false` | Skip TLS cert verification. **Security:** cert verification is not yet wired, so AUTH to a NON-loopback relay is REFUSED unless this is explicitly set true (a MITM could otherwise capture the submission credentials). Prefer a relay on localhost / a trusted path. |

## `[limits]`

Source: struct at `src/daemon/config_format.zig:115`, parsing at `src/daemon/config_format.zig:354`, mapping at `src/daemon/config_boot.zig:35`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `backlog` | integer | `128` | `1..32767` | Listener backlog (`src/daemon/config_boot.zig:35`). |
| `max_clients` | integer | `1024` | `1..32767` | Reserved connection table size and accept cap (`src/daemon/server.zig:983`). |
| `num_shards` | integer | `1` | `1..max_shards` | Worker reactor shards. **Opt-in: defaults to 1** (single in-line reactor); set `> 1` to run that many reactor threads. `Server.init` allocates the reactor array from the (clamped) shard count, and `runThreaded` spawns one worker per reactor plus the cross-shard delivery fabric when more than one reactor exists. Multi-reactor is correct under the coarse `world.lockWrite` taken once per completion (parallel io_uring I/O, serialized command processing). |
| `handshake_timeout` | duration string | `"30s"` | positive `ms/s/m/h` duration | Registration timeout, mapped to `registration_timeout_ms` (`src/daemon/config_boot.zig:47`). |
| `ping_interval` | duration string | `"2m"` | positive `ms/s/m/h` duration | Idle interval before server PING (`src/daemon/config_boot.zig:48`). |
| `ping_timeout` | duration string | `"1m"` | positive `ms/s/m/h` duration | Grace after PING before disconnect (`src/daemon/config_boot.zig:49`). |
| `topiclen` | integer | `390` | `1..8192` | TOPICLEN advertised and enforced (`src/daemon/server.zig:919`). |
| `awaylen` | integer | `256` | `1..256` | AWAYLEN advertised and enforced (`src/daemon/server.zig:922`). |
| `kicklen` | integer | `307` | `1..400` | KICKLEN advertised and enforced (`src/daemon/server.zig:925`). |
| `nicklen` | integer | `64` | `1..64` | NICKLEN advertised and enforced (`src/daemon/server.zig:928`). |
| `channellen` | integer | `64` | `2..200` | CHANNELLEN advertised and enforced (`src/daemon/server.zig:932`). |
| `maxlist` | integer | `100` | `1..10000` | Per-channel list mode cap for `+b/+e/+I/+Z` (`src/daemon/server.zig:935`). |
| `chanlimit` | integer | `50` | `1..10000` | Max channels per non-oper (`src/daemon/server.zig:938`). |
| `maxtargets` | integer | `4` | `1..64` | Max comma-separated PRIVMSG/NOTICE targets (`src/daemon/server.zig:941`). |
| `modes_per_line` | integer | `4` | `1..20` | Channel-mode changes a client should combine per MODE command, advertised as the `MODES` ISUPPORT token. Clients that honor it (mIRC, HexChat) send one mode/target per line when set to `1` (`src/daemon/server.zig` `buildIsupportTokens`). |
| `monitorlimit` | integer | `128` | `1..100000` | MONITOR target limit (`src/daemon/server.zig:945`). |
| `silencelimit` | integer | `32` | `1..256` | SILENCE mask limit (`src/daemon/server.zig:948`). |
| `max_clones_per_ip` | integer | `0` | `0..65535` | Exact-IP clone cap; `0` disables (`src/daemon/server.zig:1005`). |
| `max_clones_per_net` | integer | `0` | `0..65535` | Network-prefix clone cap; `0` disables (`src/daemon/server.zig:1009`). |
| `nick_delay` | duration string | `"0"` (disabled) | non-negative `ms/s/m/h` duration | Hold a released nick against reuse for this window after its owner exits (anti nick-camping). The owning account may reclaim during the window; opers and `nick_delay_exempt` classes bypass. `0` disables (`src/daemon/config_format.zig`, `src/daemon/nick_delay.zig`). |
| `throttle_connects` | integer | `0` (disabled) | `0..1000000` | Connection-rate throttle: max NEW connections one source IP may open within `throttle_window`; excess is refused at accept. Loopback and `trusted_proxies` are exempt (a shared reverse proxy is never throttled as one IP), making it WebSocket-safe. `0` disables (`src/daemon/clone_detect.zig`, `src/daemon/server.zig` `refuseSilentClient`). |
| `throttle_window` | duration string | `"10s"` | positive `ms/s/m/h` duration | Sliding window for `throttle_connects`. |
| `raid_joins` | integer | `0` (disabled) | `0..65535` | Network raid guard: a default join-throttle applied to channels with no explicit `+j` mode. At most `raid_joins` joins per `raid_window` before new joins are denied (`ERR_THROTTLE`) and a one-shot `.flood` Event-Spine raid alert fires. An explicit `+j` always overrides this default; opers and invited users bypass. `0` disables (`src/daemon/world.zig` `throttleAdmit`, `src/daemon/server.zig` `raidAlert`). |
| `raid_window` | duration string | `"10s"` | positive `ms/s/m/h` duration | Window for `raid_joins`. |
| `max_clones_per_ip_net` | integer | `0` (disabled) | `0..65535` | Network-wide (mesh) concurrent connections per source IP: this node plus every peer's count for the same IP, gossiped as a salted hash (raw IPs never cross the wire; needs a shared `[mesh] pass`). Authenticated accounts get +2; `limit_exempt` opers bypass; loopback/trusted proxies exempt (`src/daemon/mesh_clones.zig`, `src/daemon/server.zig`). |
| `reputation_refuse_threshold` | integer | `0` | `0..1000000` | Refuse connects at or above decaying reputation score; `0` disables (`src/daemon/server.zig:1012`). |
| `reputation_half_life` | duration string | `"1m"` | positive `ms/s/m/h` duration | IP reputation score decay half-life (`src/daemon/config_boot.zig:53`). |
| `sweep_interval` | duration string | `"2s"` | positive `ms/s/m/h` duration | Timeout sweep timer granularity (`src/daemon/config_boot.zig:54`). |

## `[class.<name>]`

Source: `Policy`/`ClassDef` at `src/daemon/conn_class.zig` and `src/daemon/config_format.zig:247`, parsing at `src/daemon/config_format.zig:780`, registry built at `src/daemon/config_boot.zig`.

A **connection class** is a named bundle of per-connection resource, admission, and flood policy, assigned to a client at registration by matching its IP, TLS, account, oper status, and ident/host. The first class in file order whose `match_*` criteria are all satisfied wins; a class with no criteria is a catch-all. Two built-ins always exist as fallbacks: `user` and `server`. Per-class limits **override** the matching `[limits]` / `nick_delay` globals; a `0` value means "inherit the global". Inspect live classes and per-class member counts with `STATS Y`.

Sizes accept `K`/`M`/`G` suffixes (`"1M"` = 1048576). Durations are strings (`"30s"`).

The source-keyed clone caps (`max_per_ip` / `max_per_host` / `max_per_account`) are enforced at registration, so they see the real post-PROXY source IP, account, and host (WebSocket- and proxy-safe). Authenticated accounts receive a **+2 bonus** above the configured value on those dimensions; operators holding the `limit_exempt` privilege bypass every per-class cap.

| Key | Type | Default | What it controls |
|---|---|---:|---|
| `match` | string array | `[]` | Source IP/CIDR list to match (IPv4 + IPv6). |
| `match_tls` | bool | `false` | Match only implicit-TLS connections. |
| `match_account` | bool | `false` | Match only SASL-authenticated connections. |
| `match_oper` | bool | `false` | Match only connections that have opered up. |
| `match_ident` | string (glob) | unset | Glob on the connection's ident/username. |
| `match_host` | string (glob) | unset | Glob on the connection's hostname. |
| `sendq` | size | `1M` (`8M` server) | Outbound SendQ ceiling in bytes. |
| `recvq` | size | `0` (inherit) | Inbound line ceiling in bytes; `0` = physical line buffer. |
| `max_clients` | integer | `0` | Max members of this class; `0` = unlimited. |
| `max_per_ip` | integer | `0` | Max concurrent connections per IP in this class; `0` = unlimited. Skipped for loopback / trusted-proxy sources (WebSocket-safe). |
| `max_per_account` | integer | `0` | Max concurrent connections per account in this class; `0` = unlimited. Always proxy/WebSocket-safe (per-identity). |
| `max_per_host` | integer | `0` | Max concurrent connections per resolved host in this class; `0` = unlimited. Skipped for the loopback host. |
| `max_channels` | integer | `0` | Max channels a member may join; `0` = inherit `chanlimit`. |
| `max_targets` | integer | `0` | Max PRIVMSG/NOTICE targets; `0` = inherit `maxtargets`. |
| `monitor` | integer | `0` | Max MONITOR entries; `0` = inherit `monitorlimit`. |
| `silence` | integer | `0` | Max SILENCE masks; `0` = inherit `silencelimit`. |
| `ping_interval` | duration | `0` (inherit) | Per-class PING interval override. |
| `ping_timeout` | duration | `0` (inherit) | Per-class PING-timeout grace override. |
| `register_timeout` | duration | `0` (inherit) | Per-class registration-handshake timeout override. |
| `flood_lines` | integer | `0` | Per-class command-rate budget driving the runtime flood guard (`src/daemon/flood_guard.zig`): keep-alives are free, PRIVMSG/NOTICE/JOIN are weighted, sustained over-budget traffic accrues excess toward an Excess Flood disconnect. `0` = no flood limit. |
| `flood_window` | duration | `0` (`10s` when only `flood_lines` set) | Window for `flood_lines`. |
| `flood_excess` | integer | `0` (auto) | Excess strikes tolerated before disconnect; `0` = auto (`max(20, 2×flood_lines)`). Each over-budget command adds a strike; strikes decay ~1/s. |
| `flood_targets` | integer | `0` (auto) | Distinct PRIVMSG targets a client may spray per `flood_window` before the spread-spam throttle bites; `0` = auto (`max(8, flood_lines)`). |
| `require_tls` | bool | `false` | Refuse admission unless the connection is TLS. |
| `require_sasl` | bool | `false` | Refuse admission unless SASL-authenticated. |
| `flood_exempt` | bool | `false` | Exempt this class from flood/throttle enforcement. |
| `nick_delay_exempt` | bool | `false` | Let members take a held nick without waiting out nick delay. |

## `[io]`

Source: struct at `src/daemon/config_format.zig:153`, parsing at `src/daemon/config_format.zig:377`, mapping at `src/daemon/config_boot.zig:55`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `ring_entries` | integer | `32` | `8..4096` | io_uring SQ entries per reactor (`src/daemon/server.zig:981`). |

## `[reputation]`

Source: struct at `src/daemon/config_format.zig:158`, parsing at `src/daemon/config_format.zig:380`, mapping at `src/daemon/config_boot.zig:56`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `registration_timeout_penalty` | float | `50.0` | `0..1000` | Reputation penalty for unfinished registration (`src/daemon/server.zig:1020`). |
| `clone_refuse_penalty` | float | `25.0` | `0..1000` | Reputation penalty for clone-limit refusal (`src/daemon/server.zig:1022`). |

## `[sessions]`

Source: struct at `src/daemon/config_format.zig:164`, parsing at `src/daemon/config_format.zig:384`, mapping at `src/daemon/config_boot.zig:58`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `max_accounts` | integer | `65536` | `1..4294967295` | Multi-session/bouncer account registry size (`src/daemon/server.zig:1024`). |
| `max_per_account` | integer | `64` | `1..1000000` | Max live sessions per account (`src/daemon/server.zig:1024`). |

## `[media]`

Source: struct at `src/daemon/config_format.zig:245`, parsing at `src/daemon/config_format.zig:553`, mapping at `src/daemon/config_boot.zig:59`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables or disables the media feature surface through `server.Config.media_enabled` and `disabled_features` (`src/daemon/config_format.zig:389`, `src/daemon/config_boot.zig:30`). |
| `max_upload_bytes` | integer | `16777216` | `0..1073741824` | Runtime upload cap applied to both media planes through `server.Config.media_max_upload_bytes` (`src/daemon/config_boot.zig:61`, `src/daemon/server.zig:2399`, `src/daemon/server.zig:2401`). |
| `max_frame_bytes` | integer | `65536` | `0..16777216` | Runtime frame cap applied to SFU/native media with each transport's protocol maximum as an upper bound (`src/daemon/config_boot.zig:62`, `src/daemon/server.zig:2397`, `src/daemon/server.zig:2400`). |
| `max_participants` | integer | `64` | `1..256` | Max participants per SFU room (`Room`), enforced at join. The inline roster ceiling is 256; the native (OPVOX/OPVIS) call leg caps at 64. Default 64 preserves prior behavior (`src/daemon/media_room.zig`, `src/daemon/config_boot.zig`). |
| `reorder_window_frames` | integer | `64` | `1..64` | Kagura media reorder/reassembly window in frames, clamped to the comptime `window_cap` (64). Default 64 (`src/substrate/kagura_frame.zig`, `src/daemon/server.zig` `mediaReassemblyConfig`). |
| `native_media_require_mac` | bool | `false` | `true` or `false` | Require an authenticated per-datagram MAC on native (OPVOX/OPVIS) media. `false` accepts untagged datagrams (back-compat); `true` drops untagged/bad-tag datagrams before the SFU learns the sender. HMAC-SHA256-128 keyed from the per-stream PRF capability; needs matching client support (`src/daemon/config_format.zig:257`, `src/daemon/config_boot.zig:66`, `src/substrate/kagura_frame.zig`). |
| `ws_media_relay` | bool | `false` | `true` or `false` | Relay browser media datagrams (binary WebSocket frames) between a channel's call participants (SFU). Off by default; opt-in. When on, `MEDIA JOIN` hands each participant a per-stream MAC key over the authenticated WS (`NOTE MEDIA <#chan> MACKEY <base64>`) and each datagram is lenient-verified before fan-out to same-node call members (`src/daemon/config_format.zig`, `src/daemon/server.zig` `handleWsMediaDatagram`, `src/substrate/kagura_frame.zig`). |
| `ws_media_require_mac` | bool | `false` | `true` or `false` | Require a valid per-stream MAC tag on every browser media datagram. `false` relays untagged datagrams (a present tag must still verify); `true` drops untagged/bad-tag datagrams. Same `native_stream_key`-derived `(channel, participant)` key as the native leg. |
| `stun_host` | string or null | unset | any string | Optional STUN host mapped to media discovery config (`src/daemon/config_boot.zig:30`, `src/daemon/server.zig:967`). |
| `stun_port` | port integer | `0` | `0..65535` | STUN port mapped when non-zero (`src/daemon/config_boot.zig:31`). |

## `[stats]`

Source: struct at `src/daemon/config_format.zig:180`, parsing at `src/daemon/config_format.zig:394`, mapping at `src/daemon/config_boot.zig:32`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `dir` | string | `""` | any string | Directory for `stats.json` and `index.html`; empty disables (`src/daemon/server.zig:958`). |
| `interval` | duration string | `"30s"` | positive `ms/s/m/h` duration | Minimum interval between stats writes (`src/daemon/config_format.zig:395`). |

## `[metrics]`

Source: struct at `src/daemon/config_format.zig:263`, parsing at `src/daemon/config_format.zig:562`, mapping at `src/daemon/config_boot.zig:67`, live HTTP endpoint at `src/daemon/metrics_http.zig:1`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `listen` | port integer | `0` | `0..65535` | Live Prometheus `/metrics` HTTP listener port. `0` or absent disables the endpoint (`src/daemon/config_boot.zig:69`, `src/daemon/server.zig:2443`). |
| `bind` | string | `"127.0.0.1"` | IPv4 literal | Bind address for the metrics listener. Defaults to loopback; invalid/non-IPv4 values keep the secure loopback default (`src/daemon/config_boot.zig:71`, `src/daemon/config_boot.zig:112`). |

## `[geoip]`

Source: struct at `src/daemon/config_format.zig:188`, parsing at `src/daemon/config_format.zig:397`, mapping at `src/daemon/config_boot.zig:34`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `database` | string | `""` | any string | MaxMind `.mmdb` path; empty disables GeoIP (`src/daemon/server.zig:955`). |
| `asn_database` | string | `""` | any string | Optional separate ASN `.mmdb` path for WHOIS AS-number/org enrichment (`src/daemon/config_format.zig:277`, `src/daemon/config_boot.zig:74`). |

## `[sasl]`

Source: struct at `src/daemon/config_format.zig:193`, parsing at `src/daemon/config_format.zig:400`, account-store boot at `src/main.zig:160`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Explicit `false` disables SASL even when `account_db` is configured. If omitted, older `account_db`-only configs still enable the account store (`src/daemon/config_format.zig:282`, `src/daemon/config_boot.zig:102`, `src/main.zig:255`). |
| `realm` | string or null | unset | any string | Informational SASL/account realm stored in runtime config; current wire mechanisms do not emit it in challenges (`src/daemon/config_format.zig:288`, `src/daemon/config_boot.zig:103`, `src/daemon/server.zig:1387`). |
| `account_db` | string or null | unset | path string | Opens the OroStore account backend; when opened, PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, and EXTERNAL are wired. With the store open, SESSION-TOKEN (opaque reconnect tokens, issued only over TLS) is available, and SCRAM-SHA-512-PLUS is offered to TLS clients via the RFC 9266 `tls-exporter` channel binding (`src/main.zig:178`, `src/main.zig:193`). |
| `allow_anonymous` | bool | `false` | `true` or `false` | Allow SASL ANONYMOUS (RFC 4505) guest logins. Default off (spam vector). A guest binds no account, is left `+r`-unset, and receives no oper/services privileges (`src/daemon/config_format.zig:297`). |
| `oauth_hmac_key` / `oauth_jwks_file` / `oauth_pubkey` | string or null | unset | secret / path | OAUTHBEARER (RFC 7628) JWT verification key. Exactly one source enables OAUTHBEARER: an HS256 shared secret, an RS256/ES256 JWKS file, or an RS256/ES256 PEM/DER public key. Unset = OAUTHBEARER is not advertised (`src/daemon/oauth_jwt.zig`, `src/daemon/config_format.zig:306`). |
| `oauth_issuer` / `oauth_audience` / `oauth_account_claim` | string or null | unset / `"sub"` | any string | When set, `iss`/`aud` are required to match; `oauth_account_claim` selects the JWT claim mapped to the account (default `sub`). OAuth identities are federated and are never auto-elevated to oper (`src/daemon/config_format.zig:302`). |

## `[acme]`

Source: struct `Acme` at `src/daemon/config_format.zig:351`, parsing at `src/daemon/config_format.zig:625`, scheduler at `src/daemon/acme_renewal.zig`, reactor-0 hot-swap at `src/daemon/server.zig` (`maybeReloadAcmeTls`).

Automatic in-daemon TLS certificate renewal (Linux only). A background thread checks the `[tls].cert_path` leaf expiry every `check_interval`; within `renew_before_days` of `notAfter` it issues a new certificate off the reactor and signals reactor 0 to hot-swap it without a restart. This requires `[tls]` with `cert_path` and `key_path`. Changing those paths via live REHASH while `[acme]` is enabled is unsupported.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enable in-daemon ACME renewal. |
| `directory_url` | string | Let's Encrypt prod | any URL | ACME directory endpoint. |
| `domain` | string or null | unset | hostname | Certificate domain to renew. |
| `contact` | string or null | unset | `mailto:…` | ACME account contact. |
| `renew_before_days` | integer | `30` | `1..89` | Renew when the leaf is within N days of `notAfter`. |
| `check_interval` | duration string | `"12h"` | positive `ms/s/m/h` duration | How often to check the leaf expiry. |

## `[cloak]`

Source: struct at `src/daemon/config_format.zig:201`, parsing at `src/daemon/config_format.zig:405`, boot wiring at `src/main.zig:200`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `secret` | string or null | unset | any string | Hash-derived stable hostname cloak key. If absent, `main.zig` generates a per-boot key (`src/main.zig:205`, `src/main.zig:210`). |
| `suffix` | string or null | unset | any string | Optional network-identifying suffix for generated cloak hosts (`src/daemon/config_format.zig:299`, `src/daemon/config_boot.zig:40`). |

## `[tls]`

Source: struct at `src/daemon/config_format.zig:208`, parsing at `src/daemon/config_format.zig:408`, TLS boot projection at `src/daemon/config_boot.zig:97`, live listener at `src/main.zig:216`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables the implicit TLS listener when certificate loading/bootstrap succeeds (`src/main.zig:222`). |
| `port` | port integer | `6697` | `0..65535` | TLS listener port; `0` binds ephemerally if TLS is enabled (`src/daemon/server.zig:1499`). |
| `cert_path` | string or null | unset | path string | Leaf certificate path; paired with `key_path` (`src/daemon/config_format.zig:411`). |
| `key_path` | string or null | unset | path string | Private key path; paired with `cert_path` (`src/daemon/config_format.zig:412`). |
| `dns_name` | string | `"localhost"` | any string | CN/SAN for self-signed bootstrap cert when files are absent (`src/main.zig:224`). |
| `request_client_cert` | bool | `false` | `true` or `false` | Requests client certs so SASL EXTERNAL can match cert fingerprints (`src/main.zig:234`, `src/daemon/sasl_bridge.zig:70`). |
| `enable_tls12` | bool | `false` | `true` or `false` | Also accept hardened TLS 1.2 ECDHE-AEAD clients through version dispatch. Off by default (`src/daemon/config_format.zig:324`, `src/daemon/config_boot.zig:174`, `src/main.zig:347`). |
| `enable_resumption` | bool | `false` | `true` or `false` | Enable TLS 1.3 PSK session tickets/resumption on the live TLS listener (`src/daemon/config_format.zig:330`, `src/daemon/config_boot.zig:175`). |
| `early_data_max_size` | integer | `0` | `0..4294967295` | Maximum TLS 1.3 0-RTT bytes advertised in issued tickets. `0` disables early data while still allowing resumption (`src/daemon/config_format.zig:334`, `src/daemon/config_boot.zig:176`). |

Orochi has no STARTTLS path. TLS is a separate implicit-TLS listener (`src/main.zig:216`, `src/daemon/dispatch.zig:369`).

## `[sts]`

Source: struct at `src/daemon/config_format.zig:229`, parsing at `src/daemon/config_format.zig:416`, STS boot projection at `src/daemon/config_boot.zig:68`, live advertisement at `src/main.zig:242`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Enables IRCv3 STS advertisement only if a TLS listener is live (`src/main.zig:247`, `src/main.zig:248`). |
| `duration` | integer | `2592000` | `0..4294967295` | STS max-age in seconds (`src/main.zig:249`). |
| `port` | port integer | `6697` | `0..65535` | Secure port advertised in the STS policy (`src/main.zig:251`). |
| `preload` | bool | `false` | `true` or `false` | Adds `preload` to the STS value (`src/main.zig:252`). |

STS is omitted entirely unless a policy is present; this prevents clients from being stranded by a nonexistent TLS listener (`src/daemon/dispatch.zig:369`).

## `[oper]`

Operator subsystem settings, distinct from the per-operator `[[opers]]` bindings
below. Source: struct `OperSection` at `src/daemon/config_format.zig`, mapping at
`src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `grants_path` | string or null | unset | path | File for persisting runtime `GRANT`/`REVOKE` operator grants. When set, active grants are written here on change and reloaded at boot, so runtime-granted opers survive a restart; revoked accounts are dropped. See [commands/oper-moderation.md](commands/oper-moderation.md#grant). |
| `auto_override` | bool | `false` | — | Auto-enable the `+j` override umode on elevation for any operator holding the `oper_override` privilege, so admins get full channel authority (KICK/MODE/TOPIC/PROP/…) without a manual `/mode +j`. `false` keeps override an explicit, audited opt-in (`src/daemon/server.zig` `applyOperAutoOverride`). |

## `[wasm]`

OroWasm plugin module system. Source: struct `Wasm` at `src/daemon/config_format.zig`, mapping at `src/daemon/config_boot.zig`, loaded by `src/daemon/server.zig` `loadWasmPlugins` (boot and REHASH), dispatched via `src/wasm/host/bridge.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `plugin_dir` | string or null | unset (dormant) | directory path | Directory scanned at boot and on REHASH for `*.wasm` control-plane plugins. Each registers IRC commands consulted **after** the built-in registry — a plugin can extend, never shadow, a core command. Plugins run sandboxed with only their negotiated host capabilities (reply/log/time). Missing dir / malformed plugin is logged, never fatal. |

## `[[opers]]`

Source: struct at `src/daemon/config_format.zig:101`, parsing at `src/daemon/config_format.zig:422`, SASL-only runtime behavior at `src/daemon/server.zig:8300`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `account` | string | required per table | non-empty; registry validation max 128 bytes | SASL account name that becomes oper after successful SASL login (`src/daemon/config_format.zig:433`, `src/daemon/oper.zig:11`). |
| `class` | string | `""` | registry validation max 64 bytes | Operator privilege group name. It must name a non-empty configured group with effective privileges; otherwise the oper binding is skipped (`src/daemon/config_boot.zig:183`). |
| `title` | string | `""` | any string | Optional WHOIS/operator title (`src/daemon/config_format.zig:441`, `src/daemon/oper.zig:139`). |

There is no oper password. `OPER` is disabled and directs users to authenticate through SASL (`src/daemon/server.zig:8300`). Operator status is granted after SASL when the account matches a configured binding (`src/daemon/server.zig:8308`).

## `[[oper_groups]]`

Source: struct at `src/daemon/config_format.zig:95`, parsing at `src/daemon/config_format.zig:450`, group registry at `src/daemon/operator_groups.zig:1`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `name` | string | required per table | non-empty | Group name referenced by `[[opers]].class` (`src/daemon/config_format.zig:462`). |
| `privileges` | array of strings | `[]` | exact `oper.Privilege` enum names | Privilege flags included in the group. Unknown names are ignored by boot conversion (`src/daemon/config_boot.zig:159`). |
| `inherits` | string | `""` | group name | Optional parent group; effective privileges union parent links up to depth 32 (`src/daemon/operator_groups.zig:11`, `src/daemon/operator_groups.zig:88`). |

Valid privilege strings are the exact enum names from `src/daemon/oper.zig:36`: `server_rehash`, `server_restart`, `server_shutdown`, `client_moderate`, `channel_moderate`, `client_kill`, `mesh_admin`, `service_admin`, `server_admin`, `oper_grant`, `oper_spy`, `event_subscribe`, `audit_read`, and `oper_override`.

Note one current behavior: if an oper names a class that has no group, or that resolves to an empty effective privilege set, boot skips that oper binding (`src/daemon/config_boot.zig:250`, `src/daemon/config_boot.zig:255`). REHASH rebuilds configured operator bindings through the same group resolver and has coverage for preserving group privileges (`src/daemon/server.zig:20008`, `src/daemon/server.zig:20546`).

## Parsed but not yet wired

No top-level key in this reference is currently known to be parser-only in the
`main.zig` / `config_boot.zig` / `server.zig` path as of `c471a06`. When a future
key is accepted before it changes live behavior, add it here in the same change.

## Comptime-bound values not yet configurable

| Value | Bound | Source |
|---|---:|---|
| Maximum daemon shards | `4096` | `src/daemon/shard.zig:23` |
| Operator account name length | `128` bytes | `src/daemon/oper.zig:11` |
| Operator class name length | `64` bytes | `src/daemon/oper.zig:11` |
| Operator group inheritance depth | `32` links | `src/daemon/operator_groups.zig:11` |
| IRCv3 multiline max bytes/lines/ref/target | `4096`, `24`, `64`, `128` | `src/daemon/server.zig:1096` |
| OroStore default max record bytes | `16 MiB` | `src/daemon/store.zig:11` |
| OroStore default max WAL bytes | `256 MiB` | `src/daemon/store.zig:12` |
| OroStore default changefeed capacity | `64` | `src/daemon/store.zig:13` |

OroStore has its own internal `Config.applyToml` helper for `[storage]`, but `[storage]` is not part of the current daemon `config_format.Config` sections covered here (`src/daemon/store.zig:26`, `src/daemon/store.zig:37`).
