# Orochi Configuration Reference

This is the complete operator-facing reference for the current daemon TOML format. It is verified against `Config` and `parseToml` in `src/daemon/config_format.zig:29`, `src/daemon/config_format.zig:310`, and the live boot projection in `src/daemon/config_boot.zig:18`.

Orochi is a pure-Zig 0.16 clean-room IRC daemon and a bespoke successor to C Ophion, not a clone. The daemon target is 64-bit only (`build.zig:20`, `build.zig:24`), uses implicit TLS rather than STARTTLS (`src/main.zig:216`, `src/main.zig:219`), and uses Zig-native OroStore persistence rather than LMDB (`src/daemon/store.zig:1`, `src/daemon/store.zig:3`).

Use `etc/orochi.reference.toml` as the runnable example and copy from it when building an instance config. The two required parsed keys are `[node].id >= 1` and `[listen].irc != 0`; missing either makes `parseToml` fail (`src/daemon/config_format.zig:478`).

## Format Rules

The config file is TOML v1.0 (`src/daemon/config_format.zig:3`). Missing keys keep typed defaults (`src/daemon/config_format.zig:4`, `src/daemon/config_format.zig:9`). Integer fields use the ranges in `parseToml`; out-of-range values return `ParseError` (`src/daemon/config_format.zig:542`). Durations are quoted strings using `ms`, `s`, `m`, or `h`, must be non-zero, and are converted to milliseconds (`src/daemon/config_format.zig:556`).

The config parser supports string indirection for any string value: `env:NAME` and `@file:path` (`src/daemon/config_format.zig:486`). Current `src/main.zig` wires only the environment resolver in the CLI boot path (`src/main.zig:100`), so `@file:` is parser-supported but requires a caller or boot path that provides a file resolver (`src/daemon/config_format.zig:495`).

The live mapping is conservative: only non-empty or non-zero values are overlaid onto `server.Config` (`src/daemon/config_boot.zig:15`). TLS and STS are projected separately because `server.Config` does not own those parser structs (`src/daemon/config_boot.zig:92`, `src/daemon/config_boot.zig:119`).

## Required Keys

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

## `[motd]`

Source: struct at `src/daemon/config_format.zig:62`, parsing at `src/daemon/config_format.zig:329`, mapping at `src/daemon/config_boot.zig:21`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `text` | string or null | unset | any string | MOTD body served by `MOTD`; newlines are split into MOTD lines. Supports `@file:` at parser level. |

The MOTD is a **per-connection template** expanded by `src/proto/motd_template.zig`
before being split into lines. When omitted or empty, the server serves a
personalized built-in default.

Substitutions (`{key}`; unknown keys left verbatim; `{{`/`}}` emit literal braces):
`{nick}` `{account}` `{host}` `{network}` `{server}` `{version}` `{time}` `{date}`
`{users}` `{opers}` `{channels}`, plus `{greeting}` (a time-of-day greeting) and
`{weather}` / `{news}` (see `[weather]` / `[news]`).

Conditionals: `{if:COND}…{else}…{/if}` where `COND` is `oper`, `account`, `secure`,
`weather`, or `news` (the last two true when that line is available); conditionals
nest. Example: `{if:account}Welcome back, {account}!{else}Please register.{/if}`

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
[commands/fantasy-bot.md](commands/fantasy-bot.md)). When enabled the daemon
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
| `webtransport` | port integer | `0` | `0..65535` | Parser/proto-only: parsed by config format, but `mapToServerConfig` does not overlay it and no listener binds from it yet (`src/daemon/config_format.zig:464`, `src/daemon/config_boot.zig:42`). |
| `s2s` | port integer | `0` | `0..65535` | Server-to-server mesh listener; `0` disables it (`src/daemon/config_boot.zig:26`, `src/daemon/server.zig:1046`). |
| `media` | port integer | `0` | `0..65535` | UDP media transport plane port; `0` means ephemeral (`src/daemon/config_boot.zig:27`, `src/daemon/server.zig:963`). |
| `native_media` | port integer | `0` | `0..65535` | Native OPVOX/OPVIS media UDP port; `0` means ephemeral (`src/daemon/config_boot.zig:28`, `src/daemon/server.zig:971`). |
| `media_host` | string | `"127.0.0.1"` | any string | Advertised media candidate host/IP (`src/daemon/config_boot.zig:29`, `src/daemon/server.zig:965`). |

## `[mesh]`

Source: struct at `src/daemon/config_format.zig:109`, parsing at `src/daemon/config_format.zig:346`, secured S2S wiring at `src/main.zig:141`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `realm` | string | `"local"` | any string | Realm fed into node identity derivation for secured S2S (`src/main.zig:149`). |
| `trust_roots` | array of strings | `[]` | strings | Parsed and tested, but not consumed by current boot mapping (`src/daemon/config_format.zig:349`, `src/daemon/config_format.zig:637`). |
| `mesh_pass` | string or null | unset | any string | Shared passphrase carried into S2S handshake config when node identity is configured (`src/main.zig:152`, `src/daemon/server.zig:1074`). |

Plaintext S2S is used when no node identity is configured; secured S2S is enabled by `[node].secret_key` (`src/main.zig:141`, `src/main.zig:153`).

## `[limits]`

Source: struct at `src/daemon/config_format.zig:115`, parsing at `src/daemon/config_format.zig:354`, mapping at `src/daemon/config_boot.zig:35`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `backlog` | integer | `128` | `1..32767` | Listener backlog (`src/daemon/config_boot.zig:35`). |
| `max_clients` | integer | `1024` | `1..32767` | Reserved connection table size and accept cap (`src/daemon/server.zig:983`). |
| `num_shards` | integer | `1` | `1..4096` | Requested worker reactor shards (`src/daemon/config_boot.zig:234`). `main.zig` passes the configured value through; if it is left at `1`, boot chooses a CPU-based default capped at 4. `Server.init` allocates the reactor array from the shard count, and `runThreaded` starts one worker per reactor when more than one reactor exists (`src/main.zig:154`, `src/main.zig:399`, `src/daemon/server.zig:1802`, `src/daemon/server.zig:2795`). |
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
| `monitorlimit` | integer | `128` | `1..100000` | MONITOR target limit (`src/daemon/server.zig:945`). |
| `silencelimit` | integer | `32` | `1..256` | SILENCE mask limit (`src/daemon/server.zig:948`). |
| `max_clones_per_ip` | integer | `0` | `0..65535` | Exact-IP clone cap; `0` disables (`src/daemon/server.zig:1005`). |
| `max_clones_per_net` | integer | `0` | `0..65535` | Network-prefix clone cap; `0` disables (`src/daemon/server.zig:1009`). |
| `reputation_refuse_threshold` | integer | `0` | `0..1000000` | Refuse connects at or above decaying reputation score; `0` disables (`src/daemon/server.zig:1012`). |
| `reputation_half_life` | duration string | `"1m"` | positive `ms/s/m/h` duration | IP reputation score decay half-life (`src/daemon/config_boot.zig:53`). |
| `sweep_interval` | duration string | `"2s"` | positive `ms/s/m/h` duration | Timeout sweep timer granularity (`src/daemon/config_boot.zig:54`). |

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

Source: struct at `src/daemon/config_format.zig:170`, parsing at `src/daemon/config_format.zig:388`, partial mapping at `src/daemon/config_boot.zig:30`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Parsed but not yet wired into `server.Config` (`src/daemon/config_format.zig:389`, `src/daemon/config_boot.zig:30`). |
| `max_upload_bytes` | integer | `16777216` | `0..1073741824` | Parsed but not yet wired into current daemon boot (`src/daemon/config_format.zig:390`). |
| `max_frame_bytes` | integer | `65536` | `0..16777216` | Parsed but not yet wired into current daemon boot (`src/daemon/config_format.zig:391`). |
| `stun_host` | string or null | unset | any string | Optional STUN host mapped to media discovery config (`src/daemon/config_boot.zig:30`, `src/daemon/server.zig:967`). |
| `stun_port` | port integer | `0` | `0..65535` | STUN port mapped when non-zero (`src/daemon/config_boot.zig:31`). |

## `[stats]`

Source: struct at `src/daemon/config_format.zig:180`, parsing at `src/daemon/config_format.zig:394`, mapping at `src/daemon/config_boot.zig:32`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `dir` | string | `""` | any string | Directory for `stats.json` and `index.html`; empty disables (`src/daemon/server.zig:958`). |
| `interval` | duration string | `"30s"` | positive `ms/s/m/h` duration | Minimum interval between stats writes (`src/daemon/config_format.zig:395`). |

## `[geoip]`

Source: struct at `src/daemon/config_format.zig:188`, parsing at `src/daemon/config_format.zig:397`, mapping at `src/daemon/config_boot.zig:34`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `database` | string | `""` | any string | MaxMind `.mmdb` path; empty disables GeoIP (`src/daemon/server.zig:955`). |

## `[sasl]`

Source: struct at `src/daemon/config_format.zig:193`, parsing at `src/daemon/config_format.zig:400`, account-store boot at `src/main.zig:160`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `enabled` | bool | `false` | `true` or `false` | Parsed but not currently used as the runtime gate; `account_db` controls live SASL store wiring (`src/daemon/config_format.zig:401`, `src/main.zig:177`). |
| `realm` | string or null | unset | any string | Parsed but not currently consumed by `main.zig` or `mapToServerConfig` (`src/daemon/config_format.zig:402`). |
| `account_db` | string or null | unset | path string | Opens the OroStore account backend; when opened, PLAIN, SCRAM-SHA-256, and EXTERNAL are wired (`src/main.zig:178`, `src/main.zig:193`). |

## `[cloak]`

Source: struct at `src/daemon/config_format.zig:201`, parsing at `src/daemon/config_format.zig:405`, boot wiring at `src/main.zig:200`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `secret` | string or null | unset | any string | Hash-derived stable hostname cloak key. If absent, `main.zig` generates a per-boot key (`src/main.zig:205`, `src/main.zig:210`). |

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
below. Source: struct at `src/daemon/config_format.zig` (`OperSection`), mapping
at `src/daemon/config_boot.zig`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `grants_path` | string or null | unset | path | File for persisting runtime `GRANT`/`REVOKE` operator grants. When set, active grants are written here on change and reloaded at boot, so runtime-granted opers survive a restart; revoked accounts are dropped. See [commands/oper-moderation.md](commands/oper-moderation.md#grant). |

## `[[opers]]`

Source: struct at `src/daemon/config_format.zig:101`, parsing at `src/daemon/config_format.zig:422`, SASL-only runtime behavior at `src/daemon/server.zig:8300`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `account` | string | required per table | non-empty; registry validation max 128 bytes | SASL account name that becomes oper after successful SASL login (`src/daemon/config_format.zig:433`, `src/daemon/oper.zig:11`). |
| `class` | string | `""` | registry validation max 64 bytes | Operator privilege group name. Empty maps to `"operator"` after boot (`src/daemon/config_boot.zig:183`). |
| `title` | string | `""` | any string | Optional WHOIS/operator title (`src/daemon/config_format.zig:441`, `src/daemon/oper.zig:139`). |

There is no oper password. `OPER` is disabled and tells users to authenticate through SASL (`src/daemon/server.zig:8300`). Operator status is granted after SASL when the account matches a configured binding (`src/daemon/server.zig:8308`).

## `[[oper_groups]]`

Source: struct at `src/daemon/config_format.zig:95`, parsing at `src/daemon/config_format.zig:450`, group registry at `src/daemon/operator_groups.zig:1`.

| Key | Type | Default | Valid range | What it controls |
|---|---|---:|---|---|
| `name` | string | required per table | non-empty | Group name referenced by `[[opers]].class` (`src/daemon/config_format.zig:462`). |
| `privileges` | array of strings | `[]` | exact `oper.Privilege` enum names | Privilege flags included in the group. Unknown names are ignored by boot conversion (`src/daemon/config_boot.zig:159`). |
| `inherits` | string | `""` | group name | Optional parent group; effective privileges union parent links up to depth 32 (`src/daemon/operator_groups.zig:11`, `src/daemon/operator_groups.zig:88`). |

Valid privilege strings are the exact enum names from `src/daemon/oper.zig:36`: `server_rehash`, `server_restart`, `server_shutdown`, `client_moderate`, `channel_moderate`, `client_kill`, `mesh_admin`, `service_admin`, `server_admin`, `oper_grant`, `oper_spy`, `event_subscribe`, `audit_read`, and `oper_override`.

Important current behavior: if an oper names a class that has no group, or resolves to an empty effective privilege set, boot falls back to full privileges (`src/daemon/config_boot.zig:174`, `src/daemon/config_boot.zig:179`). REHASH currently rebuilds oper bindings with full privileges and does not recompute `[[oper_groups]]` (`src/daemon/server.zig:10052`, `src/daemon/server.zig:10062`).

## Parsed But Not Yet Wired

These keys are accepted by `parseToml` but do not currently change live daemon behavior in the `main.zig`/`mapToServerConfig` path:

| Key | Parse source | Current status |
|---|---|---|
| `listen.webtransport` | `src/daemon/config_format.zig:464` | Parser/proto-only: no `mapToServerConfig` overlay and no listener binding from this config yet. |
| `mesh.trust_roots` | `src/daemon/config_format.zig:349` | Parsed and tested; current secured S2S boot uses node secret key, realm, and mesh pass. |
| `media.enabled` | `src/daemon/config_format.zig:389` | Parsed; current mapped media fields are ports, advertised host, and STUN. |
| `media.max_upload_bytes` | `src/daemon/config_format.zig:390` | Parsed; not mapped into current server config. |
| `media.max_frame_bytes` | `src/daemon/config_format.zig:391` | Parsed; not mapped into current server config. |
| `sasl.enabled` | `src/daemon/config_format.zig:401` | Parsed; live SASL backend wiring is currently controlled by `sasl.account_db`. |
| `sasl.realm` | `src/daemon/config_format.zig:402` | Parsed; not consumed in current boot mapping. |

## Comptime-Bound Values Not Yet Configurable

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

OroStore has its own internal `Config.applyToml` helper for `[storage]`, but `[storage]` is not part of the current daemon `config_format.Config` sections requested here (`src/daemon/store.zig:26`, `src/daemon/store.zig:37`).
