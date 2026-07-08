# Orochi services and daemon-state config sweep

This read-only inventory maps services and daemon-state constants to proposed TOML controls.

Scope: hardcoded operational/tuning constants in the services and daemon-state
area. Files surveyed: services.zig, sessions.zig, oper.zig, store.zig,
sasl_bridge.zig, announce_board.zig, announcement_mode.zig, focus_mode.zig,
tegami.zig, content_filter.zig (Koshi), duplicate_filter.zig.

Excludes per brief: server.zig, dispatch.zig, client.zig, acme_*.zig, config*.zig.
Also excluded: crypto domain constants (hash/salt/token byte lengths mandated by an
algorithm), enum discriminants, fixed wire/record-format constants, and test values.

Note: substrate/wal.zig (the CRDT delta WAL) holds only magic/version/header-length
wire constants and is not included; the operational store tunables live in store.zig.

---

## [accounts]

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|-----------|------------------|---------------|------------------|-------------------|------|---------|----------|
| config_format.zig / services.zig | `accounts.pbkdf2_rounds` / `default_pbkdf2_rounds` | `100_000` | PBKDF2-HMAC-SHA256 iteration count for account password hashing (tunable policy — explicitly in scope) | `accounts.pbkdf2_rounds` *(schema-backed)* | uint | 100000 | 10000..10000000 |
| services.zig:488 | `validatePassword` min | `8` | minimum account password length | `accounts.password_min_len` | uint | 8 | 1..64 |
| services.zig:488 | `validatePassword` max | `512` | maximum account password length | `accounts.password_max_len` | uint | 512 | 64..4096 |
| services.zig:8 | `account_max` | `32` | max account name length | `accounts.name_max_len` | uint | 32 | 8..128 |
| services.zig:11 | `email_max` | `96` | max stored account email length | `accounts.email_max_len` | uint | 96 | 32..256 |
| services.zig:9 | `channel_max` | `64` | max registered channel name length | `accounts.channel_name_max_len` | uint | 64 | 8..128 |
| services.zig:10 | `nick_max` | `64` | max nick length (GHOST target) | `accounts.nick_max_len` | uint | 64 | 8..128 |
| services.zig:12 | `mask_max` | `160` | max akick mask length | `accounts.akick_mask_max_len` | uint | 160 | 32..512 |
| services.zig:13 | `reason_max` | `128` | max akick/reason text length | `accounts.reason_max_len` | uint | 128 | 16..512 |
| services.zig:14 | `key_max` | `256` | scratch key-buffer cap for access/akick store keys | `accounts.store_key_max_len` | uint | 256 | 64..1024 |
| services.zig:15 | `record_max` | `768` | scratch buffer size for an encoded account/channel record | `accounts.record_max_len` | uint | 768 | 256..4096 |
| sasl_bridge.zig:13 | `Params.max_account_len` | `128` | max SASL-verified account name length for oper elevation lookup | `accounts.sasl_account_max_len` | uint | 128 | 32..256 |
| sasl_bridge.zig:14 | `Params.max_class_len` | `64` | max oper class-name length | `accounts.oper_class_max_len` | uint | 64 | 8..128 |

## [sessions]

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|-----------|------------------|---------------|------------------|-------------------|------|---------|----------|
| sessions.zig:20 | `Config.max_accounts` | `65536` | max distinct accounts tracked in the live session registry | `sessions.max_accounts` | uint | 65536 | 1024..1048576 |
| sessions.zig:21 | `Config.max_sessions_per_account` | `64` | max concurrent live+ghost sessions per account (multi-device cap) | `sessions.max_per_account` | uint | 64 | 1..256 |

## [bouncer]

Tegami offline-mail and announcement board fan-out are the per-account buffer/retention surfaces in this scope.

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|-----------|------------------|---------------|------------------|-------------------|------|---------|----------|
| config_format.zig / tegami.zig | `bouncer.tegami_text_max_len` / `max_text_bytes` | `400` | max offline DM body length | `bouncer.tegami_text_max_len` *(schema-backed)* | uint | 400 | 64..2048 |
| config_format.zig / tegami.zig | `bouncer.tegami_from_max_len` / `max_from_bytes` | `64` | max sender-name length on an offline DM | `bouncer.tegami_from_max_len` *(schema-backed)* | uint | 64 | 16..128 |
| config_format.zig / tegami.zig | `bouncer.tegami_mailbox_depth` / `max_per_account` | `64` | offline mailbox depth cap per account (buffer cap) | `bouncer.tegami_mailbox_depth` *(schema-backed)* | uint | 64 | 8..1024 |
| config_format.zig / tegami.zig | `bouncer.tegami_max_accounts` / `max_accounts` | `65536` | max distinct offline mailboxes | `bouncer.tegami_max_accounts` *(schema-backed)* | uint | 65536 | 1024..1048576 |
| announce_board.zig:13 | `max_announcements` | `512` | retained announcement board cap (FIFO eviction) | `bouncer.announce_max_entries` | uint | 512 | 32..8192 |
| announce_board.zig:14 | `max_category_len` | `32` | max announcement category tag length | `bouncer.announce_category_max_len` | uint | 32 | 8..128 |
| announce_board.zig:15 | `max_title_len` | `120` | max announcement headline length | `bouncer.announce_title_max_len` | uint | 120 | 16..256 |
| announce_board.zig:16 | `max_body_len` | `1000` | max announcement body length | `bouncer.announce_body_max_len` | uint | 1000 | 128..8192 |

## [storage]

OroStore append-only log, snapshot, and changefeed.

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|-----------|------------------|---------------|------------------|-------------------|------|---------|----------|
| store.zig:10 | `max_record_len` | `16 * 1024 * 1024` (16 MiB) | max single WAL/snapshot record payload size | `storage.max_record_bytes` | uint | 16777216 | 65536..268435456 |
| store.zig:11 | `max_wal_len` | `256 * 1024 * 1024` (256 MiB) | max WAL file size accepted on replay (rejects oversize log) | `storage.max_wal_bytes` | uint | 268435456 | 1048576..4294967296 |
| store.zig:98 | `ChangeFeed.init(allocator, 64)` | `64` | bounded recent-mutation changefeed ring size (service-sync feed) | `storage.changefeed_capacity` | uint | 64 | 8..4096 |

## [filter]

Koshi content filter and duplicate suppression. announcement_mode and focus_mode are
per-channel/per-account posting gates, grouped here as moderation limits.

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|-----------|------------------|---------------|------------------|-------------------|------|---------|----------|
| config_format.zig / content_filter.zig | `filter.koshi_max_patterns` / `max_patterns` | `256` | max oper-curated Koshi filter patterns (Aho-Corasick set) | `filter.koshi_max_patterns` *(schema-backed)* | uint | 256 | 16..4096 |
| config_format.zig / content_filter.zig | `filter.koshi_pattern_max_len` / `max_pattern_len` | `256` | max length of a single Koshi filter pattern | `filter.koshi_pattern_max_len` *(schema-backed)* | uint | 256 | 16..1024 |
| duplicate_filter.zig:4 | `DuplicateFilter.max_entries` | `4096` | dedup FIFO window size (recent message-hash memory) | `filter.dedup_window` | uint | 4096 | 256..65536 |
| announcement_mode.zig:7 | `max_channels` | `4096` | max channels with announcement-only mode state | `filter.announce_mode_max_channels` | uint | 4096 | 256..65536 |
| announcement_mode.zig:8 | `max_channel_bytes` | `128` | max channel-name length for announcement-mode gate | `filter.announce_mode_channel_max_len` | uint | 128 | 8..256 |
| announcement_mode.zig:9 | `max_account_bytes` | `128` | max account-name length on the announcement allowlist | `filter.announce_mode_account_max_len` | uint | 128 | 8..256 |
| announcement_mode.zig:10 | `max_accounts_per_channel` | `1024` | max allowlisted posters per announcement-only channel | `filter.announce_mode_allowlist_max` | uint | 1024 | 16..16384 |

## Borderline notes

| file:line | symbol / context | current value | note |
|-----------|------------------|---------------|------|
| services.zig:16-21 | `salt_len`/`hash_len`/`generation_len` | 16 / 32 / 16 | borderline — `generation_len` (16) is a non-crypto channel-generation nonce length and could be lifted; `salt_len`(16)/`hash_len`(32) are PBKDF2/HMAC-SHA256 domain sizes — EXCLUDED as crypto-mandated. |
| services.zig:30-33 | `missing_account_salt` | fixed 16-byte literal | borderline — a fixed timing-equalization salt for the identify-on-missing-account path; security-relevant constant, not really a tuning knob. Leave hardcoded. |
| services.zig:106-114 | `AccessLevel` enum values | 10/25/50/100 | EXCLUDED — these are ordered privilege-tier discriminants (semantic enum), not a tuning knob. |
| store.zig:8,9,12,13,14 | record/payload header lens, tombstone sentinel, meta-kind byte | fixed | EXCLUDED — on-disk wire/record-format constants. |
| focus_mode.zig | (no caps) | — | FocusMode is unbounded (no per-account allowlist cap). Borderline: a `filter.focus_allowlist_max` cap could be added later, but no literal exists today to lift. |
| oper.zig | (no operational literals) | — | oper.zig (OperPrivileges/OperRegistry) is pure compile-time policy with no tunable runtime literals. |
