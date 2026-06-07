# Mizuchi Mesh (Suimyaku) — Hardcoded Operational/Tuning Constants

Survey of `src/substrate/suimyaku/*.zig` (excluding `media.zig`).
Scope: CRDT mesh, s2s_peer, gossip/plumtree/hyparview dissemination, SWIM membership,
delta journal, anti-entropy, state projection. Read-only.

Excluded: protocol/wire constants, crypto domain constants, enum discriminants, compile-time
type widths, test-only values. Borderline entries are marked.

---

## [mesh.gossip] — HyParView overlay + Plumtree dissemination

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| gossip_views.zig:19 | `Config.active_max` | 8 | HyParView active view size (direct-traffic peers) | mesh.gossip.active_view_max | uint | 8 | 2..64 |
| gossip_views.zig:20 | `Config.passive_max` | 64 | HyParView passive reserve size | mesh.gossip.passive_view_max | uint | 64 | active_view_max+1..4096 |
| gossip_views.zig:22 | `Config.arwl` | 6 | Active random walk length (JOIN forwarding TTL) | mesh.gossip.active_walk_len | uint | 6 | 1..32 |
| gossip_views.zig:24 | `Config.prwl` | 3 | Passive random walk length (point where peers learned) | mesh.gossip.passive_walk_len | uint | 3 | 1..arwl |
| gossip_views.zig:25 | `Config.shuffle_active` | 2 | Active entries sampled into a shuffle | mesh.gossip.shuffle_active_count | uint | 2 | 0..active_view_max |
| gossip_views.zig:26 | `Config.shuffle_passive` | 4 | Passive entries sampled into a shuffle | mesh.gossip.shuffle_passive_count | uint | 4 | 0..passive_view_max |
| gossip_views.zig:16 | `max_shuffle_sample` (borderline) | 64 | Max nodes carried in one shuffle sample buffer | mesh.gossip.shuffle_sample_max | uint | 64 | 8..256 |
| gossip_views.zig:354 | `PlumtreeConfig.graft_retry_ms` | 1000 | Lazy-push GRAFT retry timer for missing messages | mesh.gossip.graft_retry_ms | duration | 1000 | 100..30000 |
| gossip_round.zig:209 | `Config.fanout` | 3 | Gossip round push fanout (peers per round) | mesh.gossip.round_fanout | uint | 3 | 1..64 |
| gossip_round.zig:210 | `Config.max_member_deltas` | 64 | Max membership deltas packed per gossip payload | mesh.gossip.max_member_deltas | uint | 64 | 1..1024 |
| gossip_round.zig:211 | `Config.max_suspicions` | 64 | Max suspicion records per gossip payload | mesh.gossip.max_suspicions | uint | 64 | 1..1024 |
| membership_view.zig:43 | `Config.active_capacity` | 8 | Bounded-view active capacity (allocated once) | mesh.gossip.view_active_capacity | uint | 8 | 2..64 |
| membership_view.zig:45 | `Config.passive_capacity` | 64 | Bounded-view passive capacity | mesh.gossip.view_passive_capacity | uint | 64 | active+1..4096 |
| membership_view.zig:47 | `Config.shuffle_active_count` | 2 | Active entries sampled per shuffle (bounded view) | mesh.gossip.view_shuffle_active | uint | 2 | 0..active_capacity |
| membership_view.zig:49 | `Config.shuffle_passive_count` | 4 | Passive entries sampled per shuffle (bounded view) | mesh.gossip.view_shuffle_passive | uint | 4 | 0..passive_capacity |

## [mesh.swim] — Witnessed SWIM failure detector

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| swim.zig:22 | `Config.period_ms` | 1000 | SWIM probe period (also used as per-ping deadline) | mesh.swim.probe_period_ms | duration | 1000 | 100..60000 |
| swim.zig:23 | `Config.k` | 3 | Number of indirect ping-req witnesses per probe | mesh.swim.indirect_probes | uint | 3 | 1..32 |
| swim.zig:24 | `Config.quorum` | 2 | Witness quorum required to declare a node dead | mesh.swim.witness_quorum | uint | 2 | 2..max_witnesses |
| swim.zig:25 | `Config.suspect_timeout_ms` | 3000 | Suspect→dead promotion timeout | mesh.swim.suspect_timeout_ms | duration | 3000 | 0..120000 |
| swim.zig:12 | `max_witnesses` (borderline) | 32 | Max witnesses tracked/carried per member | mesh.swim.max_witnesses | uint | 32 | 4..128 |
| gossip_round.zig:14 | `SazanamiConfig.suspicion_timeout_ms` | 3000 | Sazanami suspicion→reap timeout (gossip-side SWIM) | mesh.swim.sazanami_suspicion_timeout_ms | duration | 3000 | 0..120000 |
| gossip_round.zig:15 | `SazanamiConfig.witness_quorum` | 2 | Sazanami witness quorum for dead declaration | mesh.swim.sazanami_witness_quorum | uint | 2 | 1..16 |
| gossip_round.zig:11 | `max_tracked_witnesses` (borderline) | 16 | Max witnesses tracked per Sazanami member | mesh.swim.sazanami_max_witnesses | uint | 16 | 4..64 |

## [mesh.antientropy] — Anti-entropy reconciliation / repair planner

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| anti_entropy.zig:85 | `StrategyConfig.delta_replay_limit` | 8 | Max differing keys still repaired by delta replay (vs snapshot) | mesh.antientropy.delta_replay_limit | uint | 8 | 1..1024 |
| anti_entropy.zig:87 | `StrategyConfig.full_resync_threshold` | 1024 | Differing-key count that triggers a full lane snapshot | mesh.antientropy.full_resync_threshold | uint | 1024 | 16..1000000 |
| goryu_sync.zig:18 | `symbols_per_pump` | 24 | RIBLT symbols emitted per sync pump round | mesh.antientropy.symbols_per_pump | uint | 24 | 1..512 |
| goryu_sync.zig:19 | `max_symbols` (borderline) | 512 | Max RIBLT symbols accepted in one sync message | mesh.antientropy.max_symbols | uint | 512 | 32..8192 |
| goryu_sync.zig:20 | `max_requests` (borderline) | 512 | Max repair requests in one sync message | mesh.antientropy.max_requests | uint | 512 | 32..8192 |
| goryu_sync.zig:21 | `max_fills` (borderline) | 512 | Max fill records in one sync message | mesh.antientropy.max_fills | uint | 512 | 32..8192 |
| goryu_sync.zig:22 | `max_scope_len` (borderline) | 4096 | Max op-scope byte length accepted | mesh.antientropy.max_scope_len | uint | 4096 | 256..65536 |

## [mesh.link] — Peer link transport (heartbeat/idle/credit/replay)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| peer_link.zig:101 | `default_send_credit` | 65536 (64*1024) | Initial flow-control send credit (bytes) | mesh.link.send_credit_bytes | uint | 65536 | 4096..16777216 |
| peer_link.zig:102 | `default_replay_window` | 64 | Anti-replay sequence window | mesh.link.replay_window | uint | 64 | 8..4096 |
| peer_link.zig:103 | `default_handshake_timeout_ms` | 10000 | Handshake completion timeout | mesh.link.handshake_timeout_ms | duration | 10000 | 1000..120000 |
| peer_link.zig:104 | `default_heartbeat_interval_ms` | 15000 | Heartbeat send interval when idle | mesh.link.heartbeat_interval_ms | duration | 15000 | 1000..120000 |
| peer_link.zig:105 | `default_idle_timeout_ms` | 45000 | Idle (no-rx) timeout → drain | mesh.link.idle_timeout_ms | duration | 45000 | 5000..600000 |
| peer_link.zig:106 | `default_drain_timeout_ms` | 5000 | Drain→close grace timeout | mesh.link.drain_timeout_ms | duration | 5000 | 500..60000 |
| link_session.zig:36 | `Config.gossip_interval_ms` | 1000 | Session gossip-round cadence | mesh.link.gossip_interval_ms | duration | 1000 | 100..60000 |
| link_session.zig:37 | `Config.repair_interval_ms` | 2000 | Session anti-entropy repair cadence | mesh.link.repair_interval_ms | duration | 2000 | 200..120000 |
| link_session.zig:35 | `Config.gossip_config.fanout` override | 1 | Per-session gossip fanout override | mesh.link.gossip_fanout | uint | 1 | 1..64 |
| link_session.zig:38 | `Config.view_config.active_capacity` override | 4 | Per-session active view capacity override | mesh.link.view_active_capacity | uint | 4 | 2..64 |
| link_session.zig:38 | `Config.view_config.passive_capacity` override | 8 | Per-session passive view capacity override | mesh.link.view_passive_capacity | uint | 8 | active+1..4096 |
| burst.zig:21 | `Limits.max_burst_bytes` | 65536 (64*1024) | Max bytes for a serialized state burst | mesh.link.burst_max_bytes | uint | 65536 | 4096..16777216 |
| burst.zig:21 | `Limits.max_records` | 512 | Max records per state burst | mesh.link.burst_max_records | uint | 512 | 16..65536 |

## [mesh.routing] — Route table & server registry capacities

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| route_table.zig:21 | `Config.max_nicks` | 4096 | Max tracked nicknames in route table | mesh.routing.max_nicks | uint | 4096 | 64..10000000 |
| route_table.zig:22 | `Config.max_channels` | 1024 | Max tracked channels in route table | mesh.routing.max_channels | uint | 1024 | 16..1000000 |
| route_table.zig:23 | `Config.max_nodes_per_channel` | 64 | Max member nodes recorded per channel | mesh.routing.max_nodes_per_channel | uint | 64 | 4..4096 |
| route_table.zig:24 | `Config.max_name_len` (borderline) | 64 | Max nick/channel name byte length | mesh.routing.max_name_len | uint | 64 | 16..256 |
| server_registry.zig:14 | `Config.max_nodes` | 512 | Max servers tracked in registry | mesh.routing.max_servers | uint | 512 | 8..65536 |
| server_registry.zig:15 | `Config.max_name_len` (borderline) | 63 | Max server name byte length | mesh.routing.max_server_name_len | uint | 63 | 16..255 |
| server_registry.zig:16 | `Config.max_description_len` (borderline) | 255 | Max server description byte length | mesh.routing.max_server_desc_len | uint | 255 | 32..1024 |

## [mesh] — CRDT clock / misc

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| clock.zig:106 | `Vector.max_entries` (borderline) | 64 | Max replicas in a version vector / causal context | mesh.causal_max_replicas | uint | 64 | 8..1024 |
| channel_crdt.zig:44 | `max_len` (channel name, borderline) | 64 | Max channel name length for CRDT | mesh.channel_name_max_len | uint | 64 | 16..256 |
| mesh.zig:38-43 | `Config` (composite) | nested defaults | Aggregates gossip/plumtree/swim configs + rng_seed | mesh.* (composite) | — | — | – |
