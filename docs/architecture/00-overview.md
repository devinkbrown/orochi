# Orochi architecture overview

_System overview of the client-facing daemon, request flow, source map, and the architecture document index._

Orochi is a Zig package and daemon executable. The package manifest sets `.minimum_zig_version = "0.16.0"` and lists no dependencies under `.dependencies`, so the current tree builds entirely from checked-in Zig source. Evidence: `build.zig.zon:28`, `build.zig.zon:34`. The library root re-exports the major namespaces `crypto`, `daemon`, `proto`, and `substrate`, and adds the OroWasm host and browser transport shim roots. Evidence: `src/root.zig:8`, `src/root.zig:16`, `src/root.zig:21`.

This overview covers the client-facing daemon, local world, module dispatch, reactor model, media, Helix upgrade, and OroWasm. Mesh/server-to-server (S2S) and cryptography are out of scope here; see [mesh-s2s.md](mesh-s2s.md) and [crypto.md](crypto.md).

## Major subsystems

| Area | Current source of truth | What it owns | Evidence |
| --- | --- | --- | --- |
| Build/package | `build.zig`, `build.zig.zon` | Zig package metadata, `orochi` executable, test/run steps, 64-bit daemon target guard | `build.zig:20`, `build.zig:87`, `build.zig.zon:28` |
| Daemon server | `src/daemon/server.zig` | Linux TCP server, Ringlane io_uring wrapper, connection table, registration integration, live stores, registry/WASM dispatch, media/upgrade wiring | `src/daemon/server.zig:1`, `src/daemon/server.zig:466`, `src/daemon/server.zig:1285` |
| Connection classes | `src/daemon/conn_class.zig`, `src/daemon/server.zig` | Named per-connection policy (sendq/recvq ceilings, max_clients/per_ip/channels, timeouts, TLS/SASL requirements, flood control, nick-delay exemption); CIDR/TLS/account/oper/ident/host matching; per-class assignment at registration | `src/daemon/conn_class.zig:1`, `src/daemon/server.zig:7073`, `src/daemon/server.zig:3615` |
| Nick delay | `src/daemon/nick_delay.zig`, `src/daemon/server.zig` | Held-nick registry; holds a released nick for a configured window to prevent nick camping; per-account reclaim and oper bypass; exempt class bypass | `src/daemon/nick_delay.zig:1`, `src/daemon/server.zig:2099`, `src/daemon/server.zig:5949` |
| Pre-registration dispatch | `src/daemon/dispatch.zig` | PASS/NICK/USER/CAP/AUTHENTICATE/PING/PONG/QUIT, CAP/labeled-response handling, welcome burst | `src/daemon/dispatch.zig:1`, `src/daemon/dispatch.zig:1111`, `src/daemon/dispatch.zig:1233` |
| Protocol inventory | `src/proto/protocol_inventory.zig` | Canonical network name, ISUPPORT tokens, CHANMODES, runtime advertised-limit override | `src/proto/protocol_inventory.zig:1`, `src/proto/protocol_inventory.zig:40`, `src/proto/protocol_inventory.zig:73` |
| Local world | `src/daemon/world.zig` | Nick ownership, channel membership, topics, modes, bans, invitations, RCU mirrors, local-only state | `src/daemon/world.zig:1`, `src/daemon/world.zig:193`, `src/daemon/world.zig:218` |
| SerpentRegistry modules | `src/daemon/registry.zig`, `src/daemon/modules/manifest.zig`, `src/daemon/modules/*.zig` | Comptime module metadata, validated command/hook/cap tables, gated command dispatch, MODULES/COMMANDS introspection | `src/daemon/registry.zig:1`, `src/daemon/modules/manifest.zig:22`, `src/daemon/registry.zig:554` |
| Reactor/threading | `src/daemon/server.zig`, `src/daemon/reactor_pool.zig`, `src/daemon/reactor_fabric.zig`, `src/substrate/reactor.zig` | io_uring completion loop, per-reactor connection slabs, optional worker pool, cross-shard delivery fabric, deterministic time seam | `src/daemon/server.zig:1229`, `src/daemon/reactor_pool.zig:1`, `src/daemon/reactor_fabric.zig:1`, `src/substrate/reactor.zig:1` |
| Media | `src/substrate/suimyaku/media.zig`, `src/daemon/media_room.zig`, `src/daemon/media_plane.zig`, `src/daemon/native_media_transport.zig`, `src/daemon/media_bridge.zig` | SFU participant model, per-channel rooms, RTP/STUN media plane, native KaguraVox/KaguraVis UDP leg, cross-leg rewrap | `src/substrate/suimyaku/media.zig:1`, `src/daemon/media_room.zig:1`, `src/daemon/media_plane.zig:1`, `src/daemon/native_media_transport.zig:1`, `src/daemon/media_bridge.zig:1` |
| Helix upgrade | `src/daemon/modules/upgrade.zig`, `src/daemon/server.zig`, `src/daemon/helix/live.zig`, `src/daemon/helix/handoff.zig` | UPGRADE command, sealed memfd arena, listener/session fd inheritance, successor adoption | `src/daemon/modules/upgrade.zig:1`, `src/daemon/server.zig:6070`, `src/daemon/helix/live.zig:1`, `src/daemon/helix/handoff.zig:1` |
| OroWasm | `src/wasm/host/*`, `src/wasm/kagura_wasm.zig`, `src/wasm/browser_transport.zig` | Control-plane plugin interpreter/bridge/capabilities and browser KaguraVox/KaguraVis exports | `src/wasm/host/interp.zig:1`, `src/wasm/host/bridge.zig:1`, `src/wasm/kagura_wasm.zig:1` |

## End-to-end client request flow

| Step | Flow | Evidence |
| --- | --- | --- |
| 1 | `runOnce` arms accept, wake, and timer operations, waits for at least one io_uring completion, reaps completions, drains cross-shard fabric if present, then submits pending work. | `src/daemon/server.zig:2231`, `src/daemon/server.zig:2237`, `src/daemon/server.zig:2240`, `src/daemon/server.zig:2252` |
| 2 | A recv completion calls `handleRecv`: plaintext client bytes go to `feedBytes`, TLS bytes go to `driveTls`, and S2S bytes go to the S2S drivers (documented separately). | `src/daemon/server.zig:2749`, `src/daemon/server.zig:2760`, `src/daemon/server.zig:2764`, `src/daemon/server.zig:2767` |
| 3 | Complete client lines are parsed by the daemon-local IRC line parser before dispatch. The parser strips CRLF, rejects embedded NUL/line breaks, supports tags and prefixes, and caps params. | `src/daemon/server.zig:380`, `src/daemon/server.zig:385`, `src/daemon/server.zig:395`, `src/daemon/server.zig:415` |
| 4 | Before registration, the server handles IRCX enable/query and pre-away locally, then calls `processLine`, which adapts into `dispatch.dispatchLine`. | `src/daemon/server.zig:3340`, `src/daemon/server.zig:3349`, `src/daemon/server.zig:3354`, `src/daemon/server.zig:1194`, `src/daemon/server.zig:1213` |
| 5 | When `dispatchLine` completes registration, the server assigns the connection class (matching CIDR, TLS, auth, oper, ident/host; first match wins), sets SendQ/RecvQ ceilings per policy, registers the nick in `World`, enforces Warden/gag/session/seen hooks, autojoins, sends the welcome burst, fires the registry `client_registered` hook, and evaluates nick protection. | `src/daemon/server.zig:3355`, `src/daemon/server.zig:7073`, `src/daemon/server.zig:3356`, `src/daemon/server.zig:3360`, `src/daemon/server.zig:3376`, `src/daemon/server.zig:3383`, `src/daemon/server.zig:3384`, `src/daemon/server.zig:3385` |
| 6 | After registration, PING still uses `processLine`, but other lines enter `dispatchRegistered`. | `src/daemon/server.zig:3394`, `src/daemon/server.zig:3402`, `src/daemon/server.zig:3413` |
| 7 | `dispatchRegistered` first refreshes the world's wall-clock, routes multiline batches if negotiated, dispatches through SerpentRegistry, then through OroWasm plugins, then falls back to the lower preregistration dispatcher for handshake verbs. | `src/daemon/server.zig:3423`, `src/daemon/server.zig:3429`, `src/daemon/server.zig:3450`, `src/daemon/server.zig:3473`, `src/daemon/server.zig:3508` |
| 8 | Finished output is queued to a connection-local send buffer (inline ~8 KiB plus heap overflow, bounded by per-class `sendq`) or handed to the owning shard through `enqueueDelivery`; send completions drain the buffer and close when needed. Exceeding the SendQ ceiling fails the append. | `src/daemon/server.zig:2800`, `src/daemon/server.zig:2819`, `src/daemon/server.zig:2826`, `src/daemon/server.zig:2779`, `src/daemon/server.zig:1601` |

## Source tree map

| Path | Role | Evidence |
| --- | --- | --- |
| `src/main.zig` | Boot CLI, config loading, server initialization, Helix successor adoption, run loop | `src/main.zig:43`, `src/main.zig:51`, `src/main.zig:294` |
| `src/root.zig` | Public package root and namespace re-exports | `src/root.zig:1`, `src/root.zig:8` |
| `src/daemon/` | IRC daemon runtime, world, modules, services, media plane, Helix, reactor helpers | `src/daemon/server.zig:1285`, `src/daemon/world.zig:193`, `src/daemon/modules/manifest.zig:22` |
| `src/proto/` | Protocol codecs/builders/inventory used by daemon and modules | `src/proto/protocol_inventory.zig:1`, `src/proto/protocol_inventory.zig:40` |
| `src/substrate/` | Lower-level runtime primitives: reactor seam, transport stack, queues, EBR/HAMT, media transport helpers | `src/substrate/reactor.zig:1`, `src/substrate/transport_stack.zig:1`, `src/daemon/world_rcu.zig:9` |
| `src/crypto/` | Cryptography namespace; not covered here | `src/root.zig:8` |
| `src/wasm/` | OroWasm host, browser transport shim, and KaguraVox/KaguraVis browser exports | `src/root.zig:16`, `src/root.zig:21`, `src/wasm/kagura_wasm.zig:1` |

## Architecture index

| Document | Scope |
| --- | --- |
| [00-overview.md](00-overview.md) | System overview, request flow, source map, architecture index |
| [01-reactor-threading.md](01-reactor-threading.md) | Ringlane/io_uring reactor, worker shards, world locking, live multithreading status |
| [02-world-dispatch-modules.md](02-world-dispatch-modules.md) | `World`, preregistration dispatch, SerpentRegistry modules, hooks, introspection |
| [03-media.md](03-media.md) | SFU/session model, media rooms, RTP/STUN plane, native KaguraVox/KaguraVis transport, WASM shims |
| [04-upgrade-wasm.md](04-upgrade-wasm.md) | Helix UPGRADE handoff and OroWasm plugin host |
| [mesh-s2s.md](mesh-s2s.md) | Mesh/S2S architecture; separate document |
| [crypto.md](crypto.md) | Cryptography architecture; separate document |

## Planning notes and divergences

The planning docs remain useful design intent, especially `docs/planning/00-architecture.md`, `docs/planning/17-module-system.md`, `docs/planning/18-media-transport.md`, and `docs/planning/24-multithreading.md`. This architecture set treats current source as authoritative.

| Topic | Current-code finding | Evidence |
| --- | --- | --- |
| Registered command dispatch | Current `dispatchRegistered` says daemon-owned post-registration commands are resolved by the registry block; its remaining direct path is the preregistration command processor. This diverges from any older design text that describes a live legacy if/else command chain. | `src/daemon/server.zig:3502`, `src/daemon/server.zig:3508` |
| Multithreading | Default config is one shard, but the current code can allocate multiple reactors and spawn one worker per reactor when `num_shards > 1`. A nearby comment still says values above 1 are clamped at `runThreaded`, which does not match the current implementation. | `src/daemon/server.zig:992`, `src/daemon/server.zig:1543`, `src/daemon/server.zig:2278`, `src/daemon/server.zig:2295` |
| Helix session carry-over | `session_snapshot.zig` still has a stale header comment saying channel membership is later, but the current wire format includes channel memberships and the successor restores them. | `src/daemon/helix/session_snapshot.zig:8`, `src/daemon/helix/session_snapshot.zig:15`, `src/daemon/server.zig:6219` |
