# Reactor and Threading

Orochi's live Linux server is built around a Ringlane wrapper over `std.os.linux.IoUring`. The file comment defines the socket path: accept TCP clients, receive IRC bytes through `Ring`, feed complete CRLF lines into the pure command core, and send queued replies back through `Ring`. Evidence: `src/daemon/server.zig:1`, `src/daemon/server.zig:3`, `src/daemon/server.zig:4`.

## Ringlane Reactor Core

| Component | Current behavior | Evidence |
| --- | --- | --- |
| Ring wrapper | `ringlane.Ring` owns `linux.IoUring` plus feature flags and exposes init/deinit/submit/submitAndWait. | `src/daemon/server.zig:466`, `src/daemon/server.zig:617`, `src/daemon/server.zig:621`, `src/daemon/server.zig:629` |
| Supported operations | Ringlane encodes accept, recv, send, timeout, connect, and poll completions in `user_data`. | `src/daemon/server.zig:493`, `src/daemon/server.zig:518`, `src/daemon/server.zig:575` |
| Accept/recv/send APIs | The wrapper queues accept, recv, connect, send, timeout, and poll-add SQEs. | `src/daemon/server.zig:637`, `src/daemon/server.zig:642`, `src/daemon/server.zig:650`, `src/daemon/server.zig:654`, `src/daemon/server.zig:662` |
| Completion demux | `reapCompletions` copies CQEs, decodes each completion, and calls the provided handler. | `src/daemon/server.zig:666`, `src/daemon/server.zig:669`, `src/daemon/server.zig:670` |
| Deterministic seam | `src/substrate/reactor.zig` is a separate vtable seam for monotonic time; its header still says io_uring submit/poll/accept/recv/send are future work for that seam, while the live io_uring wrapper is inside `server.zig`. | `src/substrate/reactor.zig:1`, `src/substrate/reactor.zig:16`, `src/substrate/reactor.zig:26`, `src/daemon/server.zig:466` |

## Per-Reactor State and Connection Classes

`LinuxServer` stores a heap slice of `Reactor` structs. Each `Reactor` owns its ring, connection table, listener fds, timer/wake state, and shard id. Evidence: `src/daemon/server.zig:1229`, `src/daemon/server.zig:1235`, `src/daemon/server.zig:1237`, `src/daemon/server.zig:1240`, `src/daemon/server.zig:1243`, `src/daemon/server.zig:1258`.

Each connection is assigned a **connection class** at registration by matching the connection's source IP (IPv4 and IPv6 CIDR), TLS status, SASL authentication, oper status, and ident/host glob patterns. The first matching class wins; a catch-all fallback class exists for each type (built-in `user` for regular clients, `server` for mesh links). Evidence: `src/daemon/conn_class.zig:1`, `src/daemon/server.zig:7073`.

| Field | Ownership rule | Evidence |
| --- | --- | --- |
| `ring` | Owned by one reactor thread for accept/recv/send/poll/timeout completions. | `src/daemon/server.zig:1236` |
| `clients` | Connections are pinned to a reactor-local slab; another reactor must not touch their fd/send buffers directly. | `src/daemon/server.zig:1238` |
| `shard_id` | Stamped into `ClientId.shard`; always 0 in single-reactor configuration. | `src/daemon/server.zig:1241` |
| listener fds | Plaintext, optional S2S, and optional implicit TLS listener fds live per reactor. | `src/daemon/server.zig:1245`, `src/daemon/server.zig:1247`, `src/daemon/server.zig:1249` |
| wake fd | A per-reactor eventfd may be polled so another thread can wake the loop. | `src/daemon/server.zig:1258`, `src/daemon/reactor_fabric.zig:155` |

The current reactor is held in `threadlocal var current_reactor`, and handlers call `self.rx()` to resolve the current thread's reactor or fall back to reactor 0 outside reactor threads. Evidence: `src/daemon/server.zig:1277`, `src/daemon/server.zig:1283`, `src/daemon/server.zig:1455`, `src/daemon/server.zig:1460`.

## SendQ and RecvQ

Every connection has a **SendQ** (outbound) and a **RecvQ** (inbound) bounded by the per-class policy, enforced at registration.

| Buffer | Structure | Ceiling | Evidence |
| --- | --- | --- | --- |
| **SendQ** | Inline ~8 KiB send buffer (`send_buf`) plus a heap-allocated overflow queue. The armed inline buffer is never moved or freed (io_uring zero-copy safe). | Per-class `sendq` ceiling (default 1 MiB for user class, 8 MiB for server class). | `src/daemon/server.zig:1592`, `src/daemon/server.zig:1596`, `src/daemon/server.zig:1601`, `src/daemon/conn_class.zig:50` |
| **RecvQ** | Inline line buffer (`line_buf`, ~512 B) accumulates the current unterminated line; overflow spills to a heap queue. The physical inline buffer default is inherited unless the class sets `recvq > 0`. | Per-class `recvq` ceiling (`0` = physical line-buffer default, ~512 B). A line exceeding this ceiling closes the connection with `LineTooLong`. | `src/daemon/server.zig:1579`, `src/daemon/server.zig:1583`, `src/daemon/server.zig:1591`, `src/daemon/conn_class.zig:52` |

SendQ overflow is drained back into the inline buffer on send completions, so the kernel never reads a heap buffer that could move or free during the io_uring zero-copy send. RecvQ overflow is pulled into the inline buffer as it drains. Both share the same `overflow_allocator` (the owning reactor's allocator). Evidence: `src/daemon/server.zig:1613`, `src/daemon/server.zig:3612`, `src/daemon/server.zig:4385`, `src/daemon/server.zig:5259`.

## Initialization

| Step | Behavior | Evidence |
| --- | --- | --- |
| Shard count | `clampShards` converts zero to one, caps at `shard.max_shards`, and returns at least one. | `src/daemon/server.zig:1464`, `src/daemon/server.zig:1467`, `src/daemon/server.zig:1469` |
| Listener selection | One reactor uses plain listeners and can adopt an inherited Helix listener; multiple reactors use SO_REUSEPORT listeners. | `src/daemon/server.zig:1472`, `src/daemon/server.zig:1480`, `src/daemon/server.zig:1484` |
| Per-reactor ring | `initReactor` creates the listener fds, Ringlane ring, reserved client slab, and wake handle. | `src/daemon/server.zig:1511`, `src/daemon/server.zig:1520`, `src/daemon/server.zig:1522`, `src/daemon/server.zig:1534` |
| Server reactor slice | `LinuxServer.init` allocates `reactors` with length `shard_count` and initializes each. | `src/daemon/server.zig:1543`, `src/daemon/server.zig:1549`, `src/daemon/server.zig:1553` |
| Shared world/stores | `LinuxServer` owns shared world and stores separately from per-reactor I/O. | `src/daemon/server.zig:1308`, `src/daemon/server.zig:1567` |

## Run Loop

| Mode | Behavior | Evidence |
| --- | --- | --- |
| `runOnce` | Binds reactor 0 if no thread-local reactor is set, arms accept/wake/timer, waits for a completion, reaps CQEs, drains fabric if present, submits pending SQEs. | `src/daemon/server.zig:2231`, `src/daemon/server.zig:2236`, `src/daemon/server.zig:2237`, `src/daemon/server.zig:2240`, `src/daemon/server.zig:2244`, `src/daemon/server.zig:2252`, `src/daemon/server.zig:2254` |
| Single reactor | `runThreaded` runs `runOnce` inline when `self.reactors.len <= 1`; no pool and no fabric are used. | `src/daemon/server.zig:2265`, `src/daemon/server.zig:2268`, `src/daemon/server.zig:2270` |
| Multi reactor | For more than one reactor, `runThreaded` creates a cross-shard fabric, starts one worker thread per reactor, and joins the pool. | `src/daemon/server.zig:2278`, `src/daemon/server.zig:2283`, `src/daemon/server.zig:2295`, `src/daemon/server.zig:2296`, `src/daemon/server.zig:2311` |
| Worker | Each worker sets `current_reactor` to its shard and loops `runOnce` while the run flag is true. | `src/daemon/server.zig:2314`, `src/daemon/server.zig:2318`, `src/daemon/server.zig:2319` |

## Cross-Shard Delivery

When a command needs to write to a connection, `enqueueDelivery` is the central shard-aware sink. Local writes append directly to the owning reactor's connection; cross-shard writes copy bytes into pooled buffers, enqueue them into the target shard mailbox, and wake the target reactor. Evidence: `src/daemon/server.zig:2800`, `src/daemon/server.zig:2819`, `src/daemon/server.zig:2826`, `src/daemon/server.zig:2860`.

`ReactorFabric` is runtime-sized by shard count and owns one MPMC inbox and one wake eventfd per shard plus a shared pooled-buffer allocator. Evidence: `src/daemon/reactor_fabric.zig:1`, `src/daemon/reactor_fabric.zig:48`, `src/daemon/reactor_fabric.zig:63`, `src/daemon/reactor_fabric.zig:66`, `src/daemon/reactor_fabric.zig:68`, `src/daemon/reactor_fabric.zig:77`.

| Fabric operation | API | Evidence |
| --- | --- | --- |
| Copy bytes into pool | `acquire(bytes)` returns a `DeliverBuf` or null. | `src/daemon/reactor_fabric.zig:123`, `src/daemon/reactor_fabric.zig:126` |
| Enqueue | `sendTo(target, msg)` pushes into the target shard inbox. | `src/daemon/reactor_fabric.zig:141`, `src/daemon/reactor_fabric.zig:145` |
| Drain | `drain(target, out)` is called by the owning reactor. | `src/daemon/reactor_fabric.zig:149`, `src/daemon/reactor_fabric.zig:151` |
| Wake | `wake(target)` pokes the target shard's eventfd. | `src/daemon/reactor_fabric.zig:155`, `src/daemon/reactor_fabric.zig:157` |

## World Locking

The shared `World` owns an `RwLock`. Current comments say lookups take the read lock, mutations take the write lock, and every mutation/allocation happens under the exclusive lock. Evidence: `src/daemon/world.zig:218`, `src/daemon/world.zig:220`, `src/daemon/world.zig:225`, `src/daemon/world.zig:229`, `src/daemon/world.zig:235`.

The world also has lazily activated RCU mirrors for nick lookup and channel existence/membership. The RCU model is implemented in `world_rcu.zig`: readers pin EBR and traverse immutable HAMT snapshots without locks or allocation; writers serialize, copy-on-write, publish a new root, and retire old state. Evidence: `src/daemon/world.zig:207`, `src/daemon/world.zig:213`, `src/daemon/world_rcu.zig:1`, `src/daemon/world_rcu.zig:26`, `src/daemon/world_rcu.zig:33`.

## Is Multithreading Live?

Yes, conditionally. The default configuration is one shard, but current source creates multiple reactors when `config.num_shards > 1`, uses SO_REUSEPORT for multiple reactors, initializes the cross-shard fabric, and spawns one worker thread per reactor. Evidence: `src/daemon/server.zig:992`, `src/daemon/server.zig:1543`, `src/daemon/server.zig:1547`, `src/daemon/server.zig:2278`, `src/daemon/server.zig:2295`.

The test suite contains an end-to-end threaded server test using `num_shards = 2` and skips only if the server ended up with fewer than two reactors. Evidence: `src/daemon/server.zig:12068`, `src/daemon/server.zig:12077`, `src/daemon/server.zig:12084`.

## Planning Notes and Divergences

`docs/planning/06-threading.md`, `docs/planning/10-io-threading.md`, and `docs/planning/24-multithreading.md` describe the intended direction. Current code diverges in one important inline comment: `Config.num_shards` still says values greater than 1 are clamped to 1 at `runThreaded`, but the implementation starts the multi-reactor pool when `reactors.len > 1`. Evidence for the stale comment: `src/daemon/server.zig:987`; evidence for current behavior: `src/daemon/server.zig:2270`, `src/daemon/server.zig:2278`, `src/daemon/server.zig:2296`.
