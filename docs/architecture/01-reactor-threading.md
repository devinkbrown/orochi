# Reactor and threading

_The Ringlane io_uring reactor, per-reactor connection state, worker shards, cross-shard delivery, world locking, and the live multithreading status._

Orochi's live Linux server still owns an embedded Ringlane wrapper in `src/daemon/server.zig`, while the reusable substrate Ringlane backend now lives under `src/substrate/io/`. The live server comment defines the socket path as TCP accept, receive IRC bytes through `Ring`, feed complete LF-terminated lines into the pure command core, and send queued replies back through `Ring`. Evidence: `src/daemon/server.zig:4`, `src/daemon/server.zig:6`, `src/daemon/server.zig:7`, `src/daemon/server.zig:8`.

## Ringlane reactor core

| Component | Current behavior | Evidence |
| --- | --- | --- |
| Live server Ringlane | `server.zig`'s embedded `ringlane.Ring` owns `linux.IoUring` plus feature flags and exposes init/deinit/submit/submitAndWait for the daemon loop. | `src/daemon/server.zig:711`, `src/daemon/server.zig:863`, `src/daemon/server.zig:867`, `src/daemon/server.zig:875`, `src/daemon/server.zig:879` |
| Live server operations | The embedded wrapper encodes accept, recv, send, timeout, connect, and poll completions in `user_data`, and queues accept, recv, connect, send, timeout, and poll-add SQEs. | `src/daemon/server.zig:739`, `src/daemon/server.zig:749`, `src/daemon/server.zig:883`, `src/daemon/server.zig:898`, `src/daemon/server.zig:902`, `src/daemon/server.zig:906`, `src/daemon/server.zig:911`, `src/daemon/server.zig:918` |
| Completion demux | `reapCompletions` copies CQEs, decodes each completion, skips undecodable CQEs, and calls the provided handler for decoded completions. | `src/daemon/server.zig:922`, `src/daemon/server.zig:923`, `src/daemon/server.zig:924`, `src/daemon/server.zig:925`, `src/daemon/server.zig:926` |
| Substrate Ringlane backend | `src/substrate/io/root.zig` exports `ring` and `buf_ring`; `ring.zig` defines the Linux-only reusable `Ring` wrapper, pure `user_data` codec, typed completion decoder, and init/submit helpers. | `src/substrate/io/root.zig:4`, `src/substrate/io/root.zig:7`, `src/substrate/io/root.zig:8`, `src/substrate/io/ring.zig:170`, `src/substrate/io/ring.zig:194`, `src/substrate/io/ring.zig:268`, `src/substrate/io/ring.zig:323`, `src/substrate/io/ring.zig:331` |
| Provided-buffer rings | `buf_ring.zig` owns the provided-buffer-ring bookkeeping: live `setup_buf_ring`/publish/free, pure inline `BufRing` storage, lease creation from recv completions, and checked recycle/replenish. | `src/substrate/io/buf_ring.zig:56`, `src/substrate/io/buf_ring.zig:70`, `src/substrate/io/buf_ring.zig:82`, `src/substrate/io/buf_ring.zig:106`, `src/substrate/io/buf_ring.zig:151`, `src/substrate/io/buf_ring.zig:171` |
| Feature gating | The reusable backend declares baseline, `linux_6_1_safe`, and `linux_6_8_fast` profiles. `defer_taskrun` sets both `IORING_SETUP_DEFER_TASKRUN` and `IORING_SETUP_SINGLE_ISSUER`; `narrow` fails closed and keeps multishot recv coupled to buffer-ring support. | `src/substrate/io/ring.zig:57`, `src/substrate/io/ring.zig:61`, `src/substrate/io/ring.zig:71`, `src/substrate/io/ring.zig:81`, `src/substrate/io/ring.zig:87`, `src/substrate/io/ring.zig:98`, `src/substrate/io/ring.zig:101`, `src/substrate/io/ring.zig:108` |
| Live fast-path status | The live server config defaults to `RingFeatureSet.baseline`; the embedded server helper currently queues ordinary accept/recv on caller-owned buffers. The reusable substrate backend has `submitRecvBufRing`, but that helper is not the live server's current recv path. | `src/daemon/server.zig:1704`, `src/daemon/server.zig:883`, `src/daemon/server.zig:895`, `src/daemon/server.zig:898`, `src/daemon/server.zig:899`, `src/substrate/io/ring.zig:372`, `src/substrate/io/ring.zig:375`, `src/substrate/io/ring.zig:376` |
| Deterministic seam | `src/substrate/reactor.zig` is the separate vtable seam for monotonic and wall-clock time. The real backend reads platform clocks; deterministic backends expose caller-controlled or simulated-network clocks. The header still says submit/poll/accept/recv/send are future work for this seam. | `src/substrate/reactor.zig:4`, `src/substrate/reactor.zig:6`, `src/substrate/reactor.zig:9`, `src/substrate/reactor.zig:15`, `src/substrate/reactor.zig:23`, `src/substrate/reactor.zig:29`, `src/substrate/reactor.zig:41`, `src/substrate/reactor.zig:66`, `src/substrate/reactor.zig:93` |

## Per-reactor state and connection classes

`LinuxServer` stores a heap slice of `Reactor` structs. Each `Reactor` owns its ring, connection table, listener fds, timer/wake state, and shard id. Evidence: `src/daemon/server.zig:2504`, `src/daemon/server.zig:2510`, `src/daemon/server.zig:2511`, `src/daemon/server.zig:2515`, `src/daemon/server.zig:2518`, `src/daemon/server.zig:2520`, `src/daemon/server.zig:2533`, `src/daemon/server.zig:2537`, `src/daemon/server.zig:2814`, `src/daemon/server.zig:2818`.

Each connection is assigned a **connection class** by matching the connection's source IP (IPv4 and IPv6 CIDR), TLS status, SASL authentication, oper status, and ident/host glob patterns. The first matching class wins; S2S links resolve to the built-in `server` class and unmatched client links fall back to `user`. Evidence: `src/daemon/conn_class.zig:4`, `src/daemon/conn_class.zig:132`, `src/daemon/conn_class.zig:146`, `src/daemon/conn_class.zig:165`, `src/daemon/conn_class.zig:170`, `src/daemon/conn_class.zig:180`, `src/daemon/conn_class.zig:198`, `src/daemon/conn_class.zig:200`, `src/daemon/conn_class.zig:204`, `src/daemon/server.zig:9797`.

| Field | Ownership rule | Evidence |
| --- | --- | --- |
| `ring` | Owned by one reactor thread for accept/recv/send/poll/timeout completions. | `src/daemon/server.zig:2511` |
| `clients` | Connections are pinned to a reactor-local slab; another reactor must not touch their fd/send buffers directly. | `src/daemon/server.zig:2513`, `src/daemon/server.zig:2514`, `src/daemon/server.zig:6834`, `src/daemon/server.zig:6838` |
| `shard_id` | Stamped into `ClientId.shard`; always 0 in single-reactor configuration. | `src/daemon/server.zig:2516`, `src/daemon/server.zig:2517`, `src/daemon/server.zig:2518` |
| listener fds | Plaintext, optional S2S, optional implicit TLS, and optional secure-WebSocket listener fds live per reactor; S2S is reactor-0-only in sharded mode. | `src/daemon/server.zig:2520`, `src/daemon/server.zig:2522`, `src/daemon/server.zig:2524`, `src/daemon/server.zig:2526`, `src/daemon/server.zig:3295`, `src/daemon/server.zig:3298` |
| wake fd | A per-reactor eventfd may be polled so another thread can wake the loop and drain that shard's mailbox. | `src/daemon/server.zig:2537`, `src/daemon/server.zig:2540`, `src/daemon/server.zig:4383`, `src/daemon/server.zig:4388`, `src/daemon/server.zig:4422`, `src/daemon/server.zig:4430` |

The current reactor is held in `threadlocal var current_reactor`, and handlers call `self.rx()` to resolve the current thread's reactor or fall back to reactor 0 outside reactor threads. Evidence: `src/daemon/server.zig:2557`, `src/daemon/server.zig:2563`, `src/daemon/server.zig:3230`, `src/daemon/server.zig:3233`, `src/daemon/server.zig:3234`.

## SendQ and RecvQ

Every connection has a **SendQ** (outbound) and a **RecvQ** (inbound) bounded by the per-class policy, applied when `assignConnClass` runs.

| Buffer | Structure | Ceiling | Evidence |
| --- | --- | --- | --- |
| **SendQ** | Inline send buffer (`send_buf`) plus a heap-allocated overflow queue. The kernel reads only the fixed inline buffer; overflow refills the inline buffer on send completion. | Per-class `sendq` ceiling (default 1 MiB for user class, 8 MiB for server class). | `src/daemon/server.zig:2066`, `src/daemon/server.zig:2076`, `src/daemon/server.zig:2078`, `src/daemon/server.zig:2084`, `src/daemon/server.zig:30753`, `src/daemon/server.zig:30763`, `src/daemon/conn_class.zig:55`, `src/daemon/conn_class.zig:299` |
| **RecvQ** | Inline line buffer (`line_buf`) accumulates the current unterminated line; overflow spills to a heap queue. | Per-class `recvq` ceiling (`0` = physical line-buffer default). A line exceeding this ceiling closes the connection with `LineTooLong`. | `src/daemon/server.zig:2054`, `src/daemon/server.zig:2057`, `src/daemon/server.zig:2065`, `src/daemon/server.zig:30681`, `src/daemon/server.zig:30704`, `src/daemon/server.zig:30706`, `src/daemon/conn_class.zig:56`, `src/daemon/server.zig:9776` |

Both overflow queues share the connection's `overflow_allocator`; SendQ overflow is drained back into `send_buf`, and RecvQ overflow is released on reset after a completed line. Evidence: `src/daemon/server.zig:2059`, `src/daemon/server.zig:2094`, `src/daemon/server.zig:30716`, `src/daemon/server.zig:30729`, `src/daemon/server.zig:30767`, `src/daemon/server.zig:30773`.

## Initialization

| Step | Behavior | Evidence |
| --- | --- | --- |
| Shard count | `clampShards` converts zero to one, caps at `shard.max_shards`, and returns at least one. | `src/daemon/server.zig:3237`, `src/daemon/server.zig:3246`, `src/daemon/server.zig:3247`, `src/daemon/server.zig:3248`, `src/daemon/server.zig:3249` |
| Listener selection | The plaintext listener is created with SO_REUSEPORT even for one shard so a later 1-shard to N-shard upgrade can bind siblings. Sharded TLS and secure-WebSocket client listeners also use SO_REUSEPORT; the S2S listener is bound only by reactor 0. | `src/daemon/server.zig:3280`, `src/daemon/server.zig:3281`, `src/daemon/server.zig:3288`, `src/daemon/server.zig:3292`, `src/daemon/server.zig:3295`, `src/daemon/server.zig:3298`, `src/daemon/server.zig:3307`, `src/daemon/server.zig:3320` |
| Per-reactor ring | `initReactor` creates the listener fds, Ringlane ring, reserved client slab, shard-local client table, and wake handle. | `src/daemon/server.zig:3272`, `src/daemon/server.zig:3328`, `src/daemon/server.zig:3334`, `src/daemon/server.zig:3337`, `src/daemon/server.zig:3341`, `src/daemon/server.zig:3352` |
| Server reactor slice | `LinuxServer.init` allocates `reactors` with length `shard_count` and initializes each entry. | `src/daemon/server.zig:3378`, `src/daemon/server.zig:3384`, `src/daemon/server.zig:3388`, `src/daemon/server.zig:3389`, `src/daemon/server.zig:3514` |
| Shared world/stores | `LinuxServer` owns shared world and stores separately from per-reactor I/O; the worker pool is initialized alongside the server-level state. | `src/daemon/server.zig:3519`, `src/daemon/server.zig:3520`, `src/daemon/server.zig:3521`, `src/daemon/server.zig:3525`, `src/daemon/server.zig:3526` |

## Run loop

| Mode | Behavior | Evidence |
| --- | --- | --- |
| `runOnce` | Binds reactor 0 if no thread-local reactor is set, arms accept/wake/timer, waits for a completion, reaps CQEs, drains fabric if present, drains webhook posts, and submits pending SQEs. | `src/daemon/server.zig:5424`, `src/daemon/server.zig:5429`, `src/daemon/server.zig:5441`, `src/daemon/server.zig:5442`, `src/daemon/server.zig:5443`, `src/daemon/server.zig:5444`, `src/daemon/server.zig:5449`, `src/daemon/server.zig:5457`, `src/daemon/server.zig:5461`, `src/daemon/server.zig:5463` |
| Completion boundary | Each decoded completion is handled under one shared `world.lockWrite`; per-reactor clients, send buffers, and rings remain reactor-local. | `src/daemon/server.zig:30270`, `src/daemon/server.zig:30272`, `src/daemon/server.zig:30279`, `src/daemon/server.zig:30281`, `src/daemon/server.zig:30282`, `src/daemon/server.zig:30297` |
| Single reactor | `runThreaded` runs `runLoopResilient` inline when `self.reactors.len <= 1`; no pool and no fabric are used. | `src/daemon/server.zig:5474`, `src/daemon/server.zig:5479`, `src/daemon/server.zig:5480`, `src/daemon/server.zig:5481`, `src/daemon/server.zig:5482` |
| Multi reactor | For more than one reactor, `runThreaded` creates a cross-shard fabric, starts one worker thread per reactor, and joins the pool. If fabric or pool startup fails, it falls back to the single-reactor loop. | `src/daemon/server.zig:5485`, `src/daemon/server.zig:5490`, `src/daemon/server.zig:5495`, `src/daemon/server.zig:5501`, `src/daemon/server.zig:5506`, `src/daemon/server.zig:5514` |
| Worker | Each worker sets `current_reactor` to its shard and loops through `runLoopResilient`/`runOnce` while the run flag is true. | `src/daemon/server.zig:5517`, `src/daemon/server.zig:5521`, `src/daemon/server.zig:5522`, `src/daemon/server.zig:5532`, `src/daemon/server.zig:5534`, `src/daemon/reactor_pool.zig:61`, `src/daemon/reactor_pool.zig:94` |

## Cross-shard delivery

When a command needs to write to a connection, `enqueueDelivery` is the central shard-aware sink. Local writes append directly to the owning reactor's connection; cross-shard writes copy bytes into pooled buffers, enqueue them into the target shard mailbox, and wake the target reactor. Evidence: `src/daemon/server.zig:6828`, `src/daemon/server.zig:6832`, `src/daemon/server.zig:6834`, `src/daemon/server.zig:6839`, `src/daemon/server.zig:6891`, `src/daemon/server.zig:6916`, `src/daemon/server.zig:6928`, `src/daemon/server.zig:6939`, `src/daemon/server.zig:6962`.

`ReactorFabric` is runtime-sized by shard count and owns one MPMC inbox and one wake eventfd per shard plus a shared pooled-buffer allocator. The live daemon currently wakes the target reactor through `Reactor.wake`, not the fabric's own wake fds, because the reactor loop polls `Reactor.wake`. Evidence: `src/daemon/reactor_fabric.zig:4`, `src/daemon/reactor_fabric.zig:51`, `src/daemon/reactor_fabric.zig:65`, `src/daemon/reactor_fabric.zig:68`, `src/daemon/reactor_fabric.zig:70`, `src/daemon/reactor_fabric.zig:72`, `src/daemon/server.zig:6957`, `src/daemon/server.zig:6960`, `src/daemon/server.zig:6962`.

| Fabric operation | API | Evidence |
| --- | --- | --- |
| Copy bytes into pool | `acquire(bytes)` returns a `DeliverBuf` or null. | `src/daemon/reactor_fabric.zig:126`, `src/daemon/reactor_fabric.zig:129`, `src/daemon/reactor_fabric.zig:130` |
| Enqueue | `sendTo(target, msg)` pushes into the target shard inbox. | `src/daemon/reactor_fabric.zig:144`, `src/daemon/reactor_fabric.zig:148`, `src/daemon/reactor_fabric.zig:149` |
| Drain | `drain(target, out)` is called by the owning reactor. | `src/daemon/reactor_fabric.zig:152`, `src/daemon/reactor_fabric.zig:154`, `src/daemon/reactor_fabric.zig:155`, `src/daemon/server.zig:4441`, `src/daemon/server.zig:4446` |
| Wake | `wake(target)` pokes a fabric eventfd, while live cross-shard delivery wakes `self.reactors[id.shard].wake`. | `src/daemon/reactor_fabric.zig:158`, `src/daemon/reactor_fabric.zig:160`, `src/daemon/reactor_fabric.zig:161`, `src/daemon/server.zig:6957`, `src/daemon/server.zig:6962` |

## Worker pool

`ReactorPool` is the generic worker-thread harness for the sharded model. It spawns one thread per shard, passes each a distinct shard index, shares only a cooperative `RunFlag`, and joins every worker on shutdown. Evidence: `src/daemon/reactor_pool.zig:4`, `src/daemon/reactor_pool.zig:6`, `src/daemon/reactor_pool.zig:18`, `src/daemon/reactor_pool.zig:28`, `src/daemon/reactor_pool.zig:61`, `src/daemon/reactor_pool.zig:66`, `src/daemon/reactor_pool.zig:92`, `src/daemon/reactor_pool.zig:101`, `src/daemon/reactor_pool.zig:105`.

## World locking

The shared `World` owns an `RwLock`. Current comments say lookups take the read lock, mutations take the write lock, and every mutation/allocation happens under the exclusive lock. Evidence: `src/daemon/world.zig:328`, `src/daemon/world.zig:329`, `src/daemon/world.zig:336`, `src/daemon/world.zig:338`, `src/daemon/world.zig:344`.

The world also has lazily activated RCU mirrors for nick lookup and channel existence/membership. The RCU model is implemented in `world_rcu.zig`: readers pin EBR and traverse immutable HAMT snapshots without locks or allocation; writers serialize, copy-on-write, publish a new root, and retire old state. Evidence: `src/daemon/world.zig:314`, `src/daemon/world.zig:322`, `src/daemon/world_rcu.zig:7`, `src/daemon/world_rcu.zig:27`, `src/daemon/world_rcu.zig:29`, `src/daemon/world_rcu.zig:36`, `src/daemon/world_rcu.zig:40`.

## Is multithreading live?

Yes, conditionally. The default configuration is one shard, but the current source creates multiple reactors when `config.num_shards > 1`. In that case it initializes a reactor slice, starts a cross-shard fabric, and spawns one worker thread per reactor. Evidence: `src/daemon/server.zig:1640`, `src/daemon/server.zig:3378`, `src/daemon/server.zig:3384`, `src/daemon/server.zig:3389`, `src/daemon/server.zig:5485`, `src/daemon/server.zig:5490`, `src/daemon/server.zig:5501`.

The test suite contains threaded server coverage for multi-reactor startup and cross-shard behavior. It asserts `num_shards = 4` produces four reactors, and `num_shards = 2` cross-shard tests skip only when fewer than two reactors are available. Evidence: `src/daemon/server.zig:32437`, `src/daemon/server.zig:32439`, `src/daemon/server.zig:32445`, `src/daemon/server.zig:36850`, `src/daemon/server.zig:36860`, `src/daemon/server.zig:36869`, `src/daemon/server.zig:36942`, `src/daemon/server.zig:36954`, `src/daemon/server.zig:36960`.

## Planning notes and divergences

Current code diverges from older design intent in one important inline comment: `Config.num_shards` still says values greater than 1 are clamped to 1 at `runThreaded`, but the implementation starts the multi-reactor pool when `reactors.len > 1`. Evidence for the stale comment: `src/daemon/server.zig:1635`, `src/daemon/server.zig:1637`; evidence for current behavior: `src/daemon/server.zig:5479`, `src/daemon/server.zig:5485`, `src/daemon/server.zig:5501`.
