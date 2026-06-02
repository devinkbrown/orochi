**01 — Zig-Native Systems Substrate**

Planning only. I did not modify files. One requested consumer, `/home/kain/ophion/ircd/recv.c`, is not present; the actual receive path is `packet.c`, whose header identifies packet I/O and flood control at `/home/kain/ophion/ircd/packet.c:3` and `read_packet()` at `/home/kain/ophion/ircd/packet.c:454`.

**Ground Truth**
Mizuchi is explicitly clean-slate Zig: daemon and substrate are rewritten from scratch, with Ophion/libop only as reference material `/home/kain/mizuchi/docs/BRIEF.md:3`, `/home/kain/mizuchi/docs/BRIEF.md:6`. The brief already names the substrate scope: io_uring, lock-free concurrency, allocators/arenas, data structures, CRDTs, clocks, Merkle delta sync, and gossip `/home/kain/mizuchi/docs/BRIEF.md:32`.

libop currently provides a callback/timer API via `op_event_add`, `op_event_post_pri`, and cancellable handles `/home/kain/libop/include/op_event.h:37`, `/home/kain/libop/include/op_event.h:88`, `/home/kain/libop/include/op_event.h:94`; fd wrappers and callback rearming through `op_open`, `op_setselect`, `op_read`, `op_write`, TLS/WebSocket helpers, and fd passing `/home/kain/libop/include/op_commio.h:95`, `/home/kain/libop/include/op_commio.h:156`, `/home/kain/libop/include/op_commio.h:184`, `/home/kain/libop/include/op_commio.h:214`. It also has a lock-free MPSC send queue `/home/kain/libop/include/op_sendbuf.h:81`, Vyukov MPMC `/home/kain/libop/include/op_mpmc.h:1`, SPSC rings `/home/kain/libop/include/op_spsc.h:1`, arenas `/home/kain/libop/include/op_arena.h:63`, slabs `/home/kain/libop/include/op_balloc.h:81`, and LADON math primitives such as OR-Set, vector clocks, HLC, Merkle, Bloom, and HLL `/home/kain/libop/include/op_crdt.h:159`, `/home/kain/libop/include/op_vclock.h:96`, `/home/kain/libop/include/op_hlc.h:60`, `/home/kain/libop/include/op_merkle.h:109`, `/home/kain/libop/include/op_bloom.h:37`, `/home/kain/libop/include/op_hll.h:59`.

The lesson is not “port this.” The C io_uring backend is still a poll compatibility layer `/home/kain/libop/src/io_uring.c:5`; multishot recv/buf_ring is scaffolded but disabled until callback APIs change `/home/kain/libop/src/io_uring.c:107`. The thread pool has strong work-stealing ideas, but also C compromises like intentionally leaked deque buffers during growth `/home/kain/libop/src/thread_pool.c:111` and eventfd/pipe wakeups `/home/kain/libop/src/thread_pool.c:600`. The substrate should keep the ownership patterns and replace the API shape.

**1. Module Layout**
Reusable package: `mizuchi-substrate`.

```text
substrate/
  root.zig             public exports, feature manifest
  target.zig           comptime kernel/cpu feature selection
  io/
    ring.zig           io_uring Loop(Config), SQ/CQ batching
    op.zig             typed operations and completion unions
    buffer.zig         provided buffer rings, zero-copy send leases
    fd.zig             generational fixed-file handles
    timer.zig          timerfd/timeouts or uring timeout chains
  sched/
    pool.zig           futex worker pool, work stealing
    queue.zig          MPMC/SPSC/MPSC/Treiber, comptime padded
    park.zig           missed-wakeup-safe futex protocol
  mem/
    allocators.zig     root/shard/connection allocators
    arena.zig          scoped arenas, reset marks, scratch frames
    slab.zig           typed slabs and hot-path fixed buffers
    reclaim.zig        epoch/hazard-style deferred reclamation
  ds/
    map.zig trie.zig cidr.zig interval.zig ring.zig bitset.zig
    lru.zig pqueue.zig graph.zig string_intern.zig simd_scan.zig
  ladon/
    clock.zig          HLC, vector/dotted version vectors
    crdt.zig           generated CRDT families and delta codecs
    merkle.zig         adaptive Merkle forests
    sketch.zig         Bloom, Cuckoo, HLL, gossip estimators
  obs/
    metrics.zig trace.zig fault_inject.zig
  testing/
    model_check.zig crdt_laws.zig queue_litmus.zig
```

Public API is Zig-native: `Loop(Config)`, `Pool(Config)`, `Queue(T, Config)`, `Arena(.conn)`, `DeltaSet(Key, Config)`. No `void *` callback ABI.

**2. Event Loop**
Mizuchi’s loop is io_uring-first, not poll-rearmed. Ophion currently accepts with `op_accept_tcp()` after `op_listen()` `/home/kain/ophion/ircd/listener.c:412`, `/home/kain/ophion/ircd/listener.c:428`, then pins clients to accepting shards `/home/kain/ophion/ircd/listener.c:1085`. Make that the type system’s default.

```zig
const Kernel = struct {
    min_linux: std.SemanticVersion,
    multishot_accept: bool,
    multishot_recv: bool,
    buf_ring: bool,
    send_zc: bool,
    fixed_files: bool,
    defer_taskrun: bool,
    sqpoll: bool,
};

pub fn Loop(comptime cfg: Kernel) type {
    return struct {
        sq: SqBatch(cfg.sq_depth),
        cq: CqBatch(cfg.cq_depth),
        files: if (cfg.fixed_files) FixedFileTable else void,
        recv_rings: if (cfg.buf_ring) BufRingSet(cfg) else void,

        pub fn armAccept(self: *@This(), listener: ListenerToken) !void {
            if (cfg.multishot_accept) try self.sq.acceptMultishot(listener)
            else try self.sq.acceptOne(listener);
        }

        pub fn armRecv(self: *@This(), c: ConnToken(.owned_by_loop)) !void {
            if (cfg.multishot_recv and cfg.buf_ring)
                try self.sq.recvMultishot(c, self.recv_rings.group(c.shard))
            else
                try self.sq.recvInto(c, c.scratch());
        }

        pub fn tick(self: *@This()) !void {
            try self.flushSq();
            const batch = try self.collectCq(.{ .max = 512 });
            for (batch) |cqe| switch (decode(cqe)) {
                .accept => |a| try self.installConn(a),
                .recv => |r| try self.dispatchRecv(r), // owns BufLease
                .send => |s| self.completeSend(s),
                .timer => |t| self.fireTimer(t),
                .wakeup => self.drainCrossThread(),
            };
        }
    };
}
```

Feature selection is two-stage. At comptime, `target.zig` compiles out unsupported paths by target OS, arch, and configured minimum kernel. At runtime, startup probes narrow features and fail closed: if compiled with `send_zc=true` but runtime lacks it, the `SendPath` vtable becomes `copy_writev` while the rest of the loop remains the same type.

SQ policy:
- Per-shard rings, not one global ring.
- Submit in batches after draining cross-thread dirty queues.
- Multishot accept emits `AcceptCqe{ listener, fd, peer_addr_buf }`.
- Multishot recv with provided buffer rings emits `RecvCqe{ conn, lease: BufLease, len, flags }`.
- Fixed files are generational: `FdToken{ slot, gen }`, rejecting stale CQEs like libop’s fd/gen idea `/home/kain/libop/src/io_uring.c:38`.
- `send_zc` accepts only `SendLease` values whose backing storage outlives the completion.
- `DEFER_TASKRUN` and `SQPOLL` are `Kernel` flags. With `DEFER_TASKRUN`, cross-thread wakeups use a single ring-owned wake primitive, preferably `IORING_OP_MSG_RING` for ring-to-ring, falling back to one eventfd per shard, not per worker.

**3. Concurrency**
Keep the proven shapes, replace C atomics and fd wakeups. libop’s MPMC queue is the right family: per-slot sequence counters eliminate ABA `/home/kain/libop/include/op_mpmc.h:4`. But Zig makes it generic and padded by construction.

```zig
pub fn BoundedMpmc(comptime T: type, comptime cap: usize, comptime pad: CachePad) type {
    comptime assert(std.math.isPowerOfTwo(cap));
    return struct {
        const Slot = extern struct {
            seq: std.atomic.Value(u64) align(pad.bytes),
            item: T,
        };
        head: std.atomic.Value(u64) align(pad.bytes) = .init(0),
        tail: std.atomic.Value(u64) align(pad.bytes) = .init(0),
        slots: [cap]Slot,

        pub fn push(self: *@This(), item: T) bool { /* Vyukov, typed */ }
        pub fn pop(self: *@This()) ?T { /* no void*, no allocation */ }
        pub fn popBatch(self: *@This(), out: []T) usize { /* range claim */ }
    };
}
```

Worker pool:
- Chase-Lev local deque per worker.
- MPSC Treiber inbox for external submits.
- Randomized stealing.
- Affinity key for per-client command ordering, preserving Ophion’s current goal `/home/kain/ophion/ircd/worker.c:264`.
- Futex parking, not eventfd/pipe polling.

Missed-wakeup-safe park/wake:
- Worker drains inbox/deque/steals.
- If empty, it CASes `state` from `Running(epoch)` to `Sleeping(epoch)`.
- It reloads inbox with acquire. If non-empty, CASes back to running and skips sleep.
- Otherwise `futex_wait(&state_word, Sleeping(epoch))`.
- Submitter pushes to inbox with release, increments epoch with release, and if previous state was sleeping, `futex_wake`.
- Futex wait is conditional on the exact word; producer changing epoch prevents sleeping on stale state. This avoids the eventfd race that libop handles with seq_cst fences `/home/kain/libop/src/thread_pool.c:852`, `/home/kain/libop/src/thread_pool.c:970`.

Treiber freelists use tagged pointers or indexed handles: `TaggedIndex{ idx: u48, aba: u16 }`. No raw pointer ABA, no hazard needed for fixed slabs; epoch reclamation handles dynamic structures.

**4. Memory**
Allocator stack:
- `RootAllocator`: process lifetime, large metadata.
- `ShardAllocator`: per-ring, per-worker slabs, fixed fd/client queues.
- `ConnArena`: reset on disconnect; owns parser state, capability maps, transport scratch.
- `TickArena`: reset every loop tick, replacing libop’s global event arena `/home/kain/libop/include/op_arena.h:155`.
- `ParseArena`: reset after command dispatch, matching Ophion worker usage `/home/kain/ophion/ircd/worker.c:281`.

Ownership model:
- A connection is `ConnToken(.loop_owned)` or `ConnToken(.worker_borrowed)`.
- Only loop-owned tokens can issue I/O.
- Worker code can enqueue `SendMsg` or `CloseRequest`, never write sockets directly, matching the current invariant `/home/kain/ophion/ircd/send.c:268`.
- `BufLease` from a buf_ring cannot be stored unless converted to an owned copy.
- `SendLease` tracks completion: `copy`, `arena_until_tick`, `refcounted_line`, or `zc_pinned`.

**5. Data-Structure Kit**
Comptime-generated:
- `Vec(T)`, `SmallVec(T, N)`, `Ring(T, N)`, `Deque(T)`.
- `BitSet(N)`, replacing macro bitsets.
- `HashMap(K,V,Hash,Eq,Policy)`, with IRC-case fold as a comptime comparator.
- `RadixTrie(V, alphabet, fold)`, `CidrTrie(V, afi)`.
- `IntervalTree(K,V)`, `RbTree(K,V)`, `SkipList(K,V)` only where iteration/range workloads need them.
- `Lru(K,V,Policy)`, `PriorityQueue(T, lessThan)`, `Graph(Node, Edge)`.
- `RateLimit(Config)`: token bucket with monotonic time source, replacing hard-coded scale constants `/home/kain/libop/include/op_ratelimit.h:64`.
- `SimdScan(Delims)`: generated delimiter scanners for IRC lines, MessagePack markers, LADON frame headers.

Non-negotiable: containers carry allocator ownership explicitly and expose telemetry hooks.

**6. LADON Math Substrate**
LADON already uses SWIM, CRDT anti-entropy, VEIL-wrapped frames, and binary frame classes `/home/kain/ophion/docs/protocols/ladon/overview.md:8`, `/home/kain/ophion/docs/protocols/ladon/wire-protocol.md:41`. The current C CRDTs are fixed-size: 32 replicas, 64 overflow dots, 4 dots per element `/home/kain/libop/include/op_crdt.h:54`, `/home/kain/libop/include/op_crdt.h:171`. Mizuchi should make those policy parameters.

```zig
pub fn DotSet(comptime Key: type, comptime cfg: CrdtCfg) type {
    return struct {
        const Dot = struct { replica: ReplicaKey, counter: u64 };
        entries: Map(Key, SmallSet(Dot, cfg.inline_dots)),
        cc: CausalContext(cfg.max_replicas, cfg.overflow),

        pub fn add(self: *@This(), key: Key, r: ReplicaKey) Delta(Key) {
            const d = self.cc.nextDot(r);
            self.entries.getOrPut(key).add(d);
            self.cc.observe(d);
            return .{ .adds = .single(key, d), .cc = .single(d) };
        }

        pub fn remove(self: *@This(), key: Key) Delta(Key) {
            const dots = self.entries.remove(key) orelse return .empty;
            return .{ .removes = dots, .cc = self.cc.cover(dots) };
        }

        pub fn mergeDelta(self: *@This(), delta: Delta(Key)) void {
            comptime verifyJoinSemilattice(@This());
            self.applyAddsNotDominated(delta);
            self.removeDominated(delta.cc);
            self.cc.merge(delta.cc);
        }
    };
}
```

Improvements:
- Delta-state first: every mutation returns a compact delta and an anti-entropy fingerprint.
- Comptime-specialized merge: OR-Set, AWOR-Map, MV-Reg, LWW-Reg, G/P/N counters generated from a `CrdtSpec`.
- Compact tombstone GC: compute a replica stability frontier from peer causal contexts; discard dots/tombstones dominated by all live peers.
- Dotted version vectors replace plain fixed vector clocks for large meshes.
- HLC is widened to `wall_ms: u48, logical: u16, skew_class: u8`, with explicit overflow handling instead of silent logical wrap.
- Merkle becomes an adaptive forest: keyspace trie plus time buckets, not one fixed-depth time tree like `OP_MERKLE_DEPTH` `/home/kain/libop/include/op_merkle.h:26`.
- Bloom/HLL are domain-separated by frame type and mesh epoch to avoid cross-protocol hash reuse.
- Anti-entropy planner chooses between delta replay, Merkle range diff, Bloom negative set, or HLL “too divergent, resync” based on estimated cost.

**7. Novel Technologies**
1. **FlowForge**: comptime-verified I/O pipelines. Define legal states for `Accepted -> ProxyHeader? -> TLS? -> VEIL? -> IRC/LADON`; illegal transitions fail compilation for static flows and trap with typed errors for dynamic flows.

2. **CapSeals**: zero-cost capability tokens. `ConnToken(.loop_owned)` can arm recv/send; `ConnToken(.worker_borrowed)` can only enqueue commands. This encodes today’s comments as types.

3. **CausalForge**: CRDT codegen from semilattice specs. The build generates merge/apply/delta/wire code and property tests for associativity, commutativity, idempotence, and convergence.

4. **LeaseRing**: buf_ring leases tied to parser frames. A recv completion gives `BufLease(.kernel)`. The parser must consume, split, or copy before returning; the buffer cannot be re-added twice or leaked.

5. **Kernel Persona**: a comptime feature persona for Linux kernel targets. Release binaries can be built as `linux_6_1_safe`, `linux_6_8_fast`, or `linux_latest_lab`, each removing unsupported io_uring branches from hot paths.

6. **MeshLens**: adaptive anti-entropy optimizer combining Merkle, Bloom, HLL, and causal frontiers to choose the cheapest repair plan per peer.

**8. Risks & Open Questions**
- Zig’s Linux/io_uring surface may lag kernel features; substrate may need thin syscall wrappers.
- SQPOLL and fixed files complicate hot upgrade and fd passing. Decide early whether Mizuchi preserves Ophion-style shim migration.
- `send_zc` lifetime tracking is only worth it for server links and large fanout; normal IRC lines may be faster through copy/writev.
- Futex pool should be model-checked with litmus tests on ARM64.
- CRDT tombstone GC depends on accurate live-peer membership. SWIM false suspicions must not delete causality needed by a recovering peer.
- Need a target minimum Linux kernel per deployment tier.
- Decide whether SCTP survives into Mizuchi; Ophion still branches for SCTP listener setup `/home/kain/ophion/ircd/listener.c:347`.

