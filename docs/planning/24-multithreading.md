# 24 — Multithreading the daemon (sharded reactors)

## Goal

Mizuchi must scale across cores: one io_uring reactor on a single thread cannot
saturate a many-core box for a large network. The target is **N worker threads,
each owning its own io_uring reactor** and a disjoint slice of the connection
table, coordinating through lock-free queues rather than shared mutable state on
the hot path.

This is a standing requirement (the user: "everything should be multithreaded").

## Current state

- One `LinuxServer` runs a single io_uring ring; `runThreaded` is the loop.
- `ClientId` is already shard-keyed: `{ shard: u12, slot: u20, gen: u32 }`
  (shard is always 0 today).
- Lock-free primitives exist: `substrate/queue.BoundedMpmc` (MPMC) + `Spsc`.
- Socketless subsystems are already thread-agnostic: `crypto/tls_server`,
  `tls_conn`, the codecs, CRDT/coilpack, `proto/*` parsers — they own no global
  state and can run on any reactor thread unchanged.

## Foundation (landed — all support modules done + tested)

- `src/daemon/shard.zig` — `assignShard` (round-robin connection→shard pinning),
  `shardOf`/`isLocal` (lifetime pinning), `shardForChannel` (FNV-1a channel
  home), `Mailboxes(Msg, num_shards, capacity)` — per-shard lock-free inboxes
  over `BoundedMpmc` (`sendTo` any thread, `drain` by the owning reactor).
- `src/substrate/rwlock.zig` — writer-preferring spin `RwLock` (contention-tested).
- `world.zig` — `World` carries that lock + `lockRead`/`lockWrite` API
  (contention-tested); uncontended single-reactor cost is a couple of atomics.
- `src/daemon/sharded_table.zig` — `ShardedTable(Value)` over N `client.Table`
  slabs routed by `ClientId.shard`; `allocOn`/`get`/`free`/`shardTable`.
- `src/daemon/reactor_wake.zig` — eventfd cross-reactor wakeup; `WakeSet(N)`.
- `src/daemon/deliver_handle.zig` — pooled refcounted `DeliverBuf`/`DeliverPool`
  + `DeliverMsg{buf,target}` for cross-reactor outbound handoff.
- `services`/`scram_store`/`certfp_bind`/`sessions` — each carries the `RwLock`
  (mutators write-locked incl. allocation, readers read-locked); concurrency-tested.

Every primitive the capstone needs now exists, green and tested. NOTE the
borrowed-slice caveat: read-locked getters that return store-owned slices
(e.g. `accountForCertfp`) are valid only under the held lock — the reactor call
sites must consume before releasing.

## Capstone (remaining — the one serial, coupled piece)

The reactor rewire of `server.zig` cannot be parallelized (it IS the coupled
core). Concrete steps, building on the modules above:
1. Restructure `LinuxServer` so each shard owns its own `RingCore` + a
   `ShardedTable` slice + a `ReactorWake`; `runThreaded` spawns one thread per
   shard running `runOnce` on its own ring. `num_shards = 1` stays the current
   single-loop fast path.
2. Accept: SO_REUSEPORT listener per shard (kernel load-balances) — or one
   accept thread handing fds out by `assignShard`. Stamp `ClientId.shard`.
3. `ringlane.Ring` needs a `submitRead`/poll SQE + completion variant for the
   wake fd (the one ring gap the reactor_wake agent flagged); each reactor arms
   a read on its `ReactorWake.fd()` and `drain()`s on completion, then drains its
   mailbox.
4. Bracket command processing with `world.lockWrite()` (coarse Phase-B option 1);
   move to per-channel `shardForChannel` ownership later if profiling demands.
5. Cross-shard delivery: `broadcastChannel`/`deliver` to a member on another
   shard → `DeliverPool.acquire(bytes)` + `Mailboxes.sendTo(member.shard, msg)`
   + `WakeSet.wake(member.shard)`; the target reactor drains, appends to the
   local conn send buffer, and `release`s the buffer. Local members stay direct.
6. A two-reactor cross-shard smoke test: a channel spanning both shards, a
   PRIVMSG crossing shards, assert delivery + no races (run under tsan if avail).

## Remaining arc (sequenced)

### Phase A — per-shard reactors, independent connections
- N listeners via `SO_REUSEPORT` (kernel load-balances accepts), or one accept
  thread that hands fds to shards by `assignShard`.
- Each worker owns its own `RingCore` + a shard-local `ClientTable` slice, keyed
  by `ClientId.shard`. Per-connection state (recv/send buffers, `TlsConn`,
  `MultilineState`) stays entirely on its owning reactor — no locks.
- The timeout sweep + accept arming run per shard.

### Phase B — thread-safe world projection (the gating sub-arc)
The world (channels, nick registry, memberships) is global and read/written by
every connection. Options:
1. **Single shared world behind a lock** (RwLock): simplest; correctness first,
   then measure contention. Channel ops take the write lock; lookups take read.
2. **Sharded world** keyed by `shardForChannel`: each channel lives on one
   reactor; cross-shard membership handled by message passing. Lower contention,
   much more complex (a user on shard 1 in a channel homed on shard 3).

Start with (1) — a global `world_lock` around `world.zig` mutations — to unlock
real multithreading, then move hot paths to (2) if profiling demands it.

### Phase C — cross-shard delivery
Channel broadcast and direct delivery to a connection on another reactor go
through `shard.Mailboxes`: the sender enqueues a `Deliver{ to: ClientId, buf
handle }` to the target shard; the target reactor drains its inbox each loop
iteration and writes to the local connection's send buffer. Buffer ownership
crosses threads via a pooled/refcounted handle (no borrowed slices). Wake the
target reactor via an eventfd/`io_uring` msg-ring so it drains promptly.

### Phase D — shared subsystems
Account store, SCRAM/certfp bind stores, services, WAL: guard with their own
locks or make them per-shard-with-merge. SASL/account ops are infrequent vs.
message delivery, so a coarse lock is acceptable initially.

## Constraints / invariants
- Keep the single-thread path working (num_shards = 1 must be a no-op fast path).
- `ClientId.shard` is authoritative; never touch a connection from a non-owning
  reactor — route through a mailbox.
- No `std.Thread.Mutex` in the hot path; prefer the lock-free queues + the
  existing `lockSpin` tryLock pattern for the few coarse locks.
- Every phase ships green: `zig build test`, `-Dtarget=x86_64-windows`, and a
  multi-reactor smoke test (two reactors, a channel spanning both, a PRIVMSG
  crossing shards).

---

## Authoritative model (the correct design — supersedes the sketch above)

This is the contract the implementation is built to. It is genuinely concurrent:
the giant-lock-around-every-completion approach is explicitly **rejected** — it
serializes the hot path and gives no real scaling. Instead concurrency comes from
two places: (1) per-connection I/O + TLS runs lock-free on the owning reactor,
and (2) the read-heavy world path (message delivery, WHO/WHOIS/NAMES/LIST) runs
under a *shared read lock*, so many reactors deliver concurrently; only the
minority of structural mutations serialize behind the write lock.

### A. Connection ownership — fully parallel, zero locks
- N reactor threads; each owns its own `RingCore` + `ClientTable` slab + wake fd
  (the `Reactor` struct). A connection is pinned to one shard for life
  (`ClientId.shard`). All per-connection state — recv/send buffers, `TlsConn`,
  `MultilineState`, line parsing — lives on the owning reactor and is touched by
  no other thread. This is where the CPU-heavy work (TLS, parsing) parallelizes.
- **Accept:** `SO_REUSEPORT`. Each reactor binds the same `(host, port)` with
  `SO_REUSEPORT | SO_REUSEADDR` and accepts on its own socket; the kernel
  load-balances new connections across the listening sockets. No accept thread,
  no cross-thread fd handoff. Each reactor stamps its own `shard_id` into the
  `ClientId` it allocates.
- **Thread-local current reactor:** `threadlocal var current_reactor: ?*Reactor`,
  set once at each reactor thread's loop entry. `LinuxServer.rx()` returns it.
  Every handler reaches its ring/table via `self.rx().ring` / `self.rx().clients`
  — shard-correct with **no handler signature changes**. (`num_shards == 1`
  leaves `current_reactor` pointing at the single embedded reactor; uncontended.)

### B. Shared world — lock-free RCU with epoch-based reclamation
The world (channels, nick registry, memberships) is shared, but **reads never
block and never take a lock** — the fastest possible hot path, since delivery is
the hot path. This is the chosen model ("better everything", no settling).

- The world is an **immutable, structurally-shared snapshot** published behind a
  single atomic root pointer. Readers `load(.acquire)` the current root and
  traverse it with no lock; the snapshot they hold can never mutate underneath
  them. Writers build a new version (copy-on-write of only the affected path —
  cheap via structural sharing) and `store(.release)` it as the new root.
- Safe memory reclamation is **epoch-based (EBR, `substrate/ebr.zig`)**: a reader
  pins itself into the current epoch for the duration of a read (a single relaxed
  store), so a writer that has replaced a node may not free the old version until
  every reader that could still hold it has passed an epoch boundary (the grace
  period). No reader ever observes a freed node; no node is freed while reachable.
- `command_class.accessClass` selects the side:
  - **read** (`PRIVMSG`/`NOTICE`/`TAGMSG`, `WHO`, `WHOIS`, `NAMES`, `LIST`,
    `ISON`, `CHATHISTORY`, …) → lock-free read under an EBR guard. Fully
    concurrent across all reactors.
  - **write** (`JOIN`, `PART`, `NICK`, `QUIT`, `MODE`, `KICK`, `TOPIC`, `KILL`,
    account/oper/IRCX mutations, …) → write side: serialize writers (a single
    write-side mutex among the few mutators, or a dedicated writer thread fed by
    an MPSC of write ops), copy-on-write the affected subtrees, publish the new
    root, and `retire` the replaced nodes to the EBR domain for deferred free.
  - **unknown → write** (safe default).

### B′. World data structure — persistent HAMT (`substrate/persistent_map.zig`)
The world maps (channel-name → channel, nick → client, channel → member set) are
**persistent hash array-mapped tries**: immutable, with O(log₃₂ n) path-copy
writes that share all untouched structure with the prior version. This is what
makes copy-on-write publication cheap enough for the write path and gives readers
a genuinely immutable snapshot to traverse lock-free. Old path nodes from a
superseded version are `retire`d to EBR. Channel member sets are themselves
persistent sets so a JOIN/PART copies only one root-to-leaf path.

### C. Cross-shard delivery — lock-free fabric
- `reactor_fabric.ReactorFabric`: shared, runtime-sized to `num_shards`. Holds one
  MPMC mailbox + one `ReactorWake` eventfd per shard, plus one shared
  `DeliverPool`. This is the live counterpart of `cross_shard_smoke.zig`.
- Delivering bytes to a client on shard `S`:
  - `S == my shard` → direct append to the local conn's send buffer (the only
    reactor that owns it), arm send. No lock, no copy.
  - `S != my shard` → `pool.acquire(bytes)` → `fabric.sendTo(S, .{to,buf})` →
    `fabric.wake(S)`. The target reactor's wake-poll completion drains its
    mailbox, looks the client up in *its* local table, appends + arms send, and
    `release`s the buffer. Send buffers are never touched cross-thread.
- Reading the membership/target set is a world **read**; the byte handoff above is
  reactor-local or lock-free — so a read-locked `PRIVMSG` fan-out never blocks
  another reactor's read-locked fan-out.

### D. Shared stores
- `services`/`scram_store`/`certfp_bind`/`sessions` keep their own `RwLock`s
  (also reached by the media pump threads); SASL/account ops are rare vs delivery.
- Other stores (history, monitor, whowas, metadata, props, access, warden, …)
  migrate to the same RCU discipline as they become hot, or sit behind their own
  leaf lock until then. They are never on the message-delivery hot path.

### E. Module boundaries (parallelizable leaf files vs. the serial core)
New, self-contained substrate files (built in parallel, no `server.zig` edits):
- `substrate/ebr.zig` — epoch-based reclamation: `Domain`, reader `Guard`/pin,
  `retire(ptr, free)`, grace-period collect. The foundation of the whole model.
- `substrate/persistent_map.zig` — persistent HAMT (immutable map with O(log n)
  path-copy writes + structural sharing) backing the RCU world snapshots.
- `reactor_fabric.zig` — the shared cross-shard delivery fabric (C). Runtime-sized.
- `reuseport.zig` — `createReusePortListener(host, port, backlog)` (A, accept).
- `command_class.zig` — pure `accessClass(command) -> .read | .write` (selects the
  RCU read side vs write side). **Done, green.**

The serial coupled core (one owner, no parallelism) is the `server.zig` + `world`
rewire: extract `Reactor`, add `rx()` + `threadlocal current_reactor`, spawn one
thread per shard in `runThreaded`, bind per-reactor `SO_REUSEPORT` listeners,
stamp `shard_id`, rebuild `world.zig` as an RCU snapshot over the persistent HAMT
(lock-free reads under an EBR guard, copy-on-write+publish+retire writes), and
route off-shard deliveries through the fabric.

### Invariants
- `num_shards == 1` is a no-op fast path (single embedded reactor, lock
  uncontended, fabric unused).
- `ClientId.shard` is authoritative; never touch a connection from a non-owning
  reactor — always route through the fabric.
- World reads are lock-free under an EBR guard; the only serialization is among
  the (minority) writers. No reader ever blocks, ever takes a lock, or ever
  observes a freed node.
- An EBR reader guard is held only across the in-memory read + delivery enqueue —
  never across a blocking syscall or an io_uring submit/wait (that would stall the
  grace period and starve reclamation).
- Writers never block on readers (publication is a single atomic store; freeing is
  deferred to the grace period), so a slow reader can never deadlock a writer.

---

## world.zig RCU adoption map (the serial integration)

`world.zig` is the coupled heart: ~80 methods, already RwLock-guarded, holding the
full channel record (modes, key, limit, bans/exempts/invex/mutes, forward,
throttle, topic, OID, per-member modes, invites) plus the nick registry and
memberships. A wholesale rewrite of all of it is neither necessary nor wise. The
RCU win is on the **delivery hot path**, so adoption is surgical:

**Goes lock-free (read-class, RCU registries — `world_rcu.zig`):**
- `findNick` (nick → ClientId), `nickOf` (id → nick) — nick registry.
- `channelExists`, channel lookup, `resolveMessageTarget` — channel registry.
- `isMember`, `memberIterator`/member fan-out, `memberCount`, `channelsOf` —
  membership sets.
These are what PRIVMSG/NOTICE/TAGMSG/WHO/NAMES/WHOIS hit; they become loads of the
published snapshot under an EBR guard — no lock.

**Stays write-serialized (write-class, infrequent), publishing into the RCU index:**
- `registerNick`/`unregisterNick`, `join`/`part`/`removeClient` — mutate the
  registries via copy-on-write + publish + retire (so the reads above stay lock-free).
- Channel-state mutators (`setChannelFlag`/`setChannelKey`/`setChannelLimit`,
  ban/exempt/invex/mute add/remove, `setTopic`, `setMemberMode`, `addInvite`,
  throttle, `renameChannel`/`cloneChannel`) — the channel *record* itself stays a
  heap object reached via the channel registry; its fields are mutated under the
  writer path. (Rich per-channel state can migrate to per-field RCU later if a
  single hot channel's mode churn ever shows contention — it does not today.)

**Net:** delivery — the only path that runs on every message on every reactor —
reads with no lock; structural changes (join/part/nick/mode) serialize among the
few writers and publish atomically. This is the surgical adoption that lands the
RCU benefit without rewriting 80 methods, and it is the serial step gated on
`rcu_map.zig` + `world_rcu.zig` landing verified.
