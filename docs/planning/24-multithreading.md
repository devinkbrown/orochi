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

## Foundation (landed)

`src/daemon/shard.zig` — the pure, tested core:
- `assignShard(accept_seq, num_shards)` — round-robin connection→shard pinning at
  accept (the only input available before a slot is allocated).
- `shardOf(id)` / `isLocal(id, shard)` — a connection is pinned for life.
- `shardForChannel(name, num_shards)` — deterministic FNV-1a channel home, for a
  future channel-owning model.
- `Mailboxes(Msg, num_shards, capacity)` — per-shard lock-free inboxes over
  `BoundedMpmc`; `sendTo(shard, msg)` from any thread, `drain(shard, out)` by the
  owning reactor only. `Msg` must be thread-portable (owned/handle types, never a
  slice into another shard's memory).

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
