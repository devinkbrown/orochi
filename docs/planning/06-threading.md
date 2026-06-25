# 06 — Threading and concurrency

*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

This document records the threading model derived from ophion/libop and the io_uring-native, DST-first, mesh-native design the M1→M3 server builds toward.

## What ophion/libop does

| Area | Reference behavior |
| --- | --- |
| Dedicated epoll poll-thread (`op_iothread.h`) | Because `epoll_wait()` blocks, ophion runs it on its own thread that pushes ready events into a lock-free SPSC ring and wakes the main thread via eventfd. The main thread dispatches handlers and fires timers concurrently with the next `epoll_wait`. This is a *workaround for epoll's blocking nature*. |
| Work-stealing thread pool (`op_thread_pool.h`) | N workers, each a chase-lev deque + a per-worker MPSC Treiber-stack inbox; lock-free submit, affinity submit (`key → worker`), steal from random peers, eventfd wake. CPU-heavy work is offloaded here off the main dispatch thread. |
| Net effect | One central protocol/dispatch thread + a poll thread + an offload pool. The single dispatch thread is the structural bottleneck; sharing of client state is guarded by per-fd `pflags_lock`. |

## Why Orochi can do better

- **io_uring is already async.** Submit/complete + multishot accept/recv +
  `IORING_OP_MSG_RING` mean we never block in a "poll" call the way `epoll_wait`
  does. So Orochi **needs no separate poll-thread** — that whole layer disappears.
- **Share-nothing sharding beats a central dispatch thread + locks.** One central
  protocol thread is a bottleneck and forces `pflags_lock`. Instead, partition the
  world: each shard owns a disjoint set of connections and the channels/state for
  those connections, so the hot path takes **zero locks**.
- **Mesh-native cross-shard.** A channel whose members span shards is the same
  problem as a channel spanning servers — Orochi already has the Suimyaku CRDT +
  Sazanami gossip. Shards can be treated as in-process mesh peers, so one model
  covers intra-process and S2S. (Aspirational end-state; the message-passing
  primitive is the immediate win.)
- **DST-first must survive.** All of this stays behind the `Reactor` seam: tests run
  the whole daemon on one deterministic thread via `SimReactor`; production uses the
  threaded io_uring backend. Determinism is not sacrificed for parallelism.

## Orochi design: share-nothing sharded reactors

```text
            ┌──────── Shard 0 ────────┐   ┌──────── Shard 1 ────────┐
 thread 0   │ io_uring  +  owned conns│   │ io_uring  +  owned conns│   thread 1
            │ owned channels/world    │   │ owned channels/world    │
            │ reactor loop (no locks) │   │ reactor loop (no locks) │
            └────────────┬────────────┘   └────────────┬───────────┘
                         │  cross-shard delivery via    │
                         └──── IORING_OP_MSG_RING ───────┘  (kernel ring→ring wake)
```

1. **Connection→shard** by consistent hash of the accepted fd / connection id. A
   connection lives on exactly one shard for its lifetime (no migration on the hot
   path; migration only on `/UPGRADE` snapshot, which is already a cold path).
2. **Per-shard ownership**: the `World` (nicks/channels/membership/modes) is sharded.
   Channels are shard-local when all members are on one shard (the common case).
3. **Cross-shard delivery**: when a shard must deliver bytes to a conn owned by
   another shard, it enqueues a delivery message and wakes the target shard with
   `IORING_OP_MSG_RING` (kernel-native ring→ring; no eventfd, no userspace lock on
   the wake path). The target shard drains its inbox in its own loop and writes to
   its conn. Inbox is a bounded MPMC ring (substrate/queue.zig lineage).
4. **Shared channel state across shards** uses the Suimyaku delta-CRDT + Sazanami
  membership — the same code as S2S. A shard is, conceptually, a mesh node.
5. **No background "offload pool" by default.** CPU-heavy one-offs (PBKDF2 on SASL,
   ML-KEM keygen) run on a small bounded helper pool only for genuinely blocking/
   expensive work, kept off the reactor threads; everything else stays on-shard.
6. **Backpressure**: per-conn send credit (already in the frame layer) + bounded
   inbox rings; a slow consumer cannot stall a producer shard (drop-to-close policy).

## Reactor seam contract (the testability keystone)

- `Reactor` already abstracts `nowMillis`; extend it to the full submit/poll surface
  (accept/recv/send/timeout/msg_ring) so daemon logic never touches a syscall.
- `SimReactor`: single-thread, deterministic, injected clock/RNG/network — runs all
  shards cooperatively in one thread for tests (seed-replayable). This is how the
  end-to-end command tests run without real threads or sockets, fixing today's
  single-thread blocking-io_uring deadlock in the in-process tests.
- `SystemReactor`: the threaded io_uring backend above.
- One shard count of **1** must behave identically to N (just slower) — invariant
  for tests.

## Migration plan (incremental, each step verifiable)

- **T0 (now):** single LinuxServer reactor loop; in-process socket tests deadlock
  (one thread can't be both server and client). ← current state.
- **T1:** run the reactor loop on a dedicated `std.Thread`; add an in-process
  end-to-end test (test thread = loopback client, server thread = reactor). This
  alone re-enables run-verified testing of the whole command surface. *(next step)*
- **T2:** extend the `Reactor` seam to the full I/O surface; route `LinuxServer`
  through it; add `SimReactor` cooperative multi-shard execution → deterministic
  end-to-end tests with no threads/sockets.
- **T3:** N shards, share-nothing, connection→shard hashing; per-shard World.
- **T4:** cross-shard delivery via `IORING_OP_MSG_RING` + bounded MPMC inboxes.
- **T5:** unify cross-shard channel state with Suimyaku/Sazanami (shards as mesh
  nodes); the bounded helper pool for PBKDF2/ML-KEM.

## Invariants
- Hot path is lock-free (share-nothing); only cold paths (upgrade/migration) move
  conns between shards.
- Determinism: shard-count-1 == shard-count-N in observable behavior; SimReactor
  reproduces any run from a seed.
- No epoll-style poll-thread: io_uring multishot + MSG_RING replace it.
