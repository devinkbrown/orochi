# 10 — I/O & threading model (single- and multi-threaded, awesome at both)

> Deepens [06-threading.md](06-threading.md) with current (2025–26) prior art.
> Mandate: redesign now to avoid bad decisions; one code path that is excellent
> **single-threaded** (deterministic sim, small/edge deployments) AND scales
> **share-nothing thread-per-core** to many cores — no rewrite between them.
> Everything behind the DST `Reactor` seam.

## 0. Prior art (what we adopt)

- **Thread-per-core, share-nothing** (Seastar → ScyllaDB/Redpanda; Glommio): pin
  one thread per core, partition state by shard, **no shared mutable state on the
  hot path**, communicate by message passing. Wins cache locality + tail latency;
  cross-core access is a ~100× penalty vs local cache. ([seastar], [glommio])
- **Glommio's 3-ring-per-thread**: a *main* ring, a *latency* ring, and a *poll*
  ring per executor → QoS separation without locks. ([glommio])
- **Work-stealing vs TPC debate (2025):** TPC is best for homogeneous I/O-bound
  work and predictable tails; work-stealing wins for *heterogeneous, CPU-heavy*
  tasks where a shard can be stuck behind one fat task. The right answer is
  **both, layered** (below). ([tpc-debate], [tpc-tail])
- **LMAX Disruptor / single-writer principle / mechanical sympathy**: array-backed
  ring buffers, lock-free, **single writer per datum** to avoid cache-line
  contention; "any serializable domain = one writer with an MPSC queue in front."
  ~3 orders of magnitude lower latency than locked queues. ([disruptor], [single-writer])

## 1. The model: shards over a Reactor seam

```
Server = N Shards.   N=1 ⇒ single-threaded.   N=cores ⇒ thread-per-core.
Each Shard owns:  one Reactor (io_uring set) · its connections · its slice of
                  world state · its CRDT replica view · its timers.
Shards never touch each other's memory. They exchange MESSAGES only.
```

- **The exact same protocol/handler code** runs whether N=1 or N=64. Sharding is a
  *deployment dial*, not a code fork. The single-thread path is not a degraded
  mode — it is N=1 with the message bus short-circuited to direct calls.
- **`Reactor` is the seam.** Production = `IoUringReactor` (Linux) / `KqueueReactor`
  (BSD) / `IocpReactor` (Windows). Tests/sim = `SimReactor` (cooperative, virtual
  clock, deterministic) — see [Ryūsen transport](09-s2s-protocol.md §Ryūsen).
  Single-thread + SimReactor = fully deterministic record/replay.

## 2. Per-shard reactor (the hot path) — zero locks

- One io_uring per shard, **Glommio-style multi-ring** mapped to our bands:
  - *control ring* — accept, control/membership frames, timers (lowest latency).
  - *bulk ring* — IRC events, anti-entropy, regular send/recv.
  - *poll ring* — NAPI busy-poll / SQPOLL for the latency-critical sockets.
- **io_uring features**: multishot accept/recv (fewer syscalls), registered
  files + buffers, **SEND_ZC** + ZC-Rx (zero copy), batched `submit()`,
  optional SQPOLL. Already partly live (accept/recv/send); ZC is the upgrade.
- **Single-writer everywhere**: every connection and every owned datum has exactly
  one owning shard → its handler is the sole writer → no atomics on the hot path,
  no false sharing. Per-shard structs are **cache-line aligned**; the conn table
  is pre-reserved (already done — prevents realloc moving in-flight buffers).

## 3. Cross-shard communication — messages, not memory

- **Linux fast path: `IORING_OP_MSG_RING`** — post a completion directly into
  another shard's ring (kernel ring→ring), no eventfd, no shared queue, no lock.
  Cross-shard delivery becomes "submit an SQE to peer's ring."
- **Portable path / fallback: bounded MPSC ring per shard** (Disruptor discipline:
  array-backed, single-consumer = the owning shard, producers are other shards),
  with a futex/eventfd wake only when the consumer is parked.
- **State ownership rule** (single-writer at the system level):
  - **Connections** → owned by the shard that accepted them (SO_REUSEPORT fans
    accepts across shards; or accept-on-one + handoff via MSG_RING).
  - **Channels/world entities** → a **home shard** = `hash(channel) % N`. A
    PRIVMSG to a non-local channel is a message to its home shard, which fans out
    to local members and forwards to other shards holding members. No shared
    channel struct, ever.
  - **CRDT** → each shard is a Suimyaku replica lane; cross-shard convergence uses
    the *same* δ-CRDT/Goryu-Sync machinery as cross-node (one model, intra- and
    inter-process). Shards are in-process mesh peers.

## 4. The hybrid: TPC hot path + work-stealing offload pool

The 2025 critique of pure TPC is real: a single fat task (TLS/X-Wing handshake,
RIBLT decode, media transcode, BLAKE3 over a large object) can stall a shard and
spike tail latency. Mizuchi answer:

- **Hot reactors stay strictly thread-per-core** (I/O, parsing, routing, CRDT
  joins — all short, homogeneous, cache-local).
- **A separate, small work-stealing pool** (`Forge`) handles **CPU-heavy,
  latency-tolerant, off-path** jobs: handshake KEMs, batch signature verify,
  RIBLT peeling, media encode/decode, history (Bao) hashing. A shard *submits* a
  job and gets the result back via MSG_RING — it never blocks.
- This composes the best of both: TPC's locality/tails on the hot path,
  work-stealing's elasticity for heterogeneous compute. (Glommio similarly keeps
  a latency ring separate from bulk.)

## 5. Single-threaded excellence (N=1)

- N=1 short-circuits the message bus to **direct function calls** (no MSG_RING, no
  MPSC) → zero cross-shard overhead; the daemon is a tight single io_uring loop.
- The `Forge` pool can be size-0 (inline) in N=1, or a couple of helper threads
  for crypto/media even in single-shard mode (the only threads), so a 1-core box
  still doesn't stall on a handshake.
- SimReactor + N=1 = the Deterministic Ocean: same handlers, virtual clock,
  reproducible. This is the *primary test substrate*.

## 6. Backpressure, NUMA, fairness

- **Credit-based flow control** end to end (already in `peer_link`): clients soft-
  throttle→disconnect; S2S negotiates credit; cross-shard messages are credited so
  a hot shard can't flood a slow one.
- **NUMA-aware**: shard→core pinning respects NUMA nodes; per-shard allocators
  (no cross-node allocation on the hot path); registered buffers per NUMA node.
- **Fair scheduling within a shard**: weighted-deficit round-robin across bands
  (control > membership > anti-entropy > events > media-ctrl > bulk media), so
  bulk/media never starve control.

## 7. Build order (matches "core infra first")

1. Keep the current single io_uring loop; formalize the **`Reactor` seam** so
   SimReactor and IoUringReactor are interchangeable (extend beyond clock to
   accept/recv/send/timer). *(largely present; finish the seam.)*
2. Introduce the **Shard** abstraction with N=1 (direct-call bus) — no behavior
   change, but the ownership model + home-shard routing exist.
3. Add `Forge` work-stealing offload for handshake/crypto/RIBLT/media (helps even
   N=1).
4. Multi-shard: SO_REUSEPORT accept fan-out + **MSG_RING** cross-shard bus;
   home-shard channel routing; per-shard CRDT lanes converging via Goryu-Sync.
5. QoS multi-ring per shard + SEND_ZC/ZC-Rx; NAPI/SQPOLL tuning.

## Sources
- Seastar shared-nothing — https://seastar.io/shared-nothing/
- Glommio (3 rings/thread, TPC on io_uring) — https://www.datadoghq.com/blog/engineering/introducing-glommio/ ; https://github.com/DataDog/glommio
- Thread-per-core vs work-stealing — https://without.boats/blog/thread-per-core/ ; tail latency — https://ieeexplore.ieee.org/abstract/document/8901874
- LMAX Disruptor — https://lmax-exchange.github.io/disruptor/disruptor.html ; single-writer principle — https://mechanical-sympathy.blogspot.com/2011/09/single-writer-principle.html
- io_uring MSG_RING / zero-copy — https://docs.kernel.org/networking/iou-zcrx.html

[seastar]: https://seastar.io/shared-nothing/
[glommio]: https://www.datadoghq.com/blog/engineering/introducing-glommio/
[tpc-debate]: https://without.boats/blog/thread-per-core/
[tpc-tail]: https://ieeexplore.ieee.org/abstract/document/8901874
[disruptor]: https://lmax-exchange.github.io/disruptor/disruptor.html
[single-writer]: https://mechanical-sympathy.blogspot.com/2011/09/single-writer-principle.html
