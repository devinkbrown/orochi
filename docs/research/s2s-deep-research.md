# S2S Deep Research — algorithms, math, crypto, transport (reference)

> Captured 2026-06-05. Reference corpus for Orochi's clean-room S2S linking
> protocol ([../planning/09-s2s-protocol.md](../planning/09-s2s-protocol.md)).
> Mandate: extremely state-of-the-art, verifiable, secure, media-ready,
> no technical debt, sovereign `node_id` identity (no SID). Every technique below
> is evaluated for "do we adopt, adapt, or reject," and Part V synthesizes them
> into a novel Orochi design.

---

## Part I — Reconciliation & CRDT algorithms (the convergence math)

### I.1 Set reconciliation — the core anti-entropy problem
Two replicas hold sets A, B of fixed-length keys; compute the symmetric
difference A△B with communication ∝ |A△B|, *not* |A| or |B|.

**Rateless IBLT (RIBLT) — Yang/Gilad/Alizadeh, SIGCOMM 2024 — ADOPT (headline).**
- A *rateless* encoder maps the set difference into an **infinite stream of coded
  symbols** (like a fountain/rateless erasure code). The receiver pulls symbols
  until it can **peel** the IBLT and recover A△B.
- **No prior estimate** of the difference size is required (the killer property:
  classic IBLT needs you to size the table to the expected diff; RIBLT does not).
- Near-optimal communication across diffs from 1 to millions, element sizes from
  bytes to MB, and adversarial workloads. Low CPU. Go/Rust impls exist (riblt,
  riblet, rateless_iblt).
- *Math:* each coded symbol XOR-aggregates a pseudo-random subset of elements
  (mapping degrees follow a carefully chosen distribution so the peeling decoder
  succeeds just past `|A△B|` symbols w.h.p.). Decoding = repeatedly find a
  degree-1 cell, peel it, cascade — same idea as LT/Raptor code peeling.
- 2025 follow-on: **Rateless Bloom Filters (RBF)** for divergent replicas with
  variable-sized elements (no parametrization, matches an optimally-tuned BF).

**Range-Based Set Reconciliation (RBSR) / ConflictSync — ADAPT (coarse pass).**
- Recursively compare **fingerprints of contiguous ranges** of an ordered set;
  matching ranges are skipped, mismatching ranges split until the actual missing
  items fall out. Bandwidth ∝ difference. Used by anti-entropy/p2p sync.
- ConflictSync: digest-driven sync for state-based CRDTs reducing to set
  reconciliation of **irredundant join decompositions** (only ship join-irreducible
  deltas).

**Verdict:** RIBLT is the fine-grained reconciler (bandwidth ∝ diff, rateless,
no size oracle); a prolly/Merkle-search index (I.3) gives the coarse "where do we
differ" in O(log n) and content-addressed dedup. Merkle stays the integrity root.

### I.2 Delta-state CRDTs (δ-CRDT) — ADOPT
- Almeida/Shoker/Baquero. δ-mutators emit **small delta-states** (not full state);
  join (⊔) is a **commutative, associative, idempotent** semilattice operation →
  convergence regardless of order, loss, or duplication.
- Anti-entropy ships deltas (or delta-groups) and joins them; **causal δ-CRDTs**
  keep a join-decomposition so only join-irreducible pieces move.
- Lattice discipline = our correctness proof obligation: every entity is a
  bounded join-semilattice; resolution is its join.

### I.3 Prolly trees / Merkle Search Trees (MST) — ADOPT (the index)
- **Prolly tree** = B-tree ⊕ Merkle tree: node fan-out chosen **probabilistically
  from a rolling hash of content** (content-defined chunking) → the tree shape is
  a deterministic function of the *set*, **history-independent**: two replicas with
  the same key/value set have the **same tree and same root hash**.
- Therefore divergence is located in **O(log n)** by walking down where subtree
  hashes differ, and unchanged subtrees are skipped wholesale ("merkle syncing").
- **MST variant:** place each item at level = number of leading 0s in its hash →
  deterministic balanced Merkle B-tree (used by ATProto/BlueSky; prolly by Dolt).
- Content-addressed nodes → structural sharing + dedup across versions (Git-like).

### I.4 Hybrid Logical Clocks (HLC) — ADOPT (causal stamping)
- Kulkarni/Demirbas. Timestamp = `(l, c)`: `l` tracks max(physical time, max
  received `l`); `c` is a bounded counter incremented only when `l` is ambiguous,
  reset when `l` advances.
- **Captures causality (happens-before) like a logical clock** while staying within
  bounded drift ε of physical time → consistent snapshots, human-meaningful order.
- `|l − pt| ≤ ε`; `c` is bounded (resets regularly). Cheap (64-bit packable).
- Use: every CRDT delta carries `(origin node_id, hlc)`; LWW/MV resolution orders
  by `(hlc, node_id)`; never trust raw sender wall-clock (Matrix's lesson).

### I.5 Causal stability & tombstone GC (the math we must not get wrong)
- An update is **causally stable** once every live peer has observed it →
  observed-remove tombstones can be GC'd only after stability across the live set.
- Track per-peer "stability frontier" (min over peers of their version vector);
  GC below the frontier. Witnessed-SWIM defines "live set."

---

## Part II — Cryptography (verifiable + post-quantum)

### II.1 Hybrid KEM combiner — ADOPT **X-Wing pattern**
- Goal: a session key secure if *either* X25519 *or* ML-KEM-768 holds (PQ +
  classical belt-and-suspenders).
- **Naive `KDF(k1‖k2)` is NOT IND-CCA in general.** The fix (KEM-combiner result):
  mix the **ciphertexts** in too: `K = KDF(k1 ‖ k2 ‖ c1 ‖ c2 [‖ label])`. The KDF
  must be a **dual-PRF** (collision + 2nd-preimage resistant in each input
  independently).
- **SHA3/SHAKE is a dual-PRF; SHA2 is NOT** → SHA2 must be wrapped in HMAC/HKDF.
- **X-Wing** (`ML-KEM-768 + X25519`, SHA3-256 combiner) is IND-CCA under the
  strong-DH assumption (classical) and under ML-KEM-768 IND-CCA (PQ). This is the
  construction to copy. (IETF also: composite ML-KEM, TLS ecdhe-mlkem draft.)

### II.2 PQ-hybrid Noise handshake — ADOPT pattern, ADAPT mechanism
- Noise Framework (Perrin): predefined DH-based handshake patterns; **IK** =
  responder static key known to initiator, mutual auth, 1-RTT, initiator identity
  hidden until authenticated.
- **PQNoise** (Yawning Angel et al., CCS '22): post-quantum Noise variants;
  hybrid = classical pattern ⊕ PQ counterpart. Near-identical timing to classical
  under normal loss; PQ falls behind under high packet loss (bigger keys/cts).
- Orochi (**Tsumugi**): Noise-IK *shape* with the **X-Wing hybrid KEM** as the
  KEX primitive; static identity = the node Ed25519 key; transcript binds both
  `node_id`s + MeshPasses + realm root + negotiated bands (downgrade-resistant).

### II.3 Signatures & verifiability — ADOPT
- **Ed25519** for node identity, signed deltas, MeshPass tokens.
- **Batch verification** (Bos-Coster / Pippenger multi-scalar multiplication):
  ~2× throughput at batch 64; ~134k cyc/sig at 64, ~114k at large batches. Use for
  verifying bursts of signed deltas / gossip.
- Signing every delta makes relays untrusted: a peer verifies the **origin**
  signature, not the relay path (the verifiability invariant).

### II.4 Verifiable hashing & streaming — ADOPT **BLAKE3 + Bao**
- BLAKE3 is itself a Merkle tree (chunk leaves → parent compressions) → **verified
  streaming / random access**: with the root hash you can verify *any byte range*
  without rehashing the whole object (Bao / bao-tree encoding interleaves the file
  with its hash-tree nodes).
- Use for **history (Lotus) backfill**: stream/seek into channel history with
  per-range verification against a single root; also the hash for content-addressed
  prolly nodes and message ids.

---

## Part III — Dissemination & membership

### III.1 HyParView (Leitão et al., DSN'07) — ADOPT
- Two partial views: a small symmetric **active view** (size ~`log(n)+c`, the live
  links used for broadcast) and a larger **passive view** (reserve, refreshed by
  periodic shuffles). On failure, promote from passive → active in O(1).
- Robust to high churn; degree distribution + clustering give reliable coverage.

### III.2 Plumtree (Leitão et al., SRDS'07) — ADOPT
- Epidemic **broadcast tree** over the active view: **eager push** = full payload
  along tree edges; **lazy push** = gossip of message-id *digests* on non-tree
  edges. Missing id → `GRAFT` (heal/add tree edge); redundant eager delivery →
  `PRUNE` (shed). Steady-state = tree-efficient; churn = gossip-resilient.
- Orochi: lazy-push carries **RIBLT digests / dot ids**; eager-push carries the
  signed δ-CRDT deltas.

### III.3 Witnessed SWIM — ADOPT (our hardening)
- SWIM: direct ping → indirect `PING_REQ` to k random witnesses → SUSPECT
  (incarnation) → DEAD; piggybacked membership gossip.
- **Witnessed** variant (Orochi vision invariant): suspicion carries a **signed
  witness set**; transition to DEAD needs a **quorum** — no peer may declare
  another DEAD alone (Byzantine/flaky resistance).

---

## Part IV — Transport & OS technologies (state-of-the-art, per-OS)

### IV.1 Linux — io_uring data plane (primary)
- **IORING_OP_SEND_ZC** (zero-copy send): data goes user-mem → NIC, no CPU copy,
  with **registered buffers**; completion + notification (`F_NOTIF`) signal when the
  buffer is reusable. (Orochi already arms sends; ZC is the upgrade.)
- **io_uring ZC-Rx** (`IORING_RECV_MULTISHOT` + zero-copy receive): payloads land
  directly in userspace pages; headers still go through the kernel TCP stack
  (unlike DPDK). No mmap/alignment constraints (unlike `TCP_ZEROCOPY_RECEIVE`).
  L4 split: header→kernel, payload→user.
- **Multishot accept/recv**: one SQE yields many completions → fewer syscalls.
- **SQPOLL** (kernel poll thread) + **NAPI busy-poll** registration for lowest
  latency; **registered files/buffers** to cut per-op overhead.
- **AF_XDP** hybrid: kernel control plane + zero-copy Rx fast path; XDP/eBPF can
  pre-filter/steer before the stack. For extreme cases, full kernel bypass.

### IV.2 Linux — UDP/QUIC acceleration (for the datagram/media + QUIC future)
- **UDP GSO** (≥4.18): app hands one "super-buffer" of N×`gso_size` packets; kernel
  (or NIC) segments → up to 64 segments/batch, big syscall amortization. **UDP GRO**
  on Rx coalesces. Essential for QUIC throughput (Cloudflare/Tailscale: multi-×).
- **sendmmsg/recvmmsg** batch syscalls; **SO_REUSEPORT** for multi-queue accept
  fan-out across shards.
- **kTLS**: offload bulk record crypto to kernel (or NIC); enables `sendfile`/
  `splice` of encrypted data; combine with ZC.
- **In-kernel QUIC** (lxin/quic, kernel TLS handshake offload) is emerging; we ride
  userspace QUIC first, kernel later.

### IV.3 Linux — eBPF/XDP socket fast paths
- **SOCKMAP / SOCKHASH** + `sk_msg` / `bpf_msg_redirect_map`: **TCP splicing in the
  kernel** — redirect bytes socket→socket without userspace bounce (proxy/relay
  fast path). `bpf_sk_redirect_map` for skb steering. (Mind CVE-2025-39913 SOCKMAP
  UAF — pin kernel ≥ patched.)
- **XDP** at the driver/NIC for DDoS drop, steering, and sampling before the stack.

### IV.4 BSD
- **netmap** (Rizzo): userspace gets direct NIC ring access; ≥10× sockets; integrates
  with **kqueue**/select/poll. **PASTE** extends netmap for end-system TCP.
- **kqueue**: the BSD/macOS event core (our portable Reactor backend target).

### IV.5 Windows
- **RIO (Registered I/O)** + **IOCP**: pre-registered buffers + completion ports;
  polled / event / IOCP completion retrieval; polled mode for HFT-grade UDP.
- IOCP is the portable Reactor backend on Windows.

### IV.6 Alternative / future transports (evaluated)
- **Multipath QUIC** (draft-ietf-quic-multipath): multiple paths per connection,
  `PATH_ACK`, `initial_max_path_id`; resilience + aggregation; connection migration
  + 0-RTT. ADOPT as the eventual primary peer transport.
- **L4S + ECN** (RFC 9330/9331) with **scalable CC (TCP Prague / BBRv3)**:
  sub-ms queuing delay *and* high throughput. ADOPT-aware on the QUIC path.
- **Homa** (Ousterhout): receiver-driven, priority-based, message (not stream)
  transport; 7–83× lower tail latency than TCP/DCTCP in-DC. CONSIDER for
  intra-datacenter mesh links / RPC-shaped control.
- **Aeron**: reliable UDP unicast/multicast + IPC, ~18µs HW latency, >1M msg/s;
  proven reliability-over-UDP design. CONSIDER concepts for media bands / IPC
  between shards.
- **MASQUE / CONNECT-UDP**: proxying/relay for NAT'd or policy-restricted peers.

---

## Part V — Synthesis: the invented Orochi design

Two new named subsystems, each a deliberate fusion of the above:

### V.1 **Goryu-Sync** — verifiable rateless CRDT anti-entropy (novel combination)
The convergence engine = δ-CRDT ⊕ HLC ⊕ prolly-tree index ⊕ RIBLT ⊕ Ed25519:
1. **Dot model.** Every mutation is a signed dotted delta
   `dot = (node_id, hlc, op)`, content id `cid = BLAKE3(canonical CoilPack(op))`.
   Set element for reconciliation = the 32-byte `cid` (fixed-length → RIBLT-native).
2. **Index.** Live dot-cids live in a **prolly tree** (content-defined chunking,
   BLAKE3 node hashes). Same dot-set ⇒ same root ⇒ instant "are we equal?"; O(log n)
   divergence descent; structural sharing across versions.
3. **Coarse pass.** Peers exchange prolly **root hashes**; if equal, done (0 work).
   If not, descend mismatching subtrees to bound the diverging key ranges.
4. **Fine pass — rateless.** Over the diverging ranges, stream **RIBLT coded
   symbols** of the cid-set until the receiver peels out the symmetric difference
   — **no prior diff-size estimate**, bandwidth ∝ |A△B|, adversary-robust.
5. **Fill.** Fetch missing deltas by `cid` (content-addressed; verify hash on
   arrival), **batch-verify** their Ed25519 signatures (Bos-Coster), then δ-join
   into the local semilattice. Order-independent (CRDT), so loss/dup is harmless.
6. **GC.** Tombstones drop below the causal-stability frontier (min VV over the
   witnessed-live set).

*Why novel:* RIBLT (2024) gives rateless near-optimal diff; prolly trees give
content-addressed O(log n) location + dedup; δ-CRDT+HLC give order-free
convergence; Ed25519-signed cids make every byte independently verifiable. No IRC
daemon — and few systems anywhere — combine all five. Bandwidth ∝ actual change,
verification is end-to-end, and equal replicas cost a single hash compare.

### V.2 **Ryūsen** — the adaptive transport seam (OS-harnessing)
A single `Transport` interface behind the DST `Reactor` seam, picking the best
mechanism per platform/link at runtime:

| Platform | Control/IRC band (reliable) | Media/bulk band |
| --- | --- | --- |
| Linux | io_uring SEND_ZC + ZC-Rx multishot, registered bufs, SQPOLL, NAPI busy-poll; kTLS for bulk; SOCKMAP splice for pure relays | UDP GSO/GRO + pacing; AF_XDP fast path; QUIC datagrams |
| FreeBSD | kqueue + (optional) netmap rings | netmap + UDP GSO where available |
| Windows | RIO + IOCP (registered buffers) | RIO UDP, polled for low latency |

Cross-cutting: **Multipath-QUIC**-ready connection object (path set, migration,
0-RTT resume); **L4S/ECN-aware scalable congestion control** on the QUIC path;
**credit-based flow control** at the link (already in `peer_link`); **band
priority** = weighted deficit round-robin (control > membership > anti-entropy >
events > media-ctrl > bulk media). Media bands borrow **Homa** (receiver-driven
priority) / **Aeron** (reliable-UDP) ideas; loss on a media band never blocks
control (the MoQ/QUIC head-of-line lesson, pre-baked).

### V.3 Identity & security spine (already partly built)
- `node_id = BLAKE3-160(Ed25519 pubkey)` — single sovereign id (no SID). ✅
- **Tsumugi handshake** = Noise-IK shape + **X-Wing** hybrid KEM (X25519+ML-KEM-768,
  SHA3 dual-PRF combiner mixing ciphertexts) + MeshPass capability verify +
  downgrade-resistant signed transcript.
- Per-frame AEAD ratchet; AEAD-failure never advances counters; rekey on
  time/bytes/count with a drain window for reorder.
- **MeshPass** object-capability admission + revocation epoch.
- **Witnessed SWIM** quorum liveness; **signed deltas** end-to-end.

### V.4 Build order (core infra first, per mandate)
1. Tsumugi handshake (X-Wing + Noise-IK + MeshPass) wrapping the live `s2s_peer`
   byte path → secure+verifiable transport.  *(crypto primitives exist in `crypto/`.)*
2. Signed dotted deltas + cid content-addressing; batch-verify on apply.
3. Goryu-Sync: prolly index → RIBLT fine pass (replace naive burst).
4. Plumtree/HyParView multi-peer dissemination + witnessed SWIM.
5. World projection (CRDT membership → NAMES/WHO/routing) — first user payoff.
6. Ryūsen upgrades: io_uring SEND_ZC/ZC-Rx; then QUIC (UDP GSO + multipath) + media bands.

---

## Part VI — Other pathways (directions not in the first pass)

- **Eg-walker** (EuroSys'25) — op-based CRDT for **sequences/text** that stores a
  DAG of ops and computes state as a *query over the log* (≈ FugueMax; RGA/Fugue
  unify under it). Order-of-magnitude less steady-state memory, fast load/merge.
  → **ADOPT for ordered/threaded content** (CHATHISTORY threads, collaborative
  topics, future docs) instead of a heavyweight list CRDT. Pairs with the Lotus
  event DAG.
- **DAG-BFT (Narwhal/Bullshark/Shoal)** — separate **mempool DAG (Narwhal)** from
  **ordering (Bullshark)**; total order is *read off* the DAG with zero extra
  messages; Shoal adds leader-reputation + pipelining. → **ADAPT, narrowly:** we
  do NOT want global consensus for chat (CRDTs are coordination-free), but the
  Narwhal idea — *reliable causal broadcast as a DAG, ordering as a local function
  of edges* — is exactly our event-DAG model, and DAG-BFT is the fallback for the
  rare **totally-ordered** facts (realm governance: trust-root rotation, MeshPass
  revocation quorum) where Byzantine total order is actually required.
- **WebTransport (HTTP/3 over QUIC)** — client↔server streams+datagrams, no TCP
  head-of-line block, **survives IP change (migration)**. → **ADOPT as the modern
  browser transport alongside WebSocket** (keep WS for ubiquity; WebTransport for
  low-latency/media; WebRTC DataChannel only for P2P/voice). This is the browser
  half of "keep IRC + web, lay groundwork."
- **eBPF/USDT observability + flight-recorder ring buffers + deterministic
  record/replay** — overwriteable ring-buffer "tape recorder" of recent events;
  USDT probes for app-protocol tracing; deterministic replay from a recorded
  trace. → **ADOPT as the model for Orochi's debug/log spine** (§Part VIII): an
  in-process flight recorder + structured trace, DST-replayable.

## Part VII — Frontier tech (invention fuel)

- **Vector commitments / KZG / Verkle trees** — commit a vector via a degree-(n−1)
  polynomial; **openings are O(1)-sized** regardless of n; Verkle = Merkle with
  KZG → *dramatically smaller proofs*. → **WATCH / future:** could replace the
  prolly-tree Merkle proofs with constant-size membership proofs for ultra-cheap
  "prove this delta is in my state" — but needs pairing crypto (BLS12-381) we
  don't yet have; revisit when verifiable-state proofs matter.
- **IVC / folding schemes (Nova)** — incrementally verifiable computation: prove a
  long-running computation step-by-step; prover/verifier cost **independent of #
  steps** (verifier = 2 scalar-mults). → **INVENTION SEED:** a node could carry a
  *folding proof that its entire CRDT history was applied by the rules* — a joining
  peer verifies one constant-size proof instead of replaying/ trusting history.
  "Verifiable convergence." Long-horizon, but uniquely powerful for trustless
  backfill.
- **Keyhive / BeeKEM (Ink & Switch, 2025)** — **convergent capabilities** (CRDT
  state *as* the capability), a group-management CRDT with **coordination-free
  revocation**, and E2EE with **causal keys** (post-compromise security), syncing
  end-to-end-encrypted payloads a server can't read (Beelay). → **ADOPT the model
  for MeshPass + realm/channel auth:** make admission/roles a *convergent
  capability CRDT* (revocation converges without a coordinator) and enable
  **server-blind E2EE channels** as a future privacy tier. This is the strongest
  match to Orochi's "signed authority facts + rename-not-kill + sovereign keys."
- **RaptorQ fountain FEC (GF(256))** — generate unlimited repair symbols on the
  fly; receiver decodes from *any* k(1+ε) symbols → tolerates high loss without
  ARQ round-trips. → **ADOPT for media bands** (audio/video over the QUIC datagram
  path) and for **mesh burst dissemination over lossy links** (FEC the BURST so a
  joining peer needs no retransmit). Note the kinship: RaptorQ (rateless FEC) and
  RIBLT (rateless reconciliation) are the *same rateless idea* applied to loss vs.
  difference — a unifying design aesthetic for Orochi.
- **SmartNIC / DPU / P4 offload** — push parse/match-action/crypto to the NIC;
  P4-programmable dataplanes; RDMA-capable DPUs. → **WATCH:** Ryūsen's transport
  seam should keep an **offload hook** (e.g., kTLS→NIC, P4 steering) so a DPU
  deployment is a backend swap, not a redesign. Not core, but the seam must not
  preclude it.

**Cross-cutting invention thread — "everything rateless."** RIBLT (reconcile),
RaptorQ (transmit), Nova-style folding (verify): three rateless/streamed
primitives. A Orochi-original synthesis is a **single rateless pipe**: a peer
emits one coded stream that simultaneously (a) reconciles set difference, (b) is
FEC-protected against loss, and (c) carries a running convergence proof — the
receiver pulls until it has converged *and* verified, with bandwidth ∝ actual
divergence and zero round-trip negotiation. That unification is novel and worth a
design spike.

## Part VIII — Client surface & observability (per mandate)

**Keep IRC + web; groundwork for expansion.**
- **IRC line protocol** stays the primary client surface (IRCv3 + IRCX).
- **Browsers:** WebSocket today (Nexus/Ocean already use it) + **WebTransport**
  (HTTP/3) as the modern low-latency path; **WebRTC DataChannel** reserved for
  P2P voice/video. All three terminate at the daemon and map onto the same
  internal line/event model — the mesh/CRDT layer is client-surface-agnostic, so
  new surfaces (mobile push, WebTransport, future native) are additive.
- **Groundwork:** every client-visible fact (membership, modes, history) is a
  CRDT-portable, signed entity, so a new surface is a *renderer*, never a protocol
  fork.

**Heavy debugging + logging system (build now — see implementation).** Model =
eBPF flight-recorder + structured tracing + DST replay:
1. **Structured, leveled, categorized logging** (`debug`/`info`/`notice`/`warn`/
   `error`/`fatal` × subsystem category), key-value fields, monotonic + HLC
   stamped, cheap when disabled (comptime level gate).
2. **Flight recorder**: a lock-free overwriteable ring buffer of recent structured
   events (the "tape recorder") dumped on crash/`DIE`/oper command — last-N events
   even at log levels not printed.
3. **Per-subsystem runtime filters** + an oper `DEBUG`/trace command (Event-Spine
   gated) to live-tune verbosity and dump the recorder.
4. **DST-friendly**: the logger is a sink behind the Reactor seam; in the
   Deterministic Ocean sim the same event stream is the replay/record trace.

## Sources

Reconciliation/CRDT/clocks:
- Practical Rateless Set Reconciliation (RIBLT), SIGCOMM 2024 — https://arxiv.org/abs/2402.02668 ; impl https://github.com/yangl1996/riblt
- Rateless Bloom Filters for divergent replicas (2025) — https://arxiv.org/html/2510.27614
- Range-Based Set Reconciliation — https://arxiv.org/pdf/2603.19820
- Delta State Replicated Data Types — https://arxiv.org/pdf/1603.01529 ; δ-mutation https://arxiv.org/pdf/1410.2803
- Prolly trees — https://www.dolthub.com/blog/2024-01-ztree/ ; Merklizing the KV store — https://joelgustafson.com/posts/2023-05-04/merklizing-the-key-value-store-for-fun-and-profit/
- Hybrid Logical Clocks (Kulkarni/Demirbas) — https://cse.buffalo.edu/tech-reports/2014-04.pdf

Crypto:
- KEM combiners / X-Wing — https://eprint.iacr.org/2025/1444.pdf ; https://cryptojedi.org/papers/xwing-20240415.pdf ; IETF KEM combiners https://www.ietf.org/archive/id/draft-ounsworth-cfrg-kem-combiners-00.html
- Post-Quantum Noise (PQNoise), CCS'22 — https://dl.acm.org/doi/pdf/10.1145/3548606.3560577 ; Noise Framework — https://en.wikipedia.org/wiki/Noise_Protocol_Framework
- ECDHE-MLKEM for TLS 1.3 — https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- Ed25519 + batch verification — https://ed25519.cr.yp.to/ed25519-20110926.pdf ; https://cse.iitkgp.ac.in/~abhij/publications/EdDSA-BV-SPACE2014.pdf
- BLAKE3 + Bao verified streaming — https://github.com/BLAKE3-team/BLAKE3 ; https://github.com/n0-computer/bao-tree

Dissemination/membership:
- HyParView (DSN'07) — https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf
- Plumtree / Epidemic Broadcast Trees (SRDS'07) — https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf

Transport / OS:
- io_uring zero-copy Rx — https://docs.kernel.org/networking/iou-zcrx.html ; zero-copy Tx (LWN) — https://lwn.net/Articles/879724/
- Kernel-bypass (DPDK/AF_XDP/io_uring) — https://anshadameenza.com/blog/technology/2025-01-15-kernel-bypass-networking-dpdk-spdk-io_uring
- UDP GSO/GRO + QUIC — https://blog.cloudflare.com/accelerating-udp-packet-transmission-for-quic/ ; https://tailscale.com/blog/quic-udp-throughput ; segmentation offloads https://docs.kernel.org/networking/segmentation-offloads.html
- kTLS / in-kernel QUIC — https://github.com/lxin/quic
- SOCKMAP/sk_msg splicing — https://blog.cloudflare.com/sockmap-tcp-splicing-of-the-future/ ; https://docs.kernel.org/bpf/map_sockmap.html
- netmap (BSD) — https://man.freebsd.org/cgi/man.cgi?query=netmap
- Windows RIO + IOCP — https://serverframework.com/asynchronousevents/2011/10/windows-8-registered-io-and-io-completion-ports.html
- Multipath QUIC — https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/
- L4S architecture / ECN — https://www.rfc-editor.org/rfc/rfc9330.html ; https://www.rfc-editor.org/rfc/rfc9331.html
- Homa — https://arxiv.org/abs/2210.00714 ; https://arxiv.org/pdf/1803.09615
- Aeron — https://github.com/aeron-io/aeron
- Media over QUIC (MoQ) — https://blog.cloudflare.com/moq/
- Veilid private routing — https://veilid.com/how-it-works/private-routing/
- Matrix room DAG / state res — https://matrix-org.github.io/synapse/v1.40/development/room-dag-concepts.html

Frontier / other pathways:
- Eg-walker (collaborative text, EuroSys'25) — https://arxiv.org/pdf/2409.14252 ; Fugue — https://arxiv.org/pdf/2305.00583v1
- DAG-BFT SoK — https://arxiv.org/pdf/2411.10026 ; Bullshark — https://arxiv.org/abs/2201.05677 ; Shoal — https://arxiv.org/pdf/2306.03058
- WebTransport (W3C) — https://github.com/w3c/webtransport/blob/main/explainer.md ; can it replace WebSockets — https://ably.com/blog/can-webtransport-replace-websockets
- eBPF observability / flight recorder — https://thinhdanggroup.github.io/ebpf-observability/ ; deterministic record&replay — https://arxiv.org/pdf/1805.06267
- Vector commitments / Verkle / KZG — https://eprint.iacr.org/2025/667.pdf ; https://www.zkdocs.com/docs/zkdocs/commitments/kzg_polynomial_commitment/
- Nova / IVC / folding — https://eprint.iacr.org/2021/370.pdf ; https://github.com/microsoft/Nova
- Keyhive / BeeKEM (local-first access control) — https://www.inkandswitch.com/keyhive/notebook/ ; https://meri.garden/a-deep-dive-explainer-on-beekem-protocol/
- RaptorQ fountain FEC — https://arxiv.org/pdf/2004.12461 ; OpenRQ https://openrq-team.github.io/openrq/
- SmartNIC/DPU/P4 — https://codilime.com/blog/smartnics-with-p4-support/
