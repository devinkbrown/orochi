# 09 — Suimyaku S2S Linking Protocol (modern, clean-room design)

> **Mandate (user, 2026-06-05):** clean-room, no technical debt, "go our own
> way." Extremely modern S2S. Secure, **verifiable**, optimized, and shaped so
> voice/media/video can ride it later — but **core infrastructure first**. The
> sovereign `node_id` is the *single* mesh identity; there is **no TS6 server-id
> (SID)** anywhere (purged in `aaa3cb2`).

This document is the deep-research design for Mizuchi's server-to-server linking
protocol. It supersedes the S2S portions of [04-suimyaku-mesh.md](04-suimyaku-mesh.md)
where they conflict, and is grounded in current (2025–2026) distributed-systems
prior art rather than legacy IRC server linking.

---

## 1. Design goals & non-goals

**Goals**
1. **One sovereign identity.** A node is `NodeId = BLAKE3-160(Ed25519 verify key)`.
   No SIDs, no TS6, no human-name-as-identity. The Ed25519 key *is* the node.
2. **Verifiable by construction.** Every admission, every membership claim, every
   state delta is signed and attributable to a `NodeId`. A peer can independently
   verify any fact it relays — no "trust because it came over the link."
3. **Modern authenticated transport.** A PQ-hybrid Noise-style handshake (mutual
   auth + forward secrecy + identity hiding), not an ad-hoc AUTH exchange.
4. **Partition-proof state.** Delta-state CRDTs with range-based set reconciliation
   for cheap anti-entropy; convergence is a property, not a hope.
5. **Scalable dissemination.** Epidemic broadcast (Plumtree over HyParView partial
   views) so the mesh is `O(log n)` fanout, not full-mesh flooding.
6. **Media-ready spine.** A stream/band model that maps cleanly onto QUIC / Media-
   over-QUIC so realtime audio/video is a *new band*, not a redesign.
7. **Deterministic & testable.** Every layer behind the `Reactor`/clock/rng seam
   so the whole protocol runs in the Deterministic Ocean simulator.

**Non-goals**
- TS6 / legacy server linking compatibility (explicitly out — clean break).
- A global total order (we use causal order + per-entity resolution instead).
- Trusting transitive relays (no "my uplink said so" — see §6 verifiability).

---

## 2. Prior-art survey (what we borrow, what we reject)

| Source | Take | Reject |
| --- | --- | --- |
| **Matrix** room DAG + state resolution ([spec], [room-dag]) | Per-room **event DAG** with `prev_events` hash links → causal order without wall-clock trust; state-res only where the DAG forks. | Whole-room state-resolution complexity / state resets; we keep entity-scoped CRDTs, DAG only for *history/event* ordering. |
| **Veilid** private routing + multi-writer DHT ([veilid-routing], [veilid-rpc]) | Onion-style **safety/private route** option for metadata-private peering; multi-writer record model for shared mutable state. | Mandatory full anonymity overlay (optional, not core). |
| **Noise / PQNoise** ([noise], [pqnoise]) | **Noise-IK-hybrid** handshake: known-responder, 1-RTT, mutual auth, identity hiding; PQ via X25519+ML-KEM concatenation. | Rolling our own AKE. Use the framework's proven patterns. |
| **δ-CRDTs** + **Range-Based Set Reconciliation** ([delta-crdt], [rbsr], [conflictsync]) | Delta-mutators (small diffs) + **RBSR/ConflictSync** digest-driven anti-entropy: recursively compare range fingerprints, ship only mismatches. | Full-state shipping; naive Merkle-of-everything. |
| **Plumtree / HyParView** ([plumtree], [hyparview]) | Two partial views (active=TCP-ish links, passive=reserve) + eager/lazy push spanning tree with graft/prune repair. | Full-mesh broadcast; static topology. |
| **Media over QUIC (MoQ)** ([moq], [quic-dc]) | Stream+datagram band model; per-track delivery so a lost media packet never blocks control; priority scheduling. | WebRTC's SDP/ICE complexity on the *server* mesh. |

Sources are listed in §11.

---

## 3. Identity & trust model (no SIDs)

```
node secret      = Ed25519 signing key (sovereign, long-term, per node)
NodeId           = BLAKE3-160(Ed25519 verify key)   // 20 bytes, the ONLY id
display name     = metadata (a server label; never an identity, never unique)
replica lane     = NodeId  (CRDT ReplicaId is the node id — already u64-wide;
                            full 160-bit NodeId on admission, abbreviated on hot paths)
```

- The registry (`server_registry`) is keyed by `NodeId`. ✅ done (`aaa3cb2`).
- **MeshPass** admission token (Ed25519-signed capability): `{node_key, realm,
  roles, expiry, allowed_frame_families, max_fanout, media_rights, revocation_epoch}`.
  Admission requires a configured trust root **or** a quorum-signed invite from
  existing operators. A node presents its MeshPass in the handshake; peers verify
  the signature chain to the realm root before `Established`.
- **Capability, not ambient authority.** A node may only emit deltas for families
  its MeshPass grants. This is the object-capability discipline applied to S2S.

---

## 4. Layered architecture

```
┌─────────────────────────────────────────────────────────────┐
│ L5  Application state   Goryu δ-CRDT world (users/chans/modes)│  channel_crdt, world
│ L4  Mesh services       membership, gossip, anti-entropy, route│ link_session, gossip_round,
│                                                                │ anti_entropy_repair, server_registry, route_table
│ L3  Link/session        per-peer driver, credit, streams, HLC  │ s2s_peer, s2s_link, peer_link
│ L2  Secure channel      Tsumugi: PQ-hybrid handshake + ratchet │ (crypto/* — to wire)
│ L1  Framing             CoilPack frames, bands, length-delim   │ s2s_frame, coilpack
│ L0  Transport           TCP now → QUIC later (1 actor / peer)  │ reactor (io_uring)
└─────────────────────────────────────────────────────────────┘
```

Each layer is a seam. **Core-infra-first ordering:** L0/L1/L3 exist today
(reactor + `s2s_frame` + `s2s_peer`/`s2s_link`, both ends now establish &
converge); L2 (Tsumugi handshake) and L4 hardening (RBSR, Plumtree) are the next
build; L5 world-projection is the user-visible payoff; media is a later L1 band.

---

## 5. Connection lifecycle & framing

State machine (one io_uring actor owns the socket, crypto, credit, schedulers):

```
TcpConnected → HelloSent/Recv → HandshakeProved → SessionUp
            → Established → Rekeying ⇄ Established → Draining → Closed
```

Before `Established`, only `HELLO / HANDSHAKE / PING / CREDIT / ERROR` are
accepted (matches the current gating; tightened to reject app frames pre-auth).

**Framing — CoilPack** (not MessagePack): varint schema id + field bitmap +
canonical field order + typed atoms. Canonical encoding makes signatures stable
(sign the bytes, not a re-serialization). Unknown fields skip-forward → forward
compatibility without versioned forks.

**Outer frame header:** `{band:u8, flags, len:varint, stream_id:varint,
hlc:u64, src_node:NodeId, causal_digest, [route_hint]}`. The `src_node` +
signature make every frame independently attributable.

**Bands / streams** (priority via weighted deficit round-robin):

| band | stream | content | priority |
| --- | --- | --- | --- |
| 0 control | 0 | hello, credit, ping/pong, rekey, error | highest |
| 1 membership | 1 | HyParView views, witnessed SWIM | high |
| 2 anti-entropy | 2 | RBSR range digests + delta fills | high |
| 3 events | 3 | IRC/channel events (Plumtree eager/lazy) | medium |
| 4 services | 4 | signed account/auth assertions | medium |
| 5 media-ctrl | 5 | track announce/subscribe (MoQ-shaped) | medium |
| ≥64 media | n | audio/video/data tracks (datagram-eligible) | scheduled |

A lost media packet on band ≥64 never blocks control/repair — the QUIC/MoQ
lesson, pre-baked into the band model so the TCP→QUIC swap is transport-only.

---

## 6. Security & verifiability (Tsumugi)

**Handshake (PQ-hybrid Noise-IK-shaped):**
- Static keys = the node Ed25519 identity (bound into the transcript).
- Ephemeral KEX = **X25519 + ML-KEM-768** concatenated → hybrid shared secret
  (PQ forward secrecy day one; classical security never weakened).
- 1-RTT to first encrypted app data; responder identity known (IK), initiator
  identity hidden until authenticated.
- Transcript binds: both `NodeId`s, both MeshPasses, realm root, protocol version,
  negotiated bands. Downgrade-resistant (the negotiation is signed in the final
  confirm).

**Post-handshake ratchet:** root key → directional send/recv chains; per-frame
AEAD with AD = outer header ⊕ peer NodeIds ⊕ generation ⊕ stream ⊕ plaintext-len.
Rekey on time / byte-budget / message-count; old generation kept in a drain
window for reordered frames. **AEAD failure never advances counters** (replay
state is a gap-aware bitmap + bounded skipped-key cache).

**Verifiability invariants** (the heart of "secure & verifiable"):
1. Every state **delta is signed** by its origin `NodeId`; a relayer cannot forge
   or mutate it — peers verify the origin signature, not the relay.
2. **No peer may declare another DEAD alone** — witnessed SWIM: suspicion carries
   a signed witness set; transition to DEAD needs a quorum of witnesses.
3. Account/services facts are **authority-signed assertions**; a server relays
   them, it cannot invent them.
4. Admission is capability-gated (MeshPass); revocation epoch lets the realm cut a
   compromised node without rekeying the whole mesh.

---

## 7. Membership & dissemination

- **HyParView** partial views: a small **active view** (live links, symmetric,
  TCP-backed) and a larger **passive view** (reserve peers, refreshed by periodic
  shuffles). Node failure repairs from passive → active in `O(1)` hops.
- **Plumtree** epidemic broadcast over the active view: *eager push* builds a
  spanning tree (full payload), *lazy push* gossips message-id digests; a missing
  id triggers `GRAFT` (heal the tree) and duplicate eager links `PRUNE` (shed
  redundancy). Result: tree-efficient in steady state, gossip-resilient on churn.
- **Witnessed SWIM** for liveness (direct ping → indirect `PING_REQ` to k
  witnesses → signed SUSPECT → quorum DEAD). Incarnation counters + signed
  membership deltas feed the health CRDT.

---

## 8. State synchronization (Goryu δ-CRDT + RBSR)

- **Delta-state CRDTs**: mutators emit small deltas (not full state); join is
  associative/commutative/idempotent → convergence regardless of order/dups.
- **Anti-entropy = Range-Based Set Reconciliation** (ConflictSync-style): peers
  exchange **range fingerprints** over the ordered dot/event set; matching ranges
  are skipped, mismatching ranges recursively split until the actual missing
  deltas are identified and shipped. Bandwidth ∝ *difference*, not *state size* —
  the key scaling property for large channels/histories.
- **Merkle anti-entropy** remains the integrity backstop / coarse digest; RBSR is
  the fine-grained reconciliation on top.
- Entity resolution table (unchanged from [04](04-suimyaku-mesh.md) §CRDT State):
  UID OR-Map, nick MV-register (rename-to-UID loser), channel OR-Map, membership
  OR-Set, prefix-mode authority OR-Map, bans OR-Set, topic LWW, accounts
  authority-signed OR-Map.

---

## 9. Causal ordering (HLC + a DAG where it earns its keep)

- **Hybrid Logical Clocks** stamp every delta `{origin, hlc}` → a causal partial
  order without trusting wall clocks (Matrix's lesson: never order by sender time
  alone).
- **Event/history DAG** (Matrix-inspired, *scoped to CHATHISTORY/Lotus*, not whole
  channel state): history entries carry `prev` hash links; replay order is the DAG
  topo-order, and gaps are detectable & backfillable. Channel *state* stays in the
  CRDT (cheaper than full state-resolution); only the *event log* is a DAG.

---

## 10. Mapping to current code + migration

**Already done (clean core):**
- `node_id`-only identity across `server_registry`/`s2s_peer`/`s2s_link`/`channel_crdt`; SID purged.
- L0/L1/L3: io_uring listener + CONNECT, `s2s_frame` codec, `s2s_peer` driver +
  `s2s_link` adapter; both ends establish + converge; LINKS/MAP/SQUIT live.

**Next (in priority order — core infra first):**
1. **L2 Tsumugi handshake** wrapping the established `s2s_peer` byte path
   (PQ-hybrid Noise-IK + MeshPass verify) → "secure & verifiable" becomes real.
2. **Signed deltas** end-to-end (origin signature on every CRDT delta + verify on
   apply) → the verifiability invariants.
3. **RBSR anti-entropy** replacing/augmenting the current burst (bandwidth ∝ diff).
4. **Plumtree/HyParView** dissemination over multiple peers (today: per-link).
5. **World projection** (L5): converged CRDT membership → local NAMES/WHO/routing
   (items 96/97) — the first user-visible mesh payoff.
6. **Media bands** (≥64) + transport swap to QUIC once core is solid.

**Compatibility:** CoilPack canonical encoding + skip-unknown-fields means new
bands/fields ship without breaking older nodes; the handshake's signed version
negotiation prevents silent downgrades.

---

## 11. Sources

- Matrix room DAG & state resolution: [room-dag], [spec], [stateres]
- Veilid private routing / RPC: [veilid-routing], [veilid-rpc]
- Noise & PQNoise: [noise], [pqnoise]
- δ-CRDTs & set reconciliation: [delta-crdt], [rbsr], [conflictsync]
- Plumtree / HyParView: [plumtree], [hyparview]
- Media over QUIC: [moq], [quic-dc]

[room-dag]: https://matrix-org.github.io/synapse/v1.40/development/room-dag-concepts.html
[spec]: https://spec.matrix.org/latest/
[stateres]: https://matrix.org/docs/older/stateres-v2/
[veilid-routing]: https://veilid.com/how-it-works/private-routing/
[veilid-rpc]: https://veilid.com/how-it-works/rpc/
[noise]: https://en.wikipedia.org/wiki/Noise_Protocol_Framework
[pqnoise]: https://dl.acm.org/doi/pdf/10.1145/3548606.3560577
[delta-crdt]: https://arxiv.org/pdf/1603.01529
[rbsr]: https://arxiv.org/pdf/2603.19820
[conflictsync]: https://arxiv.org/pdf/1410.2803
[plumtree]: https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf
[hyparview]: https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf
[moq]: https://blog.cloudflare.com/moq/
[quic-dc]: https://www.ietf.org/archive/id/draft-engelbart-quic-data-channels-00.html
