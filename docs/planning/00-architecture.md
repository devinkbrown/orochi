# 00 — Mizuchi Master Architecture (synthesis)

This document integrates the five research tracks (`01`–`05`) — produced by parallel
Codex deep-dives into the real ophion/libop/opssl code + LADON/VEIL specs, plus Claude
synthesis — into one coherent design, and records the locked decisions and the
**canonical vocabulary** (the tracks each coined overlapping names; this section is the
authority).

> Sub-documents: [`01-substrate`](01-substrate.md) · [`02-crypto-veil`](02-crypto-veil.md)
> · [`03-daemon-modules`](03-daemon-modules.md) · [`04-ladon-mesh`](04-ladon-mesh.md)
> · [`05-innovation`](05-innovation.md). Raw worker output in [`_codex-raw/`](_codex-raw/).

## 0. Thesis

ophion's S2S complexity is largely **TS6 compatibility scar tissue** (text S2S +
`STARTMSGPACK` + `MSEQ`/`HASHCHECK`/`RESYNC` repair bolt-ons all coexisting). Mizuchi
owes no backward compatibility, so the clean-slate Zig design is **smaller and more
principled, not bigger**: one pure binary mesh protocol, one anti-entropy mechanism
(Merkle delta sync), one language top-to-bottom.

## 1. Locked decisions (2026-06-02)

| Decision | Choice | Rationale |
|---|---|---|
| Language | **Zig** (0.16.0 pinned) | comptime metaprogramming, manual memory + ReleaseSafe, io_uring model |
| Scope | **Full rewrite** — daemon + substrate (libop) + crypto (opssl) all Zig-native | 100% freedom; no C interop |
| Transport | **TCP + VEIL framing** baseline; transport-agnostic so QUIC can slot in later | Control + less surface now; MeshQUIC/MASQUE deferred to media phases |
| VEIL crypto | **PQ-hybrid from day one** (X25519 + ML-KEM-768) | Harvest-now-decrypt-later resistance; revives original ambition |
| Extensibility | **Sandboxed WASM plugins** (MizuWasm); core modules are comptime Zig | Deterministic, hot-reloadable, sandboxed, runs inside the simulator |
| Testing | **DST-first from M0** (Deterministic Ocean) | Only credible way to trust self-written CRDT mesh + crypto |
| S2S migration | **Clean break, no TS6 in core** | A bridge, if ever, is a separate lower-authority gateway process |
| Nick collision | **Rename loser to its UID, never kill** | ophion rule, baked into the CRDT merge function |

## 2. Workspace (multi-package Zig)

```
mizuchi-substrate   reactor (Ringlane), allocators/arenas, lock-free queues,
                    data structures, LADON math (CRDT/HLC/vclock/Merkle/sketches),
                    simulation runtime (Deterministic Ocean), Fault Loom
mizuchi-crypto      primitives, TLS 1.3-only, X.509-min, VEIL v2, Secret(T)/ctcheck,
                    capability keyring, session/upgrade capsules
mizuchi-proto       IRC/IRCv3/IRCX/LADON/VEIL schemas → generated codecs (Codec Loom),
                    canonical wire format (CoilPack), golden vectors
mizuchi-daemon      core, SerpentRegistry modules, CapProof, services, MizuStore,
                    MizuWasm host, media
mizuchi-tools       config validator, keygen, trace reader, capsule inspector,
                    corpus minimizer
```

## 3. Canonical invention glossary (authority — use these names)

**Substrate / runtime**
- **Ringlane** — io_uring fast-path reactor (multishot accept/recv, buf_rings, send_zc,
  fixed files, DEFER_TASKRUN); one ring per shard; portable `Reactor` fallback
  (epoll/kqueue) for non-Linux. Connections are typed `ConnSlot` indices, not pointers.
- **CapSeals** — zero-cost connection capability tokens (`loop_owned` can arm I/O;
  `worker_borrowed` can only enqueue) — ophion's invariants encoded as types.
- **Sharded-actor model** — one writer per Client/Channel; cross-shard via typed
  mailboxes (MPMC), not shared mutation. Eliminates most locking.

**Crypto / security**
- **Secret(T) / ctcheck** — secret-taint type system + build-time verifier; a
  data-dependent branch/index on a secret is a **compile error**. Flagship safety tech.
- **Cipher Foundry** — comptime AEAD/hash/KEM generator emitting target-specialized
  variants (AES-NI / ARM PMULL / software) + KATs from one spec.
- **VEIL v2 (PQ-hybrid)** — per-frame symmetric chain + scheduled X25519+ML-KEM-768 root
  ratchet (every 300s / 50k frames / topology epoch). PFS + PQ recovery without
  per-message DH. 256-frame skipped-key window; AEAD-before-commit.
- **Capability Keyring** — keys are unforgeable typed handles (purpose + export policy +
  zeroization in the type); mlocked/DONTDUMP arenas.

**Protocol / mesh**
- **CoilPack** — canonical, self-describing, signature-stable binary wire format
  (varint schema id + field bitmap + canonical order). Replaces MessagePack on S2S.
- **Codec Loom** — comptime schema→Zig codec generator: emits encoders, decoders,
  golden vectors, fuzz mutators, version adapters. (Daemon track called this `Aqualine`;
  canonical name is **Codec Loom**, output format is **CoilPack**.)
- **MeshPass** — Ed25519 admission/capability token (node key, realm, roles, expiry,
  allowed frame families, max fanout, media rights, revocation epoch).
- **Witnessed SWIM** — gossip with signed suspicion evidence + witness quorum; no single
  node can force DEAD. HyParView-style active/passive views for large meshes.
- **NickClaim** — MV-register nick uniqueness; collisions converge by **rename-to-UID**.
- **CausalTags** — compact causal trace IDs `{origin, hlc, span, parent}` on every
  mutation, surfaced to clients as cap-gated IRCv3 tags (`partition`, `conflict`, order).

**Daemon / platform**
- **SerpentRegistry** — comptime module graph → command tables, typed hook dispatch,
  cap bitsets, ISUPPORT, mode tables, config schema, inventory docs. Collisions
  (command/cap/mode/numeric/dep/conflict) are compile errors.
- **CapProof** — typed capability/permission lattice; emitting a tag, running an oper
  command, or mutating access requires the correct typed evidence value.
- **StateForge** — comptime DSL for protocol state machines (registration, CAP/SASL,
  WS upgrade, LADON HELLO/AUTH, VEIL ratchet, upgrade handoff); illegal transitions
  don't compile; generates trace labels + fuzz generators. (Subsumes "Phantom TLS".)
- **FlowForge** — structured concurrency: per-client serial execution, cancellable
  transactions, deadline propagation handler→store→network.
- **MizuStore** — Zig-native embedded store: checksummed WAL + snapshots, typed column
  families, generated migrations, CRDT-aware changefeed (feeds services sync + LADON).
- **MizuWasm** — sandboxed WASM plugin host (fuel/memory limits, no raw pointers,
  deterministic hostcalls, manifest-declared permissions). Replaces embedded CPython.
- **Aegis** — optional bounded inline policy VM (no heap/syscalls) for per-channel rules
  (media policy, anti-spam, join gates) where a full WASM call is overkill.
- **Lotus** — content-addressed (BLAKE3) append-log history store backing CHATHISTORY;
  redactions are tombstones; Merkle roots replicate via LADON anti-entropy.
- **Helix Upgrade** — native `mizuchi-supervisor` mode (same Zig tree): owns listener
  FDs, sealed memfd handoff arena, typed session/TLS/kTLS/VEIL/CRDT capsules with
  schema ids + health attestation before old process exits. Replaces ophion's shim.
- **Event Spine** — typed structured event bus; metrics/trace/IRCX-EVENT/audit/services
  subscribe without owning core state.

**Testing / ops**
- **Deterministic Ocean** — TigerBeetle-style simulator: N virtual nodes in one process,
  deterministic clock/net/RNG/storage, partitions, crashes, mixed-version upgrade; every
  run reduces to a replayable 64-bit seed. (Subsumes the daemon track's `KawaReplay`.)
- **Fault Loom** — deterministic injectable failure points at every alloc/syscall/codec/
  store/crypto-export/send boundary; seeded CI campaigns; panics print a replay seed.

**Deferred transport inventions** (post-parity / media phases): **MeshQUIC**
(LADON-over-QUIC), **MASQUE Voice Bridge** (HTTP/3 relay for hard-NAT media),
**XDP Gatekeeper** (eBPF flood rejection before accept).

## 4. The heart: IRC network state as CRDTs

Delta-state CRDTs throughout (bandwidth-bounded), HLC for deterministic tie-breaks,
Merkle delta sync for anti-entropy. This single model replaces TS6 netburst +
SJOIN + MSEQ + HASHCHECK + RESYNC.

| Entity | CRDT | Conflict resolution |
|---|---|---|
| Users / UIDs | OR-Map `uid → LWW profile + presence lease` | UID immutable; disconnect = lease expiry + tombstone |
| Nicks | MV-register claim set (NickClaim) | winner by authority → HLC → NodeId; **loser renamed to UID, never killed** |
| Channels | OR-Map `chan → ChannelRoot` | Min-HLC birth register = TS; ownership = signed grant set |
| Memberships | OR-Set `(chan, uid, session)` | add-wins; part/kick = observed remove; rejoin = new dot |
| Prefix modes (o/v/…) | OR-Map `(chan,uid,mode) → AuthToggle` | higher authority removes lower; same-authority concurrent add wins |
| Boolean modes | causal toggle register | per-mode policy: restrictive add-wins, permissive remove-wins |
| Param modes (+k/+l) | LWW-register w/ authority | keyed by mode char; HLC tie → writer |
| Bans/except/invex | OR-Set (normalized mask + LWW metadata) | observed-remove; unobserved concurrent add survives |
| Topics | LWW-register (+ optional alternates) | newest HLC; conflicts exposed to opers via cap-gated tag |
| Accounts | authority-signed OR-Map (services realm) | servers relay signed assertions; cannot invent state |
| History / media presence | bounded OR-Log w/ HLC | pruned by retention watermark + Merkle roots |

Tombstone GC: discard dots dominated by the **causal-stability frontier** across all
live peers (SWIM membership must not falsely delete causality a recovering peer needs).

Partitions: a mesh does not netsplit like a tree. Local partitions keep accepting local
actions under degraded-trust labels (CausalTags); on heal, CRDTs converge — no mass
kills, nick losers rename, bans union, services-signed account state overrides
unauthenticated local claims.

## 5. Roadmap (see `05` for full table)

M0 Bootline → M1 Reactor/Substrate → M2 IRC core → M3 IRCv3 core → M4 SASL+TLS1.3 →
M5/M6 IRCX parity → M7 Services (+MizuStore) → M8–M11 LADON/VEIL mesh
(handshake → CRDT model → SWIM+Merkle → VEIL v2) → M12 Lotus history → M13 Media →
M14 MASQUE relay → M15 Helix upgrade → M16 hardening (XDP/Aegis/CapProof) → M17 RC soak.

**M0 exit criterion:** `zig build` produces a booting binary that accepts a TCP client
and answers `PING` — with all I/O (clock/net/RNG) already behind injectable interfaces
(DST-first).

## 6. Top risks (see `05` register)

1. **Own crypto + own TLS** (Critical) — narrow TLS1.3 scope, KATs/Wycheproof, dudect
   timing tests, `Secret(T)` gate, external audit before public federation.
2. **Own mesh CRDTs** (Critical) — Deterministic Ocean before any production mesh; start
   with the simplest correct CRDT, prove convergence across thousands of seeds.
3. **Hot-upgrade version skew** — Codec Loom capsules with min/max schema negotiation +
   mixed-version simulator tests.
4. **io_uring/kTLS kernel variance** — portable reactor baseline + runtime probes.
5. **Zig pre-1.0 churn** — pinned `minimum_zig_version`, toolchain-upgrade PRs.
6. **Feature-parity surface is enormous** — mine golden conformance tests from ophion
   behavior before implementing each feature group.

## 7. Immediate next steps

1. Install + pin Zig 0.16.0; scaffold the workspace (`build.zig.zon`, `build.zig`).
2. Stand up M0 Bootline with the DST seam (Reactor interface + simulated reactor) from
   the first commit.
3. Land Codec Loom + Secret(T) skeletons early — everything downstream depends on them.
