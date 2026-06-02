# 05 — Invented Technologies, Build & Roadmap

Planning only. I did not modify files.

## Grounding

Mizuchi is a clean-slate Zig rewrite of daemon, substrate, and crypto, with ophion/libop/opssl as reference only, while preserving IRCv3, IRCX, SASL, services, WebSocket, CHATHISTORY, voice/video, and replacing TS6 with LADON+VEIL (`/home/kain/mizuchi/docs/BRIEF.md:3-12`). The brief explicitly asks for invented technologies, aggressive `comptime`, pinned Zig, x86-64/ARM64 cross-compilation, and constant-time crypto by construction (`/home/kain/mizuchi/docs/BRIEF.md:14-30`, `/home/kain/mizuchi/docs/BRIEF.md:45-54`).

Ophion’s current build gives the baseline to improve: 64-bit enforcement, hardening flags, sanitizers, io_uring probing, opssl session export, kTLS detection, subprojects, tests, fuzz targets, and shim upgrade summary (`/home/kain/ophion/meson.build:23-67`, `/home/kain/ophion/meson.build:155-179`, `/home/kain/ophion/meson.build:236-255`, `/home/kain/ophion/meson.build:262-353`, `/home/kain/ophion/meson.build:682-736`). libop already probes event/syscall features and kTLS/session-export defines (`/home/kain/libop/meson.build:45-87`, `/home/kain/libop/meson.build:119-128`). opssl already contains kTLS, PQ toggles, CPU feature probing, TLS/crypto sources, and a no-LTO constant-time AES S-box workaround (`/home/kain/opssl/meson.build:62-98`, `/home/kain/opssl/meson.build:170-232`, `/home/kain/opssl/meson.build:265-288`).

LADON is already a binary mesh concept with 8-byte frames, MessagePack payloads, SWIM membership, CRDT anti-entropy, and VEIL (`/home/kain/ophion/docs/protocols/ladon/overview.md:6-14`). Its wire spec separates native LADON from MessagePack text-link framing and defines HELLO/AUTH/AUTH_OK over Ed25519/X25519 (`/home/kain/ophion/docs/protocols/ladon/wire-protocol.md:6-9`, `/home/kain/ophion/docs/protocols/ladon/wire-protocol.md:47-66`). VEIL wraps post-auth LADON frames with X25519, HKDF-SHA-256, ChaCha20-Poly1305, skipped-key recovery, and serializable ratchet state (`/home/kain/ophion/docs/protocols/veil-security.md:6-8`, `/home/kain/ophion/docs/protocols/veil-security.md:85-104`).

## Part 1 — Invention

### 1. Ringlane I/O

Problem: IRC daemons still spend too much complexity on “which fd is armed, which buffer owns this read, which write queue is safe after migration.” Ophion already probes io_uring and has per-shard event tests (`/home/kain/ophion/meson.build:236-255`, `/home/kain/ophion/tests/meson.build:44-99`).

How: Ringlane is Mizuchi’s Linux fast path: one io_uring per shard, registered socket files, registered fixed buffers, multishot accept/recv, batched send, provided-buffer rings, and optional zero-copy send for bulk history/media. Every connection owns a typed `ConnSlot` index, not a pointer, so handoff/state snapshots are stable. Non-Linux targets use the same `Reactor` interface over kqueue/epoll/poll without pretending io_uring exists.

Risk: io_uring feature availability varies by kernel. Mitigation: build-time target gates plus runtime capability probes, with conformance tests run against both Ringlane and portable reactors.

### 2. MeshQUIC

Problem: TCP S2S links still couple one stream’s head-of-line blocking to the whole mesh.

How: MeshQUIC is optional LADON-over-QUIC for S2S and high-loss client links. Control, CRDT, IRC application, media negotiation, and media payloads become distinct QUIC streams/datagrams. VEIL remains the mesh encryption/authentication layer, so QUIC is a transport substrate, not the trust boundary. TCP LADON remains the mandatory baseline.

Risk: QUIC stacks are large and easy to get wrong. Mitigation: phase after TCP LADON is stable; start with client/media relay before core S2S authority.

### 3. XDP Gatekeeper

Problem: floods and malformed probes reach userspace too cheaply.

How: A generated eBPF/XDP program rejects impossible IRC/LADON first bytes, obvious oversized prefaces, known banned source prefixes, and token-bucket-abusive IPs before userspace accept. The daemon owns policy generation and loads eBPF only on Linux with privilege; otherwise it degrades to userspace accept throttles.

Risk: verifier complexity and operational privileges. Mitigation: eBPF is optional, generated from a tiny declarative rule set, and tested with recorded packet corpora.

### 4. MASQUE Voice Bridge

Problem: voice/video users behind hard NATs need relay paths, but the IRC daemon should not become a TURN clone bolted on sideways. Ophion’s media already spans voice, video, negotiation, stats, ABR, and simulcast frames (`/home/kain/ophion/docs/protocols/ladon/media.md:105-124`).

How: MASQUE Voice Bridge uses HTTP/3 MASQUE CONNECT-UDP as an optional relay plane for media sessions. LADON carries authorization, channel policy, participant rosters, and encryption metadata; media bytes ride QUIC datagrams through relay nodes. Per-channel policy decides whether direct WebRTC, mesh relay, or MASQUE relay is allowed.

Risk: operational complexity. Mitigation: ship media signaling first, relay later, and require explicit admin enablement.

### 5. StateForge

Problem: protocol state machines are currently encoded as scattered booleans and comments. LADON has explicit states and pre-established gating rules (`/home/kain/ophion/docs/protocols/ladon/transport-state.md:10-32`).

How: StateForge is a `comptime` DSL for protocol states. IRC registration, CAP/SASL, WebSocket upgrade, LADON HELLO/AUTH/AUTH_OK, VEIL ratchet, and live-upgrade handoff are declared as state graphs. Zig generates transition functions, illegal-transition tests, trace labels, and fuzz generators.

Risk: DSL overreach. Mitigation: require generated code to be readable and checked into docs as rendered tables.

### 6. Codec Loom

Problem: hand-written binary codecs rot. LADON frames, VEIL payloads, IRCX sync, and migration blobs all need exact layout discipline.

How: Codec Loom is a schema-to-Zig `comptime` generator. It emits encoders, decoders, golden vectors, fuzz mutators, endian checks, max-length checks, and version upgrade adapters. LADON’s 8-byte header and frame bands become schema, not manually repeated constants (`/home/kain/ophion/docs/protocols/ladon/wire-protocol.md:10-45`).

Risk: schema bugs become systemic. Mitigation: independent reference decoder in the deterministic simulator plus differential tests against existing Python harnesses.

### 7. `Secret(T)` / VeilSafe

Problem: “constant-time by convention” is not enough for a native crypto rewrite. The brief requires no secret-dependent branches or memory access (`/home/kain/mizuchi/docs/BRIEF.md:45-54`).

How: `Secret(T)` is a type wrapper that forbids `if`, `switch`, table indexing, logging, formatting, equality branching, and allocator movement unless the method is marked constant-time. VeilSafe is the crypto subsystem policy: secret arrays are page-tagged when possible, zeroized through verified destructors, and exported only through typed migration capsules.

Risk: Zig cannot prove microarchitectural constant time alone. Mitigation: compile-time restrictions plus ctgrind/dudect-style timing tests and assembly audits for release crypto.

### 8. Deterministic Ocean

Problem: mesh CRDTs, SWIM, ratchets, mode repair, netsplits, and live upgrade cannot be validated well with only black-box scripts. Ophion already tests private spawned daemons and LADON fake peers in Python (`/home/kain/ophion/tests/s2s_helpers.py:470-476`, `/home/kain/ophion/tests/s2s_helpers.py:852-910`).

How: Deterministic Ocean is a TigerBeetle-style simulation harness. It runs hundreds of virtual Mizuchi nodes in one process with deterministic time, packet loss, reordering, crash/restart, disk faults, key rotation, and random operator commands. Every run records a seed, event log, and minimized counterexample.

Risk: simulator diverges from production. Mitigation: same protocol/state-machine code is linked into simulator and daemon; only sockets/time/storage are virtualized.

### 9. Fault Loom

Problem: failure paths are where hot upgrades and mesh recovery break.

How: Every allocator, syscall wrapper, send path, codec decode, storage commit, crypto export, and reactor operation has an injectable deterministic failure point. CI runs seeded fault campaigns, and any production panic prints a replayable fault seed.

Risk: overhead and developer fatigue. Mitigation: fault points are compile-time gated but always present in debug/sim builds.

### 10. Helix Upgrade

Problem: Ophion’s shim path is powerful but externalized. It transfers plain/kTLS FDs, uses opssl session export for non-kTLS TLS, serializes clients, servers, channel state, media blobs, LADON, VEIL, MessagePack state, and raw send queues (`/home/kain/ophion/ircd/restart.c:135-151`, `/home/kain/ophion/ircd/restart.c:174-190`, `/home/kain/ophion/ircd/restart.c:197-265`, `/home/kain/ophion/ircd/session_migrate.c:728-757`, `/home/kain/ophion/ircd/session_migrate.c:2916-3064`).

How: Helix Upgrade replaces the shim with a native, minimal `mizuchi-supervisor` mode compiled from the same Zig tree. The supervisor owns listener FDs and a sealed memfd handoff arena. Old daemon freezes accept, quiesces shards, snapshots typed state capsules, exports TLS/kTLS/VEIL capsules, passes FDs through Unix domain sockets, and waits for new daemon health attestation before old process exits. kTLS state uses kernel socket continuity where available; non-kTLS TLS uses native TLS session capsules; VEIL uses ratchet capsules; mesh CRDT state uses Merkle checkpoint capsules.

Risk: compatibility across binary versions. Mitigation: every capsule has a schema id, min/max supported version, semantic validator, and simulator upgrade tests across the last N released schemas.

### 11. Causal Wake

Problem: distributed traces die at server boundaries.

How: Every client command, LADON frame, CRDT delta, moderation event, media relay, and storage write carries a compact causal trace id: `{origin_node, hlc, span, parent}`. It propagates through LADON, IRC message tags where allowed, and internal event logs. Operators can ask “why did this channel mode exist?” and get the causal chain.

Risk: metadata bloat. Mitigation: IDs are binary inside LADON, sampled for low-value traffic, mandatory for state mutations.

### 12. Event Spine

Problem: IRC daemons grow side-channel callbacks. IRCX already has oper event subscriptions (`/home/kain/ophion/docs/protocols/ircx.md:139-159`).

How: Event Spine is a typed structured event bus. Every state mutation emits a stable event struct: `UserRegistered`, `ChannelModeChanged`, `CRDTDeltaApplied`, `VeilRatchetRotated`, `UpgradeCapsuleAccepted`. Metrics, tracing, IRCX EVENT, audit logs, services, and policy hooks subscribe without owning core state.

Risk: event storms. Mitigation: backpressure classes, lossy metrics subscribers, durable audit subscribers.

### 13. Lotus History Store

Problem: CHATHISTORY wants efficient replay, dedupe, tamper evidence, and mesh reconciliation.

How: Lotus is a content-addressed append log. Messages are chunks keyed by BLAKE3, indexed by channel, HLC, sender, and moderation epoch. Redactions are tombstone records, not destructive rewrites. Merkle roots replicate through LADON anti-entropy so history gaps repair like channel state.

Risk: privacy and retention. Mitigation: per-channel retention policy, encrypted-at-rest segments, legal-delete compaction mode.

### 14. ProofMark Moderation

Problem: distributed moderation actions should be auditable without leaking all operator internals.

How: Every KLINE, quiet, access change, forced mode, redact, and media moderation action emits a signed proof containing actor authority, policy version, target, reason hash, and expiry. Peers verify authority before applying. Users can receive a redacted proof id; opers can inspect full proof.

Risk: key management. Mitigation: short-lived oper signing keys derived from account auth plus server authority, rotated and revocable.

### 15. Aegis Policy VM

Problem: per-channel custom policy normally means unsafe modules.

How: Aegis is a constrained policy VM. Policies are declarative rules compiled at `comptime` or loaded as signed bytecode with bounded CPU, no heap, no syscalls, deterministic inputs, and explicit outputs: allow, deny, transform tags, require moderation, rate-limit. Use cases: channel-specific media rules, anti-spam, join gates, CHATHISTORY visibility, IRCX property constraints.

Risk: accidental incompatibility with IRC expectations. Mitigation: policy outputs are narrow and conformance tests run with default policy disabled/enabled.

## Part 2 — Build & Test

### Build Strategy

Use a Zig workspace with packages:

- `mizuchi-substrate`: reactor, allocators, arenas, intrusive collections, lock-free queues, HLC, CRDTs, Merkle sync, simulation runtime.
- `mizuchi-crypto`: TLS 1.3, X.509, PQ-hybrid KEM/signature experiments, VEIL, `Secret(T)`, session/export capsules.
- `mizuchi-proto`: IRC/IRCv3/IRCX/LADON/VEIL schemas, generated codecs, golden vectors.
- `mizuchi-daemon`: server core, services, module registry, policy VM, storage, media.
- `mizuchi-tools`: config validator, keygen, trace reader, corpus minimizer, upgrade capsule inspector.

`build.zig.zon` pins `minimum_zig_version` and dependency hashes. Because Zig is pre-1.0, compiler upgrades are explicit “toolchain PRs” with full simulator and conformance runs, matching the brief’s pinning requirement (`/home/kain/mizuchi/docs/BRIEF.md:48-49`).

Targets:

- Tier 1: `x86_64-linux-gnu`, `x86_64-linux-musl`, `aarch64-linux-gnu`, `aarch64-linux-musl`.
- Tier 2: FreeBSD/macOS portable reactor without io_uring/kTLS.
- Linux-only gates: io_uring, kTLS, eBPF/XDP, memfd seals, pidfd, `SO_REUSEPORT` tuning.
- Reproducibility: `SOURCE_DATE_EPOCH`, deterministic generated schemas, sorted module manifests, no build timestamp in binaries except optional external build metadata.

Build modes:

- `zig build`: debug-safe daemon and tools.
- `zig build -Drelease=safe`: production default.
- `zig build -Drelease=fast -Dfastpath=linux`: Ringlane/XDP optimized.
- `zig build test`: units and pure integration.
- `zig build sim`: deterministic simulator campaigns.
- `zig build conformance`: golden IRC/IRCX/LADON/VEIL suites.
- `zig build fuzz`: parser/codec/crypto boundary fuzzers.
- `zig build dist`: reproducible tarballs plus SBOM.

### Test Strategy

Keep Ophion’s useful shape: self-contained C tests and pytest private-daemon tests exist today (`/home/kain/ophion/tests/meson.build:1-12`, `/home/kain/ophion/tests/meson.build:106-134`), fuzz targets are opt-in libFuzzer binaries (`/home/kain/ophion/fuzz/meson.build:25-47`), and upgrade tests cover startup/drain/kTLS/S2S survival (`/home/kain/ophion/tests/test_upgrade.py:5-34`, `/home/kain/ophion/tests/test_ktls_upgrade.py:5-26`, `/home/kain/ophion/tests/test_s2s_upgrade.py:5-34`).

Mizuchi test layers:

- Unit: `std.testing` for allocators, codecs, CRDTs, reactor contracts, crypto primitives, policy VM.
- Golden protocol: IRCv3 registration/CAP/SASL, IRCX commands/properties/access/events, LADON frame vectors, VEIL ratchet vectors.
- Deterministic simulation: 3 to 500 virtual nodes, randomized joins/parts/modes/history/media/control traffic, partition/heal, crash/restart, mixed-version upgrade, clock skew, duplicate delivery.
- Fuzz-by-construction: Codec Loom emits valid and near-valid mutators for IRC lines, tags, WebSocket frames, LADON headers, MessagePack payloads, VEIL frames, migration capsules, config.
- Fault injection: deterministic failure points for alloc/syscall/storage/crypto export/send/recv.
- Coverage: 80%+ line coverage on substrate/proto/daemon non-generated code; 90%+ on migration codecs and crypto boundary code.
- Sanitizers: Debug/ReleaseSafe, LLVM ASan/UBSan/TSan where Zig supports the target, valgrind-compatible portable tests, dudect timing tests for `Secret(T)` paths.
- CI matrix: x86-64 Linux fast path, x86-64 Linux portable, ARM64 Linux cross-build plus emulator smoke, musl build, FreeBSD portable build, fuzz smoke, nightly long simulator.

## Part 3 — Roadmap

| Milestone | Scope | Exit Criterion | Effort | Key Risk |
|---|---|---|---|---|
| M0 Bootline | Build workspace, config parser stub, TCP listener, IRC line parser, PING/PONG | `zig build` produces a binary that accepts TCP and answers `PING` | S | Reactor abstraction churn |
| M1 Reactor/Substrate | Ringlane portable contract, allocators, timers, logging, Event Spine | Same daemon runs on portable reactor and Linux Ringlane tests | M | io_uring behavior differences |
| M2 IRC Core | NICK/USER, PING/PONG, PRIVMSG/NOTICE, channels, modes, numerics | Two clients can register, join, chat, part, quit with golden tests | M | Legacy IRC edge cases |
| M3 IRCv3 Core | CAP LS/REQ/ACK, tags, batches, CHATHISTORY skeleton | IRCv3 conformance goldens pass | M | Tag/batch compatibility |
| M4 SASL+TLS | Native TLS 1.3, certfp, SASL PLAIN/SCRAM, WebSocket TLS | TLS client registers with SASL and certfp tests pass | L | Own crypto/TLS risk |
| M5 IRCX Parity A | IRCX opt-in, AUTH shorthand, CREATE, LISTX, MODEX, PROP | Core IRCX command goldens pass against Ophion-derived fixtures | M | Ambiguous legacy semantics |
| M6 IRCX Parity B | ACCESS/SACCESS, EVENT, REQUEST/REPLY, WHISPER, DATA/comic compatibility | IRCX access/property/event integration tests pass | M | Permission model drift |
| M7 Services | Accounts, NickServ/ChanServ-style core, oper/admin flows | Account registration/login/channel ownership survives restart | L | Persistence schema |
| M8 LADON Phase 1 | TCP LADON HELLO/AUTH/AUTH_OK, frame codec, credit windows | LADON fake peer completes handshake and PING/PONG; data gated before ESTABLISHED | M | Auth interop |
| M9 LADON Phase 2 | Binary IRC application frames, CRDT model, MSEQ/HASHCHECK equivalents | 3-node mesh converges users/channels/modes after reorder/loss | L | CRDT correctness |
| M10 LADON Phase 3 | SWIM, Merkle anti-entropy, partition heal | Simulator proves convergence after partition/heal across 100 seeds | L | Failure detector tuning |
| M11 VEIL | Ratchet, skipped keys, group keys, migration capsules | Encrypted LADON survives reorder, loss, restart, and mixed-version handshake | L | Ratchet state bugs |
| M12 CHATHISTORY Lotus | Content-addressed store, retention, redaction, Merkle repair | History queries and redactions converge across mesh | M | Storage/privacy tradeoffs |
| M13 Media | IRC media signaling, voice/video frame families, stats/ABR/simulcast | Two clients in different servers exchange authorized media frames | L | Bandwidth/backpressure |
| M14 MASQUE Relay | Optional relay nodes for hard NAT voice/video | Relay path works with policy and trace attribution | L | Operational complexity |
| M15 Helix Upgrade | Supervisor, FD handoff, TLS/kTLS/VEIL/CRDT/session capsules | Upgrade under load: clients, S2S, media, history, services survive with zero disconnects | L | Versioned capsule compatibility |
| M16 Hardening | XDP Gatekeeper, ProofMark, Aegis VM, observability polish | Abuse simulations pass; operator trace/audit workflows complete | M | Policy false positives |
| M17 Release Candidate | Packaging, docs, migration guide, long-haul soak | 7-day soak with no leaks, no divergence, clean simulator nightly | L | Unknown production gaps |

## Top-10 Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---:|---:|---|
| Writing our own crypto/TLS | High | Critical | Narrow TLS 1.3 scope, test vectors, external audits, dudect, staged deployment, keep escape hatch to system TLS during early bring-up |
| Writing our own mesh CRDTs | High | Critical | Deterministic Ocean before production mesh, formal invariants, Merkle repair, simple CRDT set first |
| io_uring/kTLS kernel variance | Medium | High | Portable reactor baseline, runtime probes, CI on old/new kernels |
| Hot upgrade version skew | Medium | Critical | Codec Loom capsules, min/max schema negotiation, mixed-version simulator tests |
| VEIL ratchet desync | Medium | High | Serializable ratchet vectors, skipped-key tests, forced restart-handshake path |
| IRCX legacy ambiguity | High | Medium | Golden tests mined from Ophion behavior and docs; compatibility mode flags |
| Event bus overhead | Medium | Medium | Sampling, priority classes, backpressure, zero-alloc hot events |
| Policy VM abuse or bugs | Medium | High | Deterministic bounded execution, signed policies, narrow outputs, default-off custom policies |
| Media relay cost/blast radius | Medium | Medium | Explicit quotas, per-channel caps, MASQUE optional, separate relay role |
| Zig compiler churn | High | Medium | Pinned `minimum_zig_version`, toolchain PRs, generated-code snapshots, LTS-like internal cadence |

