# Mizuchi — Architecture Brief (source of truth)

**Mizuchi** (水蛟 — the coiling water-dragon) is the successor to the **ophion** IRC
daemon. It is a **100% clean-slate, Zig-native** system: the daemon *and its entire
substrate* (the libop systems library and the opssl crypto/TLS library) are
**rewritten from scratch in Zig**. ophion, libop, and opssl are **reference only** —
we mine them for the feature inventory, the hard-won lessons, and the Suimyaku/Tsumugi
conceptual foundation, then design something better.

Mizuchi keeps ophion's full feature surface (IRCv3, IRCX, SASL, in-process
services, WebSocket, CHATHISTORY, voice/video) and replaces the legacy **TS6** S2S
protocol with the native **Suimyaku + Tsumugi** cryptographic mesh.

## Mandate: 100% freedom — invent
This is not a port. Every worker has license to **invent new technologies,
algorithms, and abstractions** that a from-scratch Zig design makes possible.
Prefer a novel, principled design over replicating a C idiom. Use `comptime`
aggressively. Question every assumption ophion baked in. Where we invent something,
name it and specify it well enough to build.

## Why Zig (decided 2026-06-02)
- `comptime` is a first-class metaprogramming engine — module systems, protocol
  codecs, constant-time crypto selection, and zero-cost typed abstractions are
  generated at compile time, not hand-written.
- Manual memory + explicit allocators with ReleaseSafe bounds/overflow/null checks:
  the control of C with a real safety floor, and without Rust's borrow-checker tax
  on lock-free code.
- io_uring + futex worker pool is the execution model — language async is irrelevant.
- Single language top-to-bottom: substrate, crypto, daemon, tooling all in Zig, all
  cross-compilable to x86-64 + ARM64 from one toolchain.

## Scope of the rewrite (everything is ours)
1. **Substrate (libop successor, Zig-native).** Event loop (io_uring), lock-free
   concurrency, allocators/arenas, the full data-structure kit, and the Suimyaku math
   substrate (CRDTs, vector/hybrid-logical clocks, Merkle delta sync, gossip).
   Reimagine these with comptime and Zig semantics — invent new primitives.
2. **Crypto + TLS (opssl successor, Zig-native).** Modern, TLS 1.3 + a hardened 1.2 profile,
   PQ-hybrid by default, constant-time *by construction* (ideally comptime-verified),
   plus the Tsumugi transport crypto. Invent where the design allows.
3. **Daemon core + comptime module system + 100% feature parity** with ophion.
4. **Suimyaku + Tsumugi mesh** as the only S2S protocol (no TS6). CRDT network state,
   Sazanami gossip, Merkle anti-entropy, Tsumugi frame crypto + ratchet. Innovate on the
   spec, don't just implement it.

## Hard constraints (few, deliberate)
1. **Feature parity is non-negotiable** — every IRCX/IRCv3/SASL/services feature in
   ophion must have a target home.
2. **Pin the Zig version** (`build.zig.zon` minimum_zig_version) — pre-1.0; upgrades
   are deliberate PRs.
3. **No TS6.** Suimyaku+Tsumugi only. Decide explicitly if a transitional bridge is worth
   it or it's a clean break.
4. Nick collisions: **rename loser to its UID, never kill**.
5. Constant-time crypto by construction; no data-dependent branches/memory in
   secret-handling paths.

## Reference paths (mine for lessons + feature inventory; do not preserve)
- ophion source: `/home/kain/ophion` (ircd/, modules/, include/)
- libop (reference): `/home/kain/libop` (include/, src/)
- opssl (reference): `/home/kain/opssl` (include/opssl/, src/)
# Reference specs below are ophion's OLD names, superseded in Mizuchi by the
# invented names: LADON -> Suimyaku (S2S CRDT mesh), VEIL -> Tsumugi (PQ ratchet),
# SWIM -> Sazanami (gossip), crdt -> Goryu. Cited only as historical inventory.
- Suimyaku (was LADON) reference spec: `/home/kain/ophion/docs/protocols/ladon/`
- Tsumugi (was VEIL) reference spec: `/home/kain/ophion/docs/protocols/veil-security.md`
- Suimyaku media (was LADON) reference: `/home/kain/ophion/docs/reference/modules/m_ladon_*.md`

## Planning deliverables (this phase — Codex workers + Claude synthesis)
- `docs/planning/01-substrate.md` — Zig-native systems substrate (libop successor).
- `docs/planning/02-crypto-tsumugi.md` — Zig-native crypto/TLS + Tsumugi (opssl successor).
- `docs/planning/03-daemon-modules.md` — daemon core, comptime modules, feature map.
- `docs/planning/04-suimyaku-mesh.md` — client line protocol + Suimyaku/Tsumugi mesh + CRDTs.
- `docs/planning/05-innovation.md` — invented technologies + build/test/roadmap.

Planning only; no production code until the design is settled and reviewed by Claude.

## Clean-room / no-legacy mandate
Every system is clean-room, modern, inventive — NO legacy ports. Banned: WALLOPS/OPERWALL, snomask +s, WEBIRC, /OPER passwords+hostmasks (oper=SASL certfp/SCRAM only), PASS-as-auth, ident, TS6/SJOIN, Python modules. (LINKS/MAP are KEPT — reimagined as Suimyaku mesh introspection, not a spanning tree.) See docs/dev/zig016-notes.md "CLEAN-ROOM / NO-LEGACY MANDATE".

Services are internalized native commands (REGISTER/IDENTIFY/CREGISTER/ACCESS/MEMO/...) with IRCv3 standard-replies — NOT pseudo-client bots.

Cross-platform: targets linux/macos/bsd/windows (x86_64+aarch64). io_uring/kTLS are Linux fast-paths behind the Reactor seam; everything else portable via comptime target dispatch. See docs/dev/zig016-notes.md "CROSS-PLATFORM MANDATE".
