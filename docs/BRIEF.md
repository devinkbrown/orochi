# Orochi — architecture brief (source of truth)

*Clean-slate, Zig-native successor to the ophion IRC daemon.*

Orochi (大蛇 — the eight-forked great serpent) is a 100% clean-slate, Zig-native
system: the daemon *and its entire substrate* (the libop systems library and the
opssl crypto/TLS library) are rewritten from scratch in Zig. ophion, libop, and
opssl are reference only — we mine them for the feature inventory, the hard-won
lessons, and the Suimyaku/Tsumugi conceptual foundation, then design something
better.

Orochi keeps ophion's full feature surface (IRCv3, IRCX, SASL, in-process
services, WebSocket, CHATHISTORY, voice/video) and replaces the legacy TS6 S2S
protocol with the native Suimyaku + Tsumugi cryptographic mesh.

The daemon policy surface is explicit and inspectable. `[class.*]` connection
classes match clients at registration by IPv4/IPv6 CIDR, implicit TLS, SASL
account state, oper state, ident glob, and host glob, then apply per-class
overrides for SendQ/RecvQ, flood, admission, clone, channel, target,
MONITOR/SILENCE, PING, and registration timeout. The first configured class whose
criteria all match wins, ahead of the built-in `user` and `server` fallbacks that
cover ordinary clients and mesh links.

Queueing is elastic but bounded. Outbound SendQ uses an inline buffer plus heap
overflow under the matched class's `sendq` cap; inbound RecvQ applies the same
idea to one pending unterminated line under `recvq` (`0` keeps the physical
line-buffer default). SendQ appends fail when the cap would be exceeded; RecvQ
lines that exceed the cap drop the connection as too long. `[limits].nick_delay`
optionally holds a released nick after disconnect or QUIT to reduce nick camping;
voluntary `NICK` changes are not held, and the owning account, server operators,
and `nick_delay_exempt` classes may bypass the hold. Operators inspect class
policy and live member counts with `STATS Y`, established mesh-peer SendQ state
with `STATS l`, and advertised limits, class count, nick-delay state, mesh-peer
count, and subsystem inventory through `INFO`.

## Mandate: 100% freedom to invent

This is not a port. Every worker has license to invent new technologies,
algorithms, and abstractions that a from-scratch Zig design makes possible. Prefer
a novel, principled design over replicating a C idiom. Use `comptime`
aggressively. Question every assumption ophion baked in. Where we invent
something, name it and specify it well enough to build.

## Why Zig (decided 2026-06-02)

- `comptime` is a first-class metaprogramming engine: module systems, protocol
  codecs, constant-time crypto selection, and zero-cost typed abstractions are
  generated at compile time, not hand-written.
- Manual memory and explicit allocators with ReleaseSafe bounds, overflow, and
  null checks deliver the control of C with a real safety floor, and without
  Rust's borrow-checker tax on lock-free code.
- io_uring plus a futex worker pool is the execution model; language async is
  irrelevant.
- Single language top to bottom: substrate, crypto, daemon, and tooling are all
  Zig, all cross-compilable to x86-64 and ARM64 from one toolchain.

## Scope of the rewrite (everything is ours)

1. **Substrate (libop successor, Zig-native).** Event loop (io_uring), lock-free
   concurrency, allocators and arenas, the full data-structure kit, and the
   Suimyaku math substrate (CRDTs, vector and hybrid-logical clocks, Merkle delta
   sync, gossip). Reimagine these with comptime and Zig semantics; invent new
   primitives.
2. **Crypto and TLS (opssl successor, Zig-native).** Modern: TLS 1.3 plus a
   hardened TLS 1.2 profile, post-quantum-hybrid by default, constant-time *by
   construction* (ideally comptime-verified), plus the Tsumugi transport crypto.
   Invent where the design allows.
3. **Daemon core, comptime module system, and 100% feature parity** with ophion,
   including class-based admission and resource policy, bounded growable
   SendQ/RecvQ, nick-delay protection, and `STATS`/`INFO` introspection.
4. **Suimyaku + Tsumugi mesh** as the only S2S protocol (no TS6): CRDT network
   state, Sazanami gossip, Merkle anti-entropy, and Tsumugi frame crypto plus
   ratchet. Innovate on the spec, don't just implement it.

## Hard constraints (few, deliberate)

1. **Feature parity is non-negotiable.** Every IRCX, IRCv3, SASL, and services
   feature in ophion must have a target home.
2. **Pin the Zig version** (`build.zig.zon` `minimum_zig_version`). Pre-1.0;
   upgrades are deliberate PRs.
3. **No TS6.** Suimyaku and Tsumugi only. Decide explicitly whether a transitional
   bridge is worth it or it is a clean break.
4. **Nick collisions rename the loser to its UID, never kill.**
5. **Constant-time crypto by construction.** No data-dependent branches or memory
   access in secret-handling paths.

## Reference paths (mine for lessons and feature inventory; do not preserve)

- ophion source: `ophion` (`ircd/`, `modules/`, `include/`)
- libop (reference): `libop` (`include/`, `src/`)
- opssl (reference): `opssl` (`include/opssl/`, `src/`)

The reference specs below use ophion's old names, superseded in Orochi by the
invented names: LADON → Suimyaku (S2S CRDT mesh), VEIL → Tsumugi (post-quantum
ratchet), SWIM → Sazanami (gossip), crdt → Goryu. They are cited only as
historical inventory.

- Suimyaku (was LADON) reference spec: `ophion/docs/protocols/ladon/`
- Tsumugi (was VEIL) reference spec: `ophion/docs/protocols/veil-security.md`
- Suimyaku media (was LADON) reference: `ophion/docs/reference/modules/m_ladon_*.md`

## Planning deliverables (this phase — Codex workers plus Claude synthesis)

- `docs/planning/01-substrate.md` — Zig-native systems substrate (libop successor).
- `docs/planning/02-crypto-tsumugi.md` — Zig-native crypto/TLS plus Tsumugi (opssl successor).
- `docs/planning/03-daemon-modules.md` — daemon core, comptime modules, feature map.
- `docs/planning/04-suimyaku-mesh.md` — client line protocol plus Suimyaku/Tsumugi mesh and CRDTs.
- `docs/planning/05-innovation.md` — invented technologies plus build, test, and roadmap.

Planning only; no production code until the design is settled and reviewed by Claude.

## Clean-room and no-legacy mandate

Every system is clean-room, modern, and inventive — no legacy ports. Banned:
WALLOPS/OPERWALL, snomask `+s`, WEBIRC, `/OPER` passwords and hostmasks (oper is
SASL certfp/SCRAM only), PASS-as-auth, ident, TS6/SJOIN, and Python modules.
LINKS and MAP are kept, reimagined as Suimyaku mesh introspection rather than a
spanning tree. See `docs/dev/zig016-notes.md`, "CLEAN-ROOM / NO-LEGACY MANDATE".

Services are internalized native commands (REGISTER, IDENTIFY, CREGISTER, ACCESS,
MEMO, and so on) with IRCv3 standard replies, not pseudo-client bots.

Cross-platform targets are Linux, macOS, BSD, and Windows (x86-64 and ARM64).
io_uring and kTLS are Linux fast paths behind the Reactor seam; everything else is
portable via comptime target dispatch. See `docs/dev/zig016-notes.md`,
"CROSS-PLATFORM MANDATE".
