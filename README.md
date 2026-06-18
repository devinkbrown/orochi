# Orochi 🐉

**Orochi** (水蛟 — the coiling water-dragon) is the successor to the
[ophion](https://github.com/devinkbrown/ophion) IRC daemon: a **100% clean-slate,
fully Zig-native** rewrite. The daemon *and its entire substrate* — the systems
library and the crypto/TLS stack — are written from scratch in Zig with **no C
interop**. It keeps ophion's full feature surface (IRCv3, IRCX, SASL, in-process
services, WebSocket, CHATHISTORY, voice/video), adds class-based connection
policy with bounded growable SendQ/RecvQ and nick-delay protection, and replaces
the legacy TS6 server-to-server protocol with the native **Suimyaku + Tsumugi**
cryptographic mesh.

> **Status: in production.** Runs a live two-node post-quantum mesh with
> session-preserving `USR2` hot-upgrades, serving IRCv3/IRCX clients and a
> browser WebSocket client. Full IRCv3 + IRCX + SASL surface, in-process
> channel/nick services, class-based connection policy, a single runtime flood
> guard, `+j` network raid protection, and spam-trap honeypots. 900+ Zig source
> files (300+ daemon modules), 6,900+ tests green under Zig 0.16. See
> [`docs/BRIEF.md`](docs/BRIEF.md) and [`docs/guide/`](docs/guide/).

## Design pillars
- **Zig top to bottom, no C interop.** Substrate, crypto, daemon, and tooling are
  all Zig; `comptime` replaces ophion's MAPI module machinery and generates wire
  codecs and dispatch tables.
- **Mesh, not tree.** **Suimyaku** (水脈) — a CRDT state mesh with Sazanami gossip and
  Merkle anti-entropy — over **Tsumugi** (紬) — a PQ-hybrid (X25519 + ML-KEM-768)
  forward-secret ratchet. No TS6.
- **Safety as a type.** `Secret(T)` makes a data-dependent branch on secret bytes a
  compile error; TLS is **1.3 + a hardened 1.2 profile** (AEAD/ECDHE-only; no RSA key exchange, CBC, compression, or renegotiation).
- **Trust through simulation.** Deterministic-simulation testing (the *Deterministic
  Ocean* harness) drives the CRDT mesh and crypto via injected clock/net/RNG, so any
  failure replays from a 64-bit seed.
- **Policy at registration.** `[class.*]` connection classes match IPv4/IPv6 CIDR,
  implicit TLS, SASL account state, oper state, ident, and host globs, then apply
  per-class sendq/recvq, flood, admission, clone, channel, target, monitor,
  silence, ping, and registration-timeout policy.
- **Elastic queues, explicit bounds.** Outbound SendQ and inbound RecvQ stay inline
  on the hot path and spill to heap overflow only when needed, bounded by the
  matched class. Optional `[limits].nick_delay` holds released nicks after exit to
  reduce nick camping, while `STATS Y`, `STATS l`, and richer `INFO` expose the
  live policy and mesh state.
- **Layered anti-abuse.** A single per-connection flood guard (keep-alives free,
  commands weighted, distinct-target spread throttle, decaying excess →
  disconnect) derived from each class's policy; a `+j` join-throttle with a
  network-wide raid-guard default (`[limits].raid_joins`) and one-shot operator
  raid alerts; operator-designated spam-trap honeypots (`SPAMTRAP`); and
  first-class nick services (`RECOVER`/`RELEASE`, per-account `SECURE`/`ENFORCE`)
  — all real server commands, no pseudo-clients.
- **Full feature parity** with ophion — no regressions.

## Architecture
| Package | Role |
|---|---|
| `src/substrate` | Ringlane io_uring reactor, lock-free queues, allocators, and the Suimyaku math (HLC/vector clocks, delta-state CRDTs, Merkle sync, Sazanami, sketches) + the Deterministic Ocean simulator |
| `src/crypto` | `Secret(T)`, SHA-2/HMAC/HKDF, AEADs, X25519 + ML-KEM key schedule, Tsumugi ratchet |
| `src/proto` | zero-copy IRCv3 parser, CoilPack wire codec, CAP FSM, Suimyaku frame layer, SASL |
| `src/daemon` | SerpentRegistry (comptime modules), client/channel model, connection classes, growable SendQ/RecvQ, nick delay + nick services, runtime flood guard, `+j` raid guard, spam-trap, command dispatch, OroStore, `STATS`/`INFO`, the live mesh server |

## Build & run
```sh
zig build              # build (Zig 0.16)
zig build test         # ~6,900 tests
zig build release      # optimized, stripped ReleaseFast daemon -> zig-out/bin/orochi
zig build run          # start the daemon (listens on 127.0.0.1:6680)
./tools/genroots.sh    # regenerate package-root imports from the files present
```

## License
Clean-room — intentionally **not** inheriting ophion's GPL lineage. License TBD.
