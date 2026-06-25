# Orochi 🐉

> A pure-Zig, clean-room IRC daemon — IRCv3 · IRCX · SASL · in-process services ·
> browser WebSocket · voice/video — over a post-quantum cryptographic mesh, with no C interop.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Zig 0.16](https://img.shields.io/badge/Zig-0.16-f7a41d?logo=zig&logoColor=white)](https://ziglang.org)
[![C interop: none](https://img.shields.io/badge/C%20interop-none-success.svg)](#design-pillars)
[![Status: in production](https://img.shields.io/badge/status-in%20production-success.svg)](#status)

**Orochi** (水蛟 — the coiling water-dragon) is a **100% clean-slate, fully Zig-native**
IRC daemon and the successor to the C [ophion](https://github.com/devinkbrown/ophion)
server. The daemon *and its entire substrate* — the systems library and the crypto/TLS
stack — are written from scratch in Zig with **no C interop**. It keeps ophion's full
feature surface (IRCv3, IRCX, SASL, in-process services, WebSocket, CHATHISTORY,
voice/video), adds class-based connection policy with bounded growable SendQ/RecvQ and
nick-delay protection, and replaces the legacy TS6 server-to-server protocol with the
native **Suimyaku + Tsumugi** cryptographic mesh.

**Quick links:** [Quickstart](docs/guide/00-quickstart.md) ·
[Documentation](docs/README.md) · [Architecture](docs/architecture/00-overview.md) ·
[Command reference](docs/reference/commands/_index.md) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [License](LICENSE)

## Highlights

- **Pure Zig, top to bottom** — substrate, crypto, TLS, and daemon, with zero C dependencies.
- **Post-quantum mesh** — a CRDT state mesh over an X25519 + ML-KEM-768 forward-secret ratchet, replacing TS6.
- **Full IRCv3 + IRCX + SASL** — including CHATHISTORY, the Event Spine, and in-process channel/nick services (no pseudo-clients).
- **Browser-native** — a first-class WebSocket listener and a voice/video media plane.
- **Operates like a daemon should** — class-based admission policy, layered anti-abuse, and session-preserving `USR2` hot-upgrades.

## Design pillars

- **Zig top to bottom, no C interop.** Substrate, crypto, daemon, and tooling are all
  Zig; `comptime` replaces ophion's MAPI module machinery and generates wire codecs and
  dispatch tables.
- **Mesh, not tree.** **Suimyaku** (水脈) — a CRDT state mesh with Sazanami gossip and
  Merkle anti-entropy — over **Tsumugi** (紬) — a post-quantum-hybrid (X25519 + ML-KEM-768)
  forward-secret ratchet. No TS6. Operator surfaces are network-wide: the Event Spine
  (connect/quit/oper alerts and the targeted `EVENT OBSERVE` feed) fans every event to
  all nodes rendered with the origin server, and a cross-node `MODE` shows the setter's
  nick, not the server.
- **Safety as a type.** `Secret(T)` makes a data-dependent branch on secret bytes a
  compile error; TLS is **1.3 plus a hardened 1.2 profile** (AEAD/ECDHE-only; no RSA key
  exchange, CBC, compression, or renegotiation).
- **Trust through simulation.** Deterministic-simulation testing (the *Deterministic
  Ocean* harness) drives the CRDT mesh and crypto via injected clock/net/RNG, so any
  failure replays from a 64-bit seed.
- **Policy at registration.** `[class.*]` connection classes match IPv4/IPv6 CIDR,
  implicit TLS, SASL account state, oper state, ident, and host globs, then apply
  per-class sendq/recvq, flood, admission, clone, channel, target, monitor, silence,
  ping, and registration-timeout policy.
- **Elastic queues, explicit bounds.** Outbound SendQ and inbound RecvQ stay inline on
  the hot path and spill to heap overflow only when needed, bounded by the matched class.
  Optional `[limits].nick_delay` holds released nicks after exit to reduce nick camping,
  while `STATS Y`, `STATS l`, and richer `INFO` expose the live policy and mesh state.
- **Layered anti-abuse.** A single per-connection flood guard (keep-alives free, commands
  weighted, distinct-target spread throttle, decaying excess → disconnect) derived from
  each class's policy; a `+j` join-throttle with a network-wide raid-guard default
  (`[limits].raid_joins`) and one-shot operator raid alerts; operator-designated
  spam-trap honeypots (`SPAMTRAP`); and first-class nick services (`RECOVER`/`RELEASE`,
  per-account `SECURE`/`ENFORCE`) — all real server commands, no pseudo-clients.

## Architecture

| Package | Role |
|---|---|
| `src/substrate` | Ringlane `io_uring` reactor, lock-free queues, allocators, the Suimyaku math (HLC/vector clocks, delta-state CRDTs, Merkle sync, Sazanami, sketches), and the Deterministic Ocean simulator |
| `src/crypto` | `Secret(T)`, SHA-2/HMAC/HKDF, AEADs, X25519 + ML-KEM key schedule, the Tsumugi ratchet, and the Yoroi TLS stack |
| `src/proto` | zero-copy IRCv3 parser, CoilPack wire codec, CAP state machine, Suimyaku frame layer, SASL |
| `src/daemon` | SerpentRegistry (comptime modules), client/channel model, connection classes, growable SendQ/RecvQ, nick delay and nick services, runtime flood guard, `+j` raid guard, spam-trap, command dispatch, OroStore, `STATS`/`INFO`, and the live mesh server |

See the [architecture overview](docs/architecture/00-overview.md) for subsystems, request
flow, and a full source map.

## Build & run

Orochi targets **Zig 0.16** on 64-bit Linux (the reactor uses `io_uring`).

```sh
zig build              # build the daemon
zig build check        # fast semantic analysis, no binary
zig build test         # run the full test suite
zig build release      # optimized, stripped ReleaseFast daemon -> zig-out/bin/orochi
zig build run          # run the daemon locally
./tools/genroots.sh    # regenerate package-root imports from the files present
```

Start from the [quickstart](docs/guide/00-quickstart.md), then see the
[operator guide](docs/guide/operators.md), [TLS guide](docs/guide/tls.md), and
[mesh guide](docs/guide/mesh.md). A complete, commented configuration reference lives in
[`docs/reference/config.md`](docs/reference/config.md) and
[`etc/orochi.reference.toml`](etc/orochi.reference.toml).

## Documentation

The [`docs/`](docs/README.md) tree is grounded in, and cites, the live source:

- **[Guides](docs/guide/00-quickstart.md)** — quickstart, build, TLS, mesh, operators, persistence, upgrade.
- **[Architecture](docs/architecture/00-overview.md)** — reactor and threading, dispatch and modules, mesh, cryptography, media, upgrade.
- **[Reference](docs/reference/commands/_index.md)** — every command, the config schema, IRCv3/IRCX, modes, numerics, and ISUPPORT.

## Status

**In production.** Orochi runs a live two-node post-quantum mesh with session-preserving
`USR2` hot-upgrades, serving IRCv3/IRCX clients and a browser WebSocket client. The
surface includes full IRCv3 + IRCX + SASL, in-process channel/nick services, class-based
connection policy, a single runtime flood guard, `+j` network raid protection, and
spam-trap honeypots. The tree is 900+ Zig source files (300+ daemon modules) with a
deterministic-simulation test suite, all building under Zig 0.16.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, and
pull-request guidance. Report security issues privately per [SECURITY.md](SECURITY.md).

## License

Orochi is licensed under the **GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later)**. See [`LICENSE`](LICENSE) for the full text; every source file
carries an SPDX header.

Orochi is clean-room — it does **not** derive from ophion's code, so this license is
chosen freely rather than inherited. AGPL is deliberate: Orochi is a network server, and
§13 ("Remote Network Interaction") means **anyone who runs a modified Orochi as a network
service — for example, operating an IRC network — must offer that service's users the
complete corresponding source of their modifications.** Running a private, unmodified
copy carries no such obligation; the requirement attaches only to changes you put into
service. The daemon advertises its source location (the `INFO` source URL) to satisfy
§13's prominent-offer requirement for interactive network users.

Copyright © 2026 Devin Brown.
