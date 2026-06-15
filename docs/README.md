# Orochi documentation

Orochi is a pure-Zig (0.16) clean-room IRC daemon — a bespoke successor to the
C `ophion` daemon, not a clone. It speaks IRCv3 + IRCX, runs a custom Suimyaku
CRDT mesh with forward-secret Tsumugi server links, and ships its own pure-Zig
TLS (Yoroi), media codecs (OPVOX/OPVIS), and in-place upgrade (Helix).

This tree is generated from, and cites, the live source. Where the code diverges
from convention or from the design notes in `planning/`, the docs flag it.

## Architecture
- [Overview](architecture/00-overview.md) — subsystems, request flow, source map
- [Reactor & threading](architecture/01-reactor-threading.md) — io_uring + sharded workers
- [World, dispatch & modules](architecture/02-world-dispatch-modules.md) — the SerpentRegistry command system
- [Mesh & S2S](architecture/mesh-s2s.md) — Suimyaku CRDT, links, partition detection, oper-grant sharing
- [Mesh security](architecture/mesh-security.md) — threat model, AEAD record layer, self-certifying per-frame & multi-hop origin signing, media stream-id capabilities
- [Cryptography](architecture/crypto.md) — Tsumugi handshake, Yoroi, signing, sealed tokens
- [Media](architecture/03-media.md) — SFU, transport stack, codecs, WASM shims
- [Upgrade & WASM host](architecture/04-upgrade-wasm.md) — Helix in-place upgrade, OroWasm plugins

## Command reference
- [Index](reference/commands/_index.md) — every command, one line each
- [Connection & registration](reference/commands/connection.md)
- [Messaging](reference/commands/messaging.md)
- [Channels](reference/commands/channels.md)
- [Queries](reference/commands/queries.md)
- [Informational](reference/commands/informational.md)
- [Operator & moderation](reference/commands/oper-moderation.md)
- [Mesh operations](reference/commands/mesh-ops.md)
- [Accounts & services](reference/commands/accounts-services.md)
- [IRCX](reference/commands/ircx.md)
- [Media](reference/commands/media.md)

## Protocol reference
- [Numerics](reference/protocol/numerics.md)
- [Modes](reference/protocol/modes.md) — user & channel modes, status prefixes
- [ISUPPORT (005)](reference/protocol/isupport.md)
- [Capabilities (IRCv3)](reference/protocol/caps.md)

## Configuration
- [Config reference](reference/config.md) — every section and key
- [`etc/orochi.reference.toml`](../etc/orochi.reference.toml) — runnable annotated example

## Operator guide
- [Quickstart](guide/00-quickstart.md)
- [Building](guide/build.md)
- [TLS](guide/tls.md)
- [Operators](guide/operators.md) — SASL-only oper setup
- [Mesh / S2S linking](guide/mesh.md)
- [In-place upgrade](guide/upgrade.md)
- [Persistence](guide/persistence.md) — OroStore

## Design notes
`planning/` holds the original design intent (PRDs, architecture spikes). It is
historical: where it disagrees with current behavior, the docs above — verified
against the code — are authoritative.
