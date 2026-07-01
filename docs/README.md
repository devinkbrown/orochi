# Orochi documentation

*The complete guide, architecture, and reference for the Orochi IRC daemon — grounded in, and cited against, the live source.*

Orochi is a pure-Zig (0.16) clean-room IRC daemon — a bespoke successor to the C `ophion`
daemon, not a clone. It speaks IRCv3 + IRCX, runs a custom Suimyaku CRDT mesh with
forward-secret Tsumugi server links, and ships its own pure-Zig TLS (Yoroi), media codecs
(KaguraVox/KaguraVis), and in-place upgrade (Helix).

The current daemon surface includes `[class.*]` connection classes for registration-time
resource/admission/flood policy, bounded growable SendQ and RecvQ, optional nick-delay
holds against camping, and live operator introspection through `STATS Y`, `STATS l`, and
richer `INFO`.

**New here?** Start with the [Quickstart](guide/00-quickstart.md), then the
[architecture overview](architecture/00-overview.md).

## Guides

- [Quickstart](guide/00-quickstart.md) — build, configure, and run in minutes
- [Building](guide/build.md) — build targets and cross-compilation
- [TLS](guide/tls.md) — the Yoroi stack, certificates, and mTLS
- [Operators](guide/operators.md) — SASL-only operator setup and tooling
- [Mesh / S2S linking](guide/mesh.md) — linking nodes into a Suimyaku mesh
- [In-place upgrade](guide/upgrade.md) — session-preserving `USR2` hot-upgrades
- [Persistence](guide/persistence.md) — the OroStore key/value store

## Architecture

- [Overview](architecture/00-overview.md) — subsystems, request flow, source map
- [Reactor & threading](architecture/01-reactor-threading.md) — `io_uring` and sharded workers
- [World, dispatch & modules](architecture/02-world-dispatch-modules.md) — the SerpentRegistry command system
- [Mesh & S2S](architecture/mesh-s2s.md) — Suimyaku CRDT, links, partition detection, oper-grant sharing
- [Mesh security](architecture/mesh-security.md) — threat model, AEAD record layer, origin signing, media capabilities
- [Cryptography](architecture/crypto.md) — the Tsumugi handshake, Yoroi, signing, sealed tokens
- [Media](architecture/03-media.md) — SFU, transport stack, codecs, WASM shims
- [Upgrade & WASM host](architecture/04-upgrade-wasm.md) — Helix in-place upgrade, OroWasm plugins

## Command reference

- [Index](reference/commands/_index.md) — every command, one line each
- [Connection & registration](reference/commands/connection.md)
- [Messaging](reference/commands/messaging.md)
- [Channels](reference/commands/channels.md)
- [Queries](reference/commands/queries.md)
- [Informational](reference/commands/informational.md) — `INFO`, `STATS Y`, `STATS l`
- [Operator & moderation](reference/commands/oper-moderation.md)
- [Mesh operations](reference/commands/mesh-ops.md)
- [Accounts & services](reference/commands/accounts-services.md)
- [IRCX](reference/commands/ircx.md)
- [Media](reference/commands/media.md)
- [Fantasy / bot commands](reference/commands/fantasy-bot.md)

## Protocol reference

- [Numerics](reference/protocol/numerics.md)
- [Modes](reference/protocol/modes.md) — user and channel modes, status prefixes
- [ISUPPORT (005)](reference/protocol/isupport.md)
- [Capabilities (IRCv3)](reference/protocol/caps.md)
- [IRCv3](reference/ircv3.md) — capability and message-tag support
- [IRCX](reference/ircx/README.md) — the IRCX protocol surface (PROP, ACCESS, EVENT, AUTH)
- [Native media MAC](reference/native-media-mac.md) — the media authentication tag

## Configuration

- [Config reference](reference/config.md) — every section and key, including `[limits].nick_delay` and `[class.*]`
- [`etc/orochi.reference.toml`](../etc/orochi.reference.toml) — runnable, annotated example
- [Config sweep](config-sweep/README.md) — per-subsystem audit of every config key against the source

## Design notes

`planning/` holds the original design intent (PRDs, architecture spikes) and `research/`
holds the supporting research. Both are **historical**: where they disagree with current
behavior, the guides and reference above — verified against the code — are authoritative.

## Project

- [Project README](../README.md)
- [Contributing](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)
- [License (AGPL-3.0-or-later)](../LICENSE)
