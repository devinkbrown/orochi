# Mizuchi 🐉

**Mizuchi** (水蛟 — the coiling water-dragon) is the successor to the
[ophion](https://github.com/devinkbrown/ophion) IRC daemon: a clean-slate **Zig**
rewrite that keeps ophion's full feature surface (IRCv3, IRCX, SASL, services,
WebSocket, CHATHISTORY) and replaces the legacy TS6 server-to-server protocol
with the native **Suimyaku + Tsumugi** cryptographic mesh.

Mizuchi builds on two C libraries via Zig's C interop:
- **libop** — event loop (io_uring), lock-free queues, CRDTs, vector clocks,
  Merkle delta sync, and the rest of the systems substrate.
- **opssl** — the TLS 1.2/1.3 + crypto stack (Ed25519, X25519, AES-GCM, ML-KEM).

> Status: **architecture & planning.** See [`docs/BRIEF.md`](docs/BRIEF.md) and
> [`docs/planning/`](docs/planning/).

## Design pillars
- **Zig core, C substrate.** Consume libop/opssl; never reimplement crypto or the
  event loop. `comptime` replaces ophion's MAPI module machinery.
- **Full feature parity** with ophion — no regressions.
- **Mesh, not tree.** Suimyaku (CRDT + SWIM gossip + Merkle sync) over Tsumugi
  (Ed25519 mutual auth, X25519 forward secrecy, per-frame HMAC, ratchet).

## License
GPL-2.0-or-later (matching ophion), pending confirmation.
