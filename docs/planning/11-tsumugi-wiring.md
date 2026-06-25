# 11 — Tsumugi handshake to live S2S wiring

*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

Plans task #2: replace the plaintext S2S handshake with the Tsumugi PQ-hybrid AKE, based on a read-only planning pass over live code.

## Verified facts

| Area | Fact |
|---|---|
| NodeId types | **Two NodeId types coexist.** Live path: `NodeId = u64` (`membership_view.zig:11` → `gossip_round.zig` → `s2s_peer.zig:21`, `s2s_link.zig:24`); load-bearing across registry, routes, CRDT replica lane, SWIM. Crypto path: `NodeId = [20]u8 = BLAKE3-160(Ed25519 pubkey)` (`tsumugi_handshake.zig` `nodeIdFromKey`, identical to `signed_delta.zig:53` `nodeIdFromPublicKey`). |
| Current handshake | **Current handshake is symmetric & plaintext** (`s2s_peer.zig`): `Handshake` struct carries only `node_id:u64`; both sides `startHandshake`→`emitHandshake`; `recvHandshake` adopts `remote_node_id`, replies if not sent, then `session.establish` + BURST. Magic `"S2PH"`. |
| Tsumugi shape | **Tsumugi is asymmetric & IK-shaped.** `Initiator.start(rng)→M1` requires the initiator to already hold the responder's `SignedPrekey`. `Responder.recv(M1)→M2`, `Initiator.recv(M2)→Established`. Needs each side: `sign.KeyPair`, `xwing.KeyPair` + `SignedPrekey`, `Config{realm, supported_bands, supported_features, mesh_pass, now_ms}`, and a `std.Io` rng (not the `u64` seed the live path threads). |
| Established output | `Established` exposes crossed `send_key/recv_key`, nonces, `peer_node_id:[20]u8` — **but NOT the peer pubkey** (gap for signed-delta verify). |

## Identity bridge

Keep `u64` as the operational mesh id, and add Ed25519 identity alongside. Each node
holds a `sign.KeyPair`; its 20-byte id is authoritative for signing. **Derive the
`u64` from the pubkey** (first 8 bytes LE of the BLAKE3-160 id) so a node can't
claim a `u64` mismatching its key. Handshake must exchange the Ed25519 pubkey
(Tsumugi carries it in encrypted M1/M2; capture it).

## Phases

| Phase | Scope |
|---|---|
| **Phase 0 (smallest safe step, no wire change)** | Add `Config.node_key:?sign.Seed` + a derivation helper producing the `sign.KeyPair` and `u64 node_id`; fall back to existing `node_id:u64` when absent. Unit test: stable derivation from fixed seed. |
| **Phase 1 (identity + pubkey exchange, frames stay plaintext)** | Dialing side = Initiator (`handleConnect`/`link.start`, server.zig:2778), accepting side = Responder (server.zig:885). Resolve IK constraint with an **in-band prekey-offer pre-M1 step**: responder emits its `SignedPrekey` on accept; initiator defers `start()` until it has the prekey — `driveS2s`/`handleConnect` already tolerate "no outbound yet". Replace `recvHandshake`/`startHandshake` with M1/M2 drive; bridge 20-byte id → `u64` then run existing adopt logic. **Extend `Established` with `peer_node_key: sign.PublicKey`** (edit `deriveEstablished` + both `recv`). |
| **Phase 2 (optional frame AEAD)** | Add a `SecureChannel` owning send/recv keys + per-direction monotonic nonce counter; seal in `emitFrame`, open in `dispatch` (except handshake frames). Gate behind a flag. Nonce reuse is catastrophic → monotonic counters, rekey on exhaustion. |
| **Phase 3 (end-to-end signed-delta verify)** | `sendDelta` signs with local key; `mergeDelta` decodes `signed_delta.decodeSigned` + `verifyOne(peer_node_key)`, rejecting bad. Third-party (gossiped) deltas need a `[20]u8→pubkey` keystore; first cut limited to direct-peer-authored deltas. |

## New `Options` fields

Add these fields to `s2s_link.zig` + `s2s_peer.zig`; all are optional with
plaintext fallback:

```zig
local_node_key: ?*const sign.KeyPair = null,
local_prekey: ?tsumugi.SignedPrekey = null,
local_prekey_secret: ?*const xwing.SecretKey = null,
realm: tsumugi.RealmId = [_]u8{0} ** 32,
supported_bands: u128 = 1,
supported_features: u128 = 0,
mesh_pass: []const u8 = &.{},
rng: ?std.Io = null,
```

Plus `server.zig:Config`: `node_key:?sign.Seed`, `realm:[32]u8`, `supported_bands:u128=1`.
Use realtime ms (`platform.realtimeMillis`) for Tsumugi `now_ms`/prekey validity,
not the monotonic link-timer ms.

## Test impact (keep green via optional/fallback until secure path has its own tests)

| Area | Impact |
|---|---|
| `s2s_peer.zig` | "two s2s peer drivers handshake and converge…" (newPeer), PING/PONG, partial-inbound — need keypair/prekey/rng or fallback; add a `DeterministicIo` (copy from `tsumugi_handshake.zig`). |
| `s2s_link.zig` | "two links handshake…" (line 163), "consumeOutbound…" (215). |
| `server.zig` | S2S integration tests ~6354–6477 (`node_id` ints → `node_key` seeds or fallback + deterministic `std.Io`). |

## Risks (ranked)

| Rank | Risk | Resolution |
|---|---|---|
| 1 | IK prekey availability (biggest protocol-shape change) | in-band prekey offer. |
| 2 | `Established` lacks peer pubkey | extend it. |
| 3 | RNG plumbing (`u64` seed vs `std.Io`) | add `std.Io` to Options; tests reuse DeterministicIo. |
| 4 | `u64`↔`[20]u8` truncation collisions | key all crypto off the full 20-byte id. |
| 5 | Third-party signed deltas | keystore later; first cut direct-peer only. |
| 6 | AEAD nonce management | per-direction monotonic, rekey on exhaustion. |
| 7 | Clock-domain mix-up | realtime ms for crypto validity. |

Smallest safe first step: **Phase 0**.
