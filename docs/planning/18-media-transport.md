# 18 — Media Transport Plane (SFU): ICE/STUN + SRTP over UDP

Status: **live**. The signaling plane, the UDP transport plane, ICE connectivity,
SDES SRTP keying, and the selective-forwarding relay are all implemented, wired into the
daemon, and verified end-to-end (real UDP sockets, real STUN crypto, RFC-vectored SRTP).
This document consolidates the architecture and the on-the-wire contract so the browser /
Ocean client can be built against it and the remaining arcs (DTLS-SRTP, RTCP/NACK) have a
stable base to extend.

The thesis, in one line: **Mizuchi is its own selective-forwarding unit — a participant
runs ICE to the server, the server distributes one SRTP key per call over the
TLS-protected IRC link, and the server relays opaque ciphertext between participants
without ever seeing plaintext.** Everything is clean-room pure Zig on the existing
`stun` / `ice` / `rtp_profile` / `srtp` substrate; no libwebrtc, no C.

---

## 0. What already exists (do not re-invent)

- `src/proto/stun.zig` — RFC 5389 STUN framing: decode, MESSAGE-INTEGRITY (HMAC-SHA1),
  FINGERPRINT (CRC32), XOR-MAPPED-ADDRESS, `buildBindingSuccessResponse`.
- `src/proto/ice.zig` — `TransportAddress`, `Candidate`, `Agent`, candidate pairing /
  priority / checklist ordering (RFC 8445).
- `src/proto/rtp_profile.zig` — RTP/RTCP header encode/decode, jitter + receiver-stats.
- `src/proto/srtp.zig` — RFC 3711 transform: AES-CM KDF + AES-128-CTR encryption +
  HMAC-SHA1-80 auth. **KDF validated against RFC 3711 Appendix B.3 vectors.**
- `src/substrate/media_transport.zig` — the SFU control core (registry + routing).
- `src/substrate/media_socket.zig` — live IPv4 `SOCK_DGRAM` socket + STUN/RTP demux.
- `src/daemon/media_plane.zig` — threaded owner: socket + registry + pump thread + mutex.
- `src/daemon/server.zig` — `MEDIA` command surface and the daemon wiring.

---

## 1. Architecture

```
  IRC client (TLS)                         Mizuchi daemon
  ─────────────────                        ─────────────────────────────────
  MEDIA OFFER  ───────────────────────▶    mediaOffer:
                                             • media_session.negotiate (codecs/FEC)
                                             • media_rooms.setProfile
                                             • media_plane.allocate  → ICE ufrag/pwd
                                             • media_plane.groupKey   → SRTP key (SDES)
  ◀───────────────  NOTE MEDIA OFFER-ACK / PROFILE / TRANSPORT
                                                                  ▲ signaling plane (TCP/TLS)
  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
  STUN bind  ════════ UDP ═════════════▶    pump thread (media_plane):
  (HMAC keyed by pwd)                        • MediaSocket.recvFrom
  ◀═══════ STUN success (XOR-MAPPED) ═══     • demux STUN vs RTP (RFC 5764)
                                             • handleStunBinding → bind peer addr
  SRTP/RTP  ════════ UDP ═════════════▶      • validate RTP framing, learn SSRC
                                             • forwardFromSource → relay to peers
  ◀═══════ relayed SRTP (opaque) ═══════                          ▼ transport plane (UDP)
```

Two planes, deliberately separate:

- **Signaling plane** rides the existing TLS IRC connection (the `MEDIA` command family).
  It is reliable, ordered, authenticated, and already encrypted — the natural carrier for
  codec negotiation, ICE credentials, and the SRTP key (SDES).
- **Transport plane** is a dedicated UDP socket with its own pump thread, *not* folded into
  the io_uring TCP loop. Media I/O is hot and self-contained; a separate socket keeps it
  off the client/S2S event loop. The two threads share `MediaTransport` under one coarse
  `std.atomic.Mutex` (STUN/keying are low-rate; the relay does one map lookup per packet).

## 2. The endpoint registry (`MediaTransport`)

Per call participant, keyed by `"channel\x00participant"`:

- `ufrag`/`pwd` — ICE short-term credentials (RFC 8445 §5.3) the server offers.
- `remote` — the peer's bound UDP address, set once a STUN check authenticates.
- `ssrc` — learned from the first RTP packet.
- `rx_packets`/`rx_bytes` — relay metering.

Three indexes: `by_ufrag` (STUN USERNAME demux), `by_addr` (RTP source → participant), and
`group_keys` (channel → 30-byte SRTP master key+salt, one per call, dropped when empty).

Key operations: `allocate` (issue creds), `byServerUfrag` + `handleStunBinding` (auth +
bind), `forwardFromSource` (RTP source → SFU relay set), `ensureGroupKey`, `statsForChannel`.

## 3. ICE / STUN flow

1. `MEDIA OFFER` → server `allocate`s an endpoint and advertises `ufrag`/`pwd` + a host
   candidate (`media_host:media_port`) in the `TRANSPORT` line.
2. Client sends a STUN binding request to the candidate, USERNAME = `<server-ufrag>:<peer>`,
   MESSAGE-INTEGRITY keyed by the server `pwd`.
3. Pump demuxes (top two bits zero ⇒ STUN), `handleStunBinding` looks up the endpoint by
   server ufrag, verifies integrity, **binds the source address**, and returns a binding
   success response (XOR-MAPPED-ADDRESS = source, integrity, fingerprint).
4. The bound address becomes the SFU forward target for that participant.

## 4. SRTP (SDES keying)

- The server generates **one SRTP master key+salt per call** (30 bytes, CSPRNG) on first
  `OFFER` and distributes it to every participant as `srtp=<base64>` in `TRANSPORT`. Safe
  because the IRC link is TLS.
- Participants derive session keys with `srtp.deriveSessionKeys` and `protect`/`unprotect`
  media end-to-end. **The SFU relays ciphertext opaquely — it never holds the session keys
  beyond distribution, and never sees plaintext.** This is the privacy-preserving model.
- The key is released when the last participant leaves the call.

## 5. RTP relay (the SFU)

The pump, for a non-STUN datagram:

1. Require version-2 RTP/RTCP framing (`byte0 & 0xC0 == 0x80`, ≥ 12 bytes) — otherwise drop,
   so a bound peer cannot turn the port into an open UDP reflector.
2. For RTP (not RTCP per the RFC 5761 mux rule: byte 1 ∉ 192–223) decode the header and
   learn the SSRC.
3. `forwardFromSource(source, len, ssrc)` → meters the sender and returns the bound remotes
   of every **other** connected participant in the call; `sendTo` each.

## 6. Wire protocol (signaling)

All server→client lines: `:<server> NOTE MEDIA <#chan> <verb> …`.

| Verb | Direction | Payload |
|------|-----------|---------|
| `OFFER-ACK` | →caller | `codecs=<list> fec=<scheme>` (negotiated set) |
| `PROFILE` | →room | `codecs=<list> fec=<scheme>` (call converges) |
| `ANSWER-ACK` | →answerer | `codecs=<list> fec=<scheme>` (intersection) |
| `TRANSPORT` | →caller | `ufrag=<u> pwd=<p> candidate=<ip>:<port> srtp=<base64>` |
| `STATS` | →caller | `<nick> ice=<connected\|pending> ssrc=<hex> rx_pkts=<n> rx_bytes=<n>` |
| `ROSTER`/`JOIN`/`LEAVE`/`MUTE`/… | →room | media-room presence (see `media_room.zig`) |

Client commands: `MEDIA OFFER|ANSWER|PROFILE|STATS|JOIN|LEAVE|ROSTER|MUTE|UNMUTE|SPEAKING
|BREAKOUT|POS|HAND|REACT|CAPTION|TRANSCRIPT <#chan> …`.

## 7. Config

- `server.Config.media_port` — UDP port for the media plane (0 = ephemeral). The boot
  path calls `media_plane.start`; a bind failure is non-fatal (IRC keeps serving).
- `server.Config.media_host` — the IP advertised to clients as the server candidate.
  (Not yet surfaced in the `config_format` TOML schema — wire it there when deploying.)

## 8. Verified end-to-end

- STUN: real client binding request (HMAC-SHA1 + CRC32) → daemon answers `0x0101` success.
- Relay: two clients OFFER, complete ICE, an RTP packet from one is relayed byte-for-byte
  to the other; garbage from a bound peer is dropped; `STATS` shows `ssrc`/`rx_pkts`.
- SRTP: both participants receive the identical 30-byte `srtp` key; `srtp.zig` protect/
  unprotect round-trips and rejects tamper; KDF matches RFC 3711 B.3.

## 9. Remaining arcs (each separately scoped)

- **DTLS-SRTP** — per-hop key agreement (a DTLS handshake on the media socket) as an
  alternative to SDES, for deployments that want forward secrecy on the media leg.
  `src/proto/dtls_record.zig` is the substrate.
- **RTCP / NACK retransmission** — a retransmit cache + RTCP feedback handling on the relay
  (`src/proto/rtp_nack.zig` exists, dark).
- **Public-candidate discovery** — derive the server-reflexive candidate instead of relying
  on the configured `media_host` (e.g. STUN to an external reflector at boot).
- **Browser / Ocean client** — the WASM transport shim + WebRTC bridge that consumes this
  contract (proprietary client; tracked separately).
