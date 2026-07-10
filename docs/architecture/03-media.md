# Media architecture

*Orochi's media stack: a control-plane SFU, a WebRTC-compatible RTP/STUN UDP plane, a native KaguraVox/KaguraVis UDP leg, header-only cross-leg rewrap, a congestion/loss transport substrate, and browser/WASM codec exports.*

This document covers the current source tree only.

## SFU control plane

`src/substrate/suimyaku/media.zig` is the pure media control substrate. Its header states it owns bounded roster state, SFU forwarding decisions, simulcast layer choice, ABR hints, and codec offer/answer negotiation, with hot paths using inline storage. Evidence: `src/substrate/suimyaku/media.zig:1`, `src/substrate/suimyaku/media.zig:3`, `src/substrate/suimyaku/media.zig:4`.

| Type | Role | Evidence |
| --- | --- | --- |
| `MediaKind` | Voice, video, and screen media kinds. | `src/substrate/suimyaku/media.zig:44` |
| `ParticipantId` | Bounded inline participant id with validation. | `src/substrate/suimyaku/media.zig:84`, `src/substrate/suimyaku/media.zig:90` |
| `Participant` | Tracks joined, muted, and speaking kind sets; controls publish/receive checks. | `src/substrate/suimyaku/media.zig:112`, `src/substrate/suimyaku/media.zig:118`, `src/substrate/suimyaku/media.zig:122` |
| `Session(max_participants)` | Inline roster, join/leave/mute/speaking operations, and `forwardSet`. | `src/substrate/suimyaku/media.zig:129`, `src/substrate/suimyaku/media.zig:137`, `src/substrate/suimyaku/media.zig:148`, `src/substrate/suimyaku/media.zig:164`, `src/substrate/suimyaku/media.zig:177`, `src/substrate/suimyaku/media.zig:202` |
| `RoutePolicy` | Optional `require_speaking` forwarding gate. | `src/substrate/suimyaku/media.zig:243` |

`forwardSet` verifies the source participant exists, verifies the source can publish the requested kind, optionally requires the source to be speaking, and returns receivers that can receive the kind while excluding the source. Evidence: `src/substrate/suimyaku/media.zig:207`, `src/substrate/suimyaku/media.zig:208`, `src/substrate/suimyaku/media.zig:210`, `src/substrate/suimyaku/media.zig:211`, `src/substrate/suimyaku/media.zig:216`, `src/substrate/suimyaku/media.zig:217`, `src/substrate/suimyaku/media.zig:218`.

## Daemon media rooms

`src/daemon/media_room.zig` maps an IRC channel to a Suimyaku `Session`. Its header says this is control plane only — who is in a call, what they publish, and mute/speaking state — while media bytes flow over the transport substrate. Evidence: `src/daemon/media_room.zig:1`, `src/daemon/media_room.zig:2`, `src/daemon/media_room.zig:3`, `src/daemon/media_room.zig:4`.

| Concern | Current behavior | Evidence |
| --- | --- | --- |
| Room sizing | `max_participants` is 64 and parameterizes `media.Session(max_participants)`. | `src/daemon/media_room.zig:14`, `src/daemon/media_room.zig:15` |
| Runtime config | Breakout label cap is runtime-tunable; max participants stays comptime-bound and deferred. | `src/daemon/media_room.zig:19`, `src/daemon/media_room.zig:21`, `src/daemon/media_room.zig:34` |
| Per-channel maps | Rooms, breakouts, positions, hands, and negotiated profiles are keyed by channel/composite keys. | `src/daemon/media_room.zig:80`, `src/daemon/media_room.zig:83`, `src/daemon/media_room.zig:87`, `src/daemon/media_room.zig:90`, `src/daemon/media_room.zig:92`, `src/daemon/media_room.zig:96` |
| Codec/FEC profile | `MEDIA OFFER` establishes a per-channel `CallProfile`; `MEDIA ANSWER` consults it. | `src/daemon/media_room.zig:66`, `src/daemon/media_room.zig:93`, `src/daemon/media_room.zig:241`, `src/daemon/media_room.zig:258` |
| Room lifecycle | Join creates the room on first join; leave prunes when empty. | `src/daemon/media_room.zig:267`, `src/daemon/media_room.zig:269`, `src/daemon/media_room.zig:275` |

## RTP/STUN media plane

`src/daemon/media_plane.zig` ties the `MediaTransport` endpoint registry to a live UDP socket and pump thread. The pump demuxes datagrams, answers STUN checks, and relays RTP/RTCP under a mutex. Evidence: `src/daemon/media_plane.zig:1`, `src/daemon/media_plane.zig:4`, `src/daemon/media_plane.zig:5`, `src/daemon/media_plane.zig:6`, `src/daemon/media_plane.zig:7`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Startup | Binds UDP, records local port, optionally discovers server-reflexive candidate, sets recv timeout, spawns pump thread. | `src/daemon/media_plane.zig:108`, `src/daemon/media_plane.zig:112`, `src/daemon/media_plane.zig:114`, `src/daemon/media_plane.zig:118`, `src/daemon/media_plane.zig:124`, `src/daemon/media_plane.zig:127` |
| STUN | STUN datagrams call `transport.handleStunBinding` under the mutex and send a response if one is built. | `src/daemon/media_plane.zig:153`, `src/daemon/media_plane.zig:155`, `src/daemon/media_plane.zig:159` |
| RTP/RTCP filter | Non-STUN media must look like RTP/RTCP version 2 and be at least RTP header length, preventing open UDP reflection. | `src/daemon/media_plane.zig:162`, `src/daemon/media_plane.zig:164` |
| RTCP NACK | Generic NACK is terminated locally from the retransmit cache; other RTCP is relayed. | `src/daemon/media_plane.zig:166`, `src/daemon/media_plane.zig:169`, `src/daemon/media_plane.zig:171`, `src/daemon/media_plane.zig:174` |
| RTP relay | Decodes RTP header where possible, forwards through `transport.forwardFromSource`, caches for NACK, and sends to selected targets. | `src/daemon/media_plane.zig:176`, `src/daemon/media_plane.zig:178`, `src/daemon/media_plane.zig:190`, `src/daemon/media_plane.zig:195`, `src/daemon/media_plane.zig:207` |
| Cross-leg bridge | After RTP relay, the plane can call an installed `RtpCrossSink` to reach native participants. | `src/daemon/media_plane.zig:82`, `src/daemon/media_plane.zig:103`, `src/daemon/media_plane.zig:209`, `src/daemon/media_plane.zig:211` |
| Signaling support | `allocate` returns ICE credentials; `groupKey` returns the per-call SRTP group key; `remoteFor` resolves live WebRTC peer address. | `src/daemon/media_plane.zig:229`, `src/daemon/media_plane.zig:231`, `src/daemon/media_plane.zig:247`, `src/daemon/media_plane.zig:278` |

## DTLS-SRTP signaling and RFC 8122 fingerprint verification

Opt-in (`[media].dtls_srtp`, plus `[media].dtls13` for the DTLS 1.3 engine), the media plane terminates DTLS-SRTP (RFC 5764) on the same UDP socket. The RFC 7983 demux routes DTLS records (content-type 20..63) to the per-peer terminator; STUN/RTP/SRTP are untouched, so with the feature off the pump is byte-identical. Both the 1.2 (`src/proto/dtls12_server.zig`) and 1.3 (`src/proto/dtls13_server.zig`) terminators share one self-signed ECDSA-P256 certificate, hence one SHA-256 `a=fingerprint`.

RFC 8122 binds the SDP-signaled identity to the DTLS certificate. orochi is the DTLS **server** (`setup:passive`); the browser is the DTLS client. The signaling path (`MEDIA OFFER`/`ANSWER` in `server.zig`) advertises the daemon's fingerprint + `setup=passive` in the `TRANSPORT` reply and parses/validates/stores the peer's offered `fingerprint=sha-256:<hex>` keyed by `(channel, participant)`. When the peer's DTLS records arrive at its ICE-bound address, the pump resolves the address to that participant (`MediaTransport.compositeForSource`) and binds the expected fingerprint into the terminator (`Terminator.bindExpectedFingerprint`). At handshake completion the terminator gates `exportedKeys`/`srtpProfile`: if an expected fingerprint is bound and the peer's presented certificate has not matched it, **the keys are withheld (fail closed)** — an unverifiable peer gets no media. The comparison lives in `src/proto/dtls_peer_verify.zig` (constant-time digest compare) and is driven by `Terminator.recordPeerCertificate`, the seam a future terminator increment calls once it captures the browser's client certificate (`CertificateRequest` + `Certificate` + `CertificateVerify` possession proof); until then a signaled-but-uncaptured peer stays fail-closed. Malformed `fingerprint=` or a DTLS request while the feature is off is rejected at the boundary (`FAIL MEDIA BAD_FINGERPRINT` / `DTLS_UNAVAILABLE`), never a downgrade to the SDES group key.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Fingerprint binding | `bindOfferedFingerprint`/`dropOfferedFingerprint` store the peer's signaled fingerprint per `(channel, participant)`; the pump binds it into the terminator by resolved address on inbound DTLS. | `src/daemon/media_plane.zig` (`bindOfferedFingerprint`, `bindDtlsFingerprintFor`), `src/substrate/media_transport.zig` (`compositeForSource`) |
| Verification gate | Terminators fail closed on `exportedKeys`/`srtpProfile` for a bound-but-unverified peer; `peerVerified` reports the verdict. | `src/proto/dtls12_server.zig`, `src/proto/dtls13_server.zig`, `src/proto/dtls_peer_verify.zig` |
| USR2 continuity | The media UDP socket + fixed port survive the hot upgrade; RTP/SRTP forwarding is stateless w.r.t. the terminator, so established encrypted media flows uninterrupted. The DTLS terminator/cert is rebuilt fresh on the successor (per-peer DTLS session state is not serialized across `execve`); a peer that needs a new DTLS session re-handshakes gracefully and pins the successor's fingerprint from its next `OFFER`. | `src/daemon/helix/listener_capsule.zig` (media fd), `src/daemon/media_plane.zig` (`startDtls`) |

## Native KaguraVox/KaguraVis transport

`src/daemon/native_media_transport.zig` is the daemon-owned native UDP leg for Orochi's KaguraVox/KaguraVis codec framing. It forwards `kagura_frame` datagrams, not RTP, and never transcodes. Evidence: `src/daemon/native_media_transport.zig:1`, `src/daemon/native_media_transport.zig:2`, `src/daemon/native_media_transport.zig:3`, `src/daemon/native_media_transport.zig:15`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Channel isolation | Each call/channel has its own `NativeMediaLink`; a stream-id index maps inbound datagrams to the owning channel. | `src/daemon/native_media_transport.zig:6`, `src/daemon/native_media_transport.zig:7`, `src/daemon/native_media_transport.zig:43`, `src/daemon/native_media_transport.zig:45` |
| Startup | Binds UDP, records local port, sets recv timeout, starts pump thread. | `src/daemon/native_media_transport.zig:77`, `src/daemon/native_media_transport.zig:81`, `src/daemon/native_media_transport.zig:83`, `src/daemon/native_media_transport.zig:84`, `src/daemon/native_media_transport.zig:88` |
| Frame validation | Pump requires kagura framing and decodes before routing. | `src/daemon/native_media_transport.zig:114`, `src/daemon/native_media_transport.zig:115`, `src/daemon/native_media_transport.zig:116` |
| Forwarding | Routes by stream id, learns publisher address, computes SFU forward set, resends same bytes to each recipient. | `src/daemon/native_media_transport.zig:122`, `src/daemon/native_media_transport.zig:124`, `src/daemon/native_media_transport.zig:136` |
| Registration | `register` records channel, participant id, media kind, stream id, and address, then indexes stream id to channel. | `src/daemon/native_media_transport.zig:160`, `src/daemon/native_media_transport.zig:164`, `src/daemon/native_media_transport.zig:175`, `src/daemon/native_media_transport.zig:178` |
| Cross-leg bridge | After native forwarding, a native frame can be handed to a cross-leg sink for WebRTC participants. | `src/daemon/native_media_transport.zig:54`, `src/daemon/native_media_transport.zig:63`, `src/daemon/native_media_transport.zig:138`, `src/daemon/native_media_transport.zig:140` |

## OPCodec frame container

`src/substrate/kagura_frame.zig` is a wire container, not the audio/video codec itself. It carries encoded payloads over media bands. Evidence: `src/substrate/kagura_frame.zig:1`, `src/substrate/kagura_frame.zig:3`, `src/substrate/kagura_frame.zig:4`.

| Field/behavior | Evidence |
| --- | --- |
| Media bands are `band_id >= 64`; control bands are below 64. | `src/substrate/kagura_frame.zig:6`, `src/substrate/kagura_frame.zig:56`, `src/substrate/kagura_frame.zig:119` |
| Wire format includes payload length, band id, stream id, sequence, timestamp, keyframe flag, codec tag, and payload. | `src/substrate/kagura_frame.zig:9`, `src/substrate/kagura_frame.zig:11`, `src/substrate/kagura_frame.zig:18` |
| `CodecTag` supports `raw`, `kaguravox_audio`, and `kaguravis_video`. | `src/substrate/kagura_frame.zig:66`, `src/substrate/kagura_frame.zig:67` |
| Decode rejects truncation, control band ids, trailing bytes, and unknown codec tags. | `src/substrate/kagura_frame.zig:153`, `src/substrate/kagura_frame.zig:155`, `src/substrate/kagura_frame.zig:161`, `src/substrate/kagura_frame.zig:165`, `src/substrate/kagura_frame.zig:175` |
| ReassemblyBuffer is a bounded jitter/reorder buffer with compile-time payload/window bounds and runtime window config. | `src/substrate/kagura_frame.zig:211`, `src/substrate/kagura_frame.zig:233`, `src/substrate/kagura_frame.zig:236`, `src/substrate/kagura_frame.zig:255` |

## Cross-leg bridge

`src/daemon/media_bridge.zig` bridges participants on the native leg and the WebRTC leg by header rewrap only. Its header states that payload bytes stay opaque and are shared verbatim; there is no encoding, decoding, or transcoding. Evidence: `src/daemon/media_bridge.zig:1`, `src/daemon/media_bridge.zig:3`, `src/daemon/media_bridge.zig:7`, `src/daemon/media_bridge.zig:16`.

| Direction | Behavior | Evidence |
| --- | --- | --- |
| Native to WebRTC | Decode kagura frame, map to bridge frame, write RTP using the stream id as SSRC, send to WebRTC members. | `src/daemon/media_bridge.zig:143`, `src/daemon/media_bridge.zig:148`, `src/daemon/media_bridge.zig:152`, `src/daemon/media_bridge.zig:155`, `src/daemon/media_bridge.zig:156` |
| WebRTC to native | Decode RTP header, map to native frame with source SSRC as native stream id, encode kagura datagram, send to native members. | `src/daemon/media_bridge.zig:159`, `src/daemon/media_bridge.zig:162`, `src/daemon/media_bridge.zig:166`, `src/daemon/media_bridge.zig:168`, `src/daemon/media_bridge.zig:170` |
| Target selection | `crossTargets` copies only members on the opposite leg, excluding the sender id when provided. | `src/daemon/media_bridge.zig:174`, `src/daemon/media_bridge.zig:177`, `src/daemon/media_bridge.zig:178`, `src/daemon/media_bridge.zig:181`, `src/daemon/media_bridge.zig:182` |

The live server installs bridge callbacks around `LinuxServer.media_bridges`, `media_plane`, and `native_media`. Evidence: `src/daemon/server.zig:114`, `src/daemon/server.zig:131`, `src/daemon/server.zig:139`, `src/daemon/server.zig:158`.

## Transport stack substrate

`src/substrate/transport_stack.zig` composes a datagram transport with congestion control, pacing, rate cap, loss recovery, and qlog. It is deterministic and consumes ACKs supplied by the peer or application. Evidence: `src/substrate/transport_stack.zig:1`, `src/substrate/transport_stack.zig:5`, `src/substrate/transport_stack.zig:11`, `src/substrate/transport_stack.zig:13`, `src/substrate/transport_stack.zig:14`.

| Component | Behavior | Evidence |
| --- | --- | --- |
| Congestion control | Tiny vtable wraps L4S and BBR controllers. | `src/substrate/transport_stack.zig:30`, `src/substrate/transport_stack.zig:58`, `src/substrate/transport_stack.zig:85` |
| Send | Gates by congestion window, rate cap, and pacer, then starts send and records loss/pacing/qlog state. | `src/substrate/transport_stack.zig:203`, `src/substrate/transport_stack.zig:206`, `src/substrate/transport_stack.zig:208`, `src/substrate/transport_stack.zig:210`, `src/substrate/transport_stack.zig:213`, `src/substrate/transport_stack.zig:222` |
| Recv | Supplies a receive buffer and polls receive completions. | `src/substrate/transport_stack.zig:228`, `src/substrate/transport_stack.zig:230`, `src/substrate/transport_stack.zig:232` |
| ACK/loss | `onAck` updates loss recovery, congestion control, pacer, and qlog; `tick` detects loss for retransmit. | `src/substrate/transport_stack.zig:237`, `src/substrate/transport_stack.zig:247`, `src/substrate/transport_stack.zig:251`, `src/substrate/transport_stack.zig:252`, `src/substrate/transport_stack.zig:256` |

## WASM shims

Browser and client WASM exports are separate from the daemon plugin host.

| File | Export surface | Evidence |
| --- | --- | --- |
| `src/wasm/kagura_wasm.zig` | KaguraVox audio encode/decode and KaguraVis video intra/inter encode/decode for `wasm32-freestanding`. | `src/wasm/kagura_wasm.zig:1`, `src/wasm/kagura_wasm.zig:3`, `src/wasm/kagura_wasm.zig:17`, `src/wasm/kagura_wasm.zig:21`, `src/wasm/kagura_wasm.zig:35`, `src/wasm/kagura_wasm.zig:39`, `src/wasm/kagura_wasm.zig:49` |
| `src/wasm/browser_transport.zig` | Browser transport shim core is re-exported from the package root; the wasm32 export wrapper lives in `src/wasm/transport_shim.zig`. | `src/root.zig:18`, `src/root.zig:21` |

## Planning notes and divergences

Where older media-transport design intent has not fully landed in the source, the current code verifies these concrete pieces:

| Topic | Current status | Evidence |
| --- | --- | --- |
| Runtime media SFU sizing | `max_participants` remains comptime-bound at 64; config-driven participant capacity is deferred. | `src/daemon/media_room.zig:14`, `src/daemon/media_room.zig:21`, `src/daemon/media_room.zig:24` |
| Runtime kagura reassembly sizing | Runtime window defaults exist, but actual `ReassemblyBuffer` capacity remains comptime-bound. | `src/substrate/kagura_frame.zig:34`, `src/substrate/kagura_frame.zig:35`, `src/substrate/kagura_frame.zig:236` |
| Mixed-leg calls | The bridge exists as header rewrap only; it requires a shared codec payload and does not transcode. | `src/daemon/media_bridge.zig:16`, `src/daemon/media_bridge.zig:17`, `src/daemon/media_bridge.zig:143`, `src/daemon/media_bridge.zig:159` |
