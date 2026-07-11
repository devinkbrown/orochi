# Media architecture

*Orochi's media stack: a Suimyaku SFU control plane, RTP/SRTP and native Kagura UDP legs, header-only Kagura-frame <-> RTP rewrap, DTLS-SRTP keying, WebTransport framing, and browser/WASM codec exports.*

This document covers the current source tree only.

## SFU control plane

`src/substrate/suimyaku/media.zig` is the pure media control substrate. It owns bounded roster state, SFU forwarding decisions, simulcast layer choice, ABR hints, and codec offer/answer negotiation, with hot paths using inline storage. Evidence: `src/substrate/suimyaku/media.zig:4`, `src/substrate/suimyaku/media.zig:6`, `src/substrate/suimyaku/media.zig:7`.

| Type | Role | Evidence |
| --- | --- | --- |
| `MediaKind` | Voice, video, and screen media kinds. | `src/substrate/suimyaku/media.zig:47` |
| `ParticipantId` | Bounded inline participant id with validation. | `src/substrate/suimyaku/media.zig:87`, `src/substrate/suimyaku/media.zig:93` |
| `Participant` | Tracks joined, muted, and speaking kind sets; controls publish/receive checks. | `src/substrate/suimyaku/media.zig:115`, `src/substrate/suimyaku/media.zig:121`, `src/substrate/suimyaku/media.zig:125` |
| `Session(max_participants)` | Inline roster, join/leave/mute/speaking operations, and `forwardSet`. | `src/substrate/suimyaku/media.zig:132`, `src/substrate/suimyaku/media.zig:140`, `src/substrate/suimyaku/media.zig:151`, `src/substrate/suimyaku/media.zig:167`, `src/substrate/suimyaku/media.zig:180`, `src/substrate/suimyaku/media.zig:205` |
| `RoutePolicy` | Optional `require_speaking` forwarding gate. | `src/substrate/suimyaku/media.zig:246` |

`forwardSet` verifies the source participant exists, verifies the source can publish the requested kind, optionally requires the source to be speaking, and returns receivers that can receive the kind while excluding the source. Evidence: `src/substrate/suimyaku/media.zig:211`, `src/substrate/suimyaku/media.zig:213`, `src/substrate/suimyaku/media.zig:214`, `src/substrate/suimyaku/media.zig:218`, `src/substrate/suimyaku/media.zig:220`, `src/substrate/suimyaku/media.zig:221`.

## Daemon media rooms

`src/daemon/media_room.zig` maps an IRC channel to a Suimyaku `Session`. This is control plane only: who is in a call, what they publish, and mute/speaking state; media bytes flow over the transport substrate. Evidence: `src/daemon/media_room.zig:4`, `src/daemon/media_room.zig:5`, `src/daemon/media_room.zig:6`, `src/daemon/media_room.zig:7`.

| Concern | Current behavior | Evidence |
| --- | --- | --- |
| Room sizing | Runtime default is 64 participants, while the inline `Room` ceiling is `media.Session(256)`. `[media].max_participants` is clamped to `1..256` and enforced at join. | `src/daemon/media_room.zig:17`, `src/daemon/media_room.zig:18`, `src/daemon/media_room.zig:19`, `src/daemon/media_room.zig:23`, `src/daemon/media_room.zig:32`, `src/daemon/media_room.zig:37`, `src/daemon/media_room.zig:339` |
| Native leg sizing | The native Kagura leg is separately bounded at 64 participants per call. | `src/daemon/native_media_transport.zig:35`, `src/daemon/native_media_transport.zig:42`, `src/daemon/native_media_transport.zig:43` |
| Runtime config | Breakout label cap and participant cap are runtime-tunable under the inline ceilings. | `src/daemon/media_room.zig:25`, `src/daemon/media_room.zig:26`, `src/daemon/media_room.zig:27`, `src/daemon/media_room.zig:39` |
| Per-channel maps | Rooms, breakouts, positions, hands, negotiated profiles, and per-participant profiles are keyed by channel/composite keys. | `src/daemon/media_room.zig:84`, `src/daemon/media_room.zig:87`, `src/daemon/media_room.zig:91`, `src/daemon/media_room.zig:94`, `src/daemon/media_room.zig:96`, `src/daemon/media_room.zig:100`, `src/daemon/media_room.zig:104` |
| Codec/FEC profile | `MEDIA OFFER` establishes a per-channel `CallProfile`; `MEDIA ANSWER` consults it. | `src/daemon/media_room.zig:70`, `src/daemon/media_room.zig:73`, `src/daemon/media_room.zig:259`, `src/daemon/server.zig:26596`, `src/daemon/server.zig:26822` |
| Room lifecycle | Join creates the room on first join; leave prunes when empty. | `src/daemon/media_room.zig:334`, `src/daemon/media_room.zig:385`, `src/daemon/media_room.zig:354`, `src/daemon/media_room.zig:396` |

## RTP/SRTP media plane

`src/daemon/media_plane.zig` ties the `MediaTransport` endpoint registry to a live UDP socket and pump thread. The pump demuxes DTLS/STUN/RTP/RTCP, answers STUN checks, and relays RTP/RTCP under a mutex. Evidence: `src/daemon/media_plane.zig:4`, `src/daemon/media_plane.zig:5`, `src/daemon/media_plane.zig:7`, `src/daemon/media_plane.zig:334`, `src/daemon/media_plane.zig:343`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Startup | Binds UDP, records local port, optionally discovers a server-reflexive candidate, sets recv timeout, and spawns the pump thread. | `src/daemon/media_plane.zig:182`, `src/daemon/media_plane.zig:186`, `src/daemon/media_plane.zig:188`, `src/daemon/media_plane.zig:191`, `src/daemon/media_plane.zig:198`, `src/daemon/media_plane.zig:214` |
| STUN | STUN datagrams call `transport.handleStunBinding` under the mutex and send a response if one is built. | `src/daemon/media_plane.zig:334`, `src/daemon/media_plane.zig:336`, `src/daemon/media_plane.zig:340` |
| RTP/RTCP filter | Non-STUN media must look like RTP/RTCP version 2 and be at least RTP header length, preventing open UDP reflection. | `src/daemon/media_plane.zig:343`, `src/daemon/media_plane.zig:345` |
| RTCP feedback | RTCP is decrypted first for DTLS peers, then Generic NACK is terminated locally from the retransmit cache; other RTCP is relayed or translated cross-leg. | `src/daemon/media_plane.zig:612`, `src/daemon/media_plane.zig:621`, `src/daemon/media_plane.zig:643`, `src/daemon/media_plane.zig:649`, `src/daemon/media_plane.zig:652` |
| RTP relay | Decodes RTP header where possible, forwards through `transport.forwardFromSource`, caches for NACK, and sends to selected targets. | `src/daemon/media_plane.zig:354`, `src/daemon/media_plane.zig:356`, `src/daemon/media_plane.zig:567`, `src/daemon/media_plane.zig:581`, `src/daemon/media_plane.zig:592` |
| Cross-leg bridge | After RTP relay, the plane can call an installed `RtpCrossSink` to reach native participants. | `src/daemon/media_plane.zig:105`, `src/daemon/media_plane.zig:177`, `src/daemon/media_plane.zig:606`, `src/daemon/media_plane.zig:608` |
| Signaling support | `allocate` returns ICE credentials; `groupKey` returns the legacy per-call SRTP group key; `remoteFor` resolves live peer address. | `src/daemon/media_plane.zig:710`, `src/daemon/media_plane.zig:715`, `src/daemon/media_plane.zig:728`, `src/daemon/media_plane.zig:735` |

### RTP/RTCP helpers

The RTP/RTCP helpers are pure protocol surfaces used by the plane and bridge. `rtp_profile.zig` owns the 12-byte RTP header, RFC 3550-style stats, and SR/RR helpers; `rtp_ext.zig` parses RFC 8285 RTP extensions; `rtp_red.zig` handles RED payload blocks; `rtcp_compound.zig`, `rtcp_translate.zig`, and `rtcp_xr.zig` parse/build RTCP compound, feedback, and XR packets. SRTP/SRTCP protection lives in `srtp.zig` and `srtcp.zig`. Evidence: `src/proto/rtp_profile.zig:4`, `src/proto/rtp_profile.zig:12`, `src/proto/rtp_ext.zig:4`, `src/proto/rtp_red.zig:12`, `src/proto/rtcp_compound.zig:4`, `src/proto/rtcp_translate.zig:4`, `src/proto/rtcp_xr.zig:4`, `src/proto/srtp.zig:4`, `src/proto/srtcp.zig:4`.

## DTLS-SRTP signaling and RFC 8122 fingerprint verification

DTLS-SRTP is opt-in (`[media].dtls_srtp`, plus `[media].dtls13` for the DTLS 1.3 engine). When enabled, RFC 7983 demux routes DTLS records to the per-peer terminator; otherwise STUN/RTP/SRTP paths remain byte-identical. The DTLS 1.2 and 1.3 engines share one certificate fingerprint for signaling. Evidence: `src/daemon/server.zig:3649`, `src/daemon/server.zig:3650`, `src/daemon/server.zig:3651`, `src/daemon/media_plane.zig:327`, `src/daemon/media_plane.zig:330`, `src/daemon/media_plane.zig:247`, `src/daemon/media_plane.zig:255`.

The signaling path parses `fingerprint=sha-256:<colon-hex>` on `MEDIA OFFER`/`MEDIA ANSWER` and fails closed on malformed fingerprints or a DTLS request while the feature is unavailable. When accepted, the peer fingerprint is stored per `(channel, participant)`, resolved to the peer's ICE-bound transport address, and bound into both DTLS terminators before handshake completion. Evidence: `src/daemon/server.zig:26554`, `src/daemon/server.zig:26557`, `src/daemon/server.zig:26609`, `src/daemon/server.zig:26621`, `src/daemon/server.zig:26629`, `src/daemon/server.zig:26834`, `src/daemon/server.zig:26875`, `src/daemon/media_plane.zig:489`, `src/daemon/media_plane.zig:527`, `src/daemon/media_plane.zig:538`, `src/daemon/media_plane.zig:551`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Server identity | In DTLS mode, `MEDIA TRANSPORT` advertises `fingerprint=<server fp>` and `setup=passive` instead of the legacy `srtp=` group key. | `src/daemon/server.zig:26684`, `src/daemon/server.zig:26692`, `src/daemon/server.zig:26702`, `src/daemon/server.zig:40671`, `src/daemon/server.zig:40682` |
| `use_srtp` | `dtls_srtp.zig` defines RFC 5764 profiles, key export, and `use_srtp` encode/parse helpers; both terminators select AES-128-CM-HMAC-SHA1-80 when offered. | `src/proto/dtls_srtp.zig:4`, `src/proto/dtls_srtp.zig:19`, `src/proto/dtls_srtp.zig:78`, `src/proto/dtls_srtp.zig:129`, `src/proto/dtls12_server.zig:754`, `src/proto/dtls13_server.zig:815` |
| Verification gate | `exportedKeys` and `srtpProfile` return null for a bound-but-unverified peer; `recordPeerCertificate` is the certificate-capture seam and uses constant-time digest compare. | `src/proto/dtls_peer_verify.zig:4`, `src/proto/dtls_peer_verify.zig:41`, `src/proto/dtls12_server.zig:235`, `src/proto/dtls12_server.zig:240`, `src/proto/dtls12_server.zig:249`, `src/proto/dtls12_server.zig:279`, `src/proto/dtls13_server.zig:245`, `src/proto/dtls13_server.zig:254`, `src/proto/dtls13_server.zig:274` |
| Per-recipient SRTP | For established DTLS peers, RTP is decrypted once to a canonical packet and re-encrypted per DTLS recipient; SRTCP follows the same canonical-then-protect model. | `src/daemon/media_plane.zig:559`, `src/daemon/media_plane.zig:575`, `src/daemon/media_plane.zig:592`, `src/daemon/media_plane.zig:600`, `src/daemon/media_plane.zig:655`, `src/daemon/media_plane.zig:665` |

## Native KaguraVox/KaguraVis transport

`src/daemon/native_media_transport.zig` is the daemon-owned native UDP leg for KaguraVox/KaguraVis framing. It forwards Kagura frame datagrams, not RTP, and never transcodes. Evidence: `src/daemon/native_media_transport.zig:4`, `src/daemon/native_media_transport.zig:5`, `src/daemon/native_media_transport.zig:6`, `src/daemon/native_media_transport.zig:17`, `src/daemon/native_media_transport.zig:18`.

| Path | Behavior | Evidence |
| --- | --- | --- |
| Channel isolation | Each call/channel has its own `NativeMediaLink`; a stream-id index maps inbound datagrams to the owning channel. | `src/daemon/native_media_transport.zig:9`, `src/daemon/native_media_transport.zig:10`, `src/daemon/native_media_transport.zig:55`, `src/daemon/native_media_transport.zig:57` |
| Startup | Binds UDP, records local port, sets recv timeout, starts pump thread. | `src/daemon/native_media_transport.zig:117`, `src/daemon/native_media_transport.zig:121`, `src/daemon/native_media_transport.zig:123`, `src/daemon/native_media_transport.zig:124`, `src/daemon/native_media_transport.zig:128` |
| Frame validation | Pump requires Kagura framing, accepts either an exact frame or frame+MAC tag, and decodes before routing. | `src/daemon/native_media_transport.zig:154`, `src/daemon/native_media_transport.zig:160`, `src/daemon/native_media_transport.zig:161`, `src/daemon/native_media_transport.zig:162` |
| Forwarding | Routes by stream id, authenticates the datagram, learns/verifies publisher address, computes SFU forward set, and resends the same bytes to each recipient. | `src/daemon/native_media_transport.zig:170`, `src/daemon/native_media_transport.zig:173`, `src/daemon/native_media_transport.zig:175`, `src/daemon/native_media_transport.zig:191`, `src/daemon/native_media_link.zig:224`, `src/daemon/native_media_link.zig:236`, `src/daemon/native_media_link.zig:242` |
| Registration | `register` records channel, participant id, media kind, stream id, and address, then indexes stream id to channel. | `src/daemon/native_media_transport.zig:325`, `src/daemon/native_media_transport.zig:329`, `src/daemon/native_media_transport.zig:344`, `src/daemon/native_media_transport.zig:349`, `src/daemon/native_media_transport.zig:350` |
| Cross-leg bridge | After native forwarding, a native frame can be handed to a cross-leg sink for RTP/SRTP participants. | `src/daemon/native_media_transport.zig:78`, `src/daemon/native_media_transport.zig:94`, `src/daemon/native_media_transport.zig:193`, `src/daemon/native_media_transport.zig:195` |

### Native security model

Native stream ids are keyed HMAC-derived capability tokens per `(channel, nick)`, delivered through authenticated IRC signaling. The optional per-datagram MAC uses a key derived from the same native stream PRF root plus `(channel, participant)`, HMAC-SHA256 truncated to 128 bits. When `[media].native_media_require_mac` is false, untagged frames are accepted for compatibility but present tags must verify; when it is true, missing or bad tags fail closed before forwarding. Evidence: `src/daemon/server.zig:26781`, `src/daemon/server.zig:26796`, `src/daemon/server.zig:26717`, `src/daemon/config_format.zig:464`, `src/daemon/config_format.zig:1193`, `src/daemon/server.zig:3628`, `src/substrate/kagura_frame.zig:68`, `src/substrate/kagura_frame.zig:248`, `src/substrate/kagura_frame.zig:300`, `src/substrate/kagura_frame.zig:320`, `src/substrate/kagura_frame.zig:327`, `src/substrate/kagura_frame.zig:329`, `src/daemon/native_media_transport.zig:246`, `src/daemon/native_media_transport.zig:249`, `src/daemon/native_media_transport.zig:252`.

Address binding is also fail-closed for native streams after the first observed source: `NativeMediaLink.inboundFrom` learns a publisher address, then rejects later datagrams for that stream from a different address; native feedback envelopes use `bindAddressForStream` for the same ownership check. Evidence: `src/daemon/native_media_link.zig:105`, `src/daemon/native_media_link.zig:108`, `src/daemon/native_media_link.zig:111`, `src/daemon/native_media_link.zig:224`, `src/daemon/native_media_link.zig:236`, `src/daemon/native_media_transport.zig:213`.

## Kagura frame container and codecs

`src/substrate/kagura_frame.zig` is a wire container, not the audio/video codec itself. It carries encoded payloads over media bands. Evidence: `src/substrate/kagura_frame.zig:4`, `src/substrate/kagura_frame.zig:6`, `src/substrate/kagura_frame.zig:7`.

| Field/behavior | Evidence |
| --- | --- |
| Media bands are `band_id >= 64`; control bands are below 64. | `src/substrate/kagura_frame.zig:10`, `src/substrate/kagura_frame.zig:61`, `src/substrate/kagura_frame.zig:136` |
| Wire format includes payload length, band id, stream id, sequence, timestamp, keyframe flag, codec tag, and payload. | `src/substrate/kagura_frame.zig:12`, `src/substrate/kagura_frame.zig:14`, `src/substrate/kagura_frame.zig:19`, `src/substrate/kagura_frame.zig:20` |
| `CodecTag` supports `raw`, `kaguravox_audio`, and `kaguravis_video`. | `src/substrate/kagura_frame.zig:78`, `src/substrate/kagura_frame.zig:80`, `src/substrate/kagura_frame.zig:81`, `src/substrate/kagura_frame.zig:82` |
| Decode rejects truncation, control band ids, trailing bytes, and unknown codec tags. | `src/substrate/kagura_frame.zig:171`, `src/substrate/kagura_frame.zig:175`, `src/substrate/kagura_frame.zig:222`, `src/substrate/kagura_frame.zig:232` |
| ReassemblyBuffer is a bounded jitter/reorder buffer with compile-time payload/window bounds and runtime window config. | `src/substrate/kagura_frame.zig:396`, `src/substrate/kagura_frame.zig:397`, `src/substrate/kagura_frame.zig:410`, `src/substrate/kagura_frame.zig:418` |
| KaguraVox is an allocation-free IMA ADPCM voice codec building block; KaguraVis is an allocation-free lossless delta/RLE video building block. | `src/substrate/kaguravox_adpcm.zig:4`, `src/substrate/kaguravox_adpcm.zig:6`, `src/substrate/kaguravox_adpcm.zig:58`, `src/substrate/kaguravox_adpcm.zig:76`, `src/substrate/kaguravis_delta.zig:4`, `src/substrate/kaguravis_delta.zig:6`, `src/substrate/kaguravis_delta.zig:60`, `src/substrate/kaguravis_delta.zig:71` |

## Cross-leg bridge

`src/daemon/media_bridge.zig` bridges participants on the native Kagura leg and the RTP/SRTP leg by header rewrap only. Payload bytes stay opaque and are shared verbatim; there is no encoding, decoding, or transcoding. Evidence: `src/daemon/media_bridge.zig:4`, `src/daemon/media_bridge.zig:6`, `src/daemon/media_bridge.zig:10`, `src/daemon/media_bridge.zig:19`.

| Direction | Behavior | Evidence |
| --- | --- | --- |
| Native to RTP | Decode Kagura frame, map to bridge frame, write RTP using the mapped SSRC, send to opposite-leg members. | `src/daemon/media_bridge.zig:254`, `src/daemon/media_bridge.zig:260`, `src/daemon/media_bridge.zig:261`, `src/daemon/media_bridge.zig:266`, `src/daemon/media_bridge.zig:268`, `src/daemon/media_bridge.zig:269` |
| RTP to native | Decode RTP header, map to native frame with the mapped stream id, encode Kagura datagram, send to native members. | `src/daemon/media_bridge.zig:272`, `src/daemon/media_bridge.zig:276`, `src/daemon/media_bridge.zig:277`, `src/daemon/media_bridge.zig:282`, `src/daemon/media_bridge.zig:283`, `src/daemon/media_bridge.zig:285`, `src/daemon/media_bridge.zig:286` |
| Target selection | Cross-leg targets are opposite-leg recipients from the per-channel session, excluding disconnected/ineligible members. | `src/daemon/media_bridge.zig:236`, `src/daemon/media_bridge.zig:237`, `src/daemon/media_bridge.zig:240`, `src/daemon/media_bridge.zig:243` |
| Transcode-free gate | Participant codec sets must converge on a shared codec; incompatible sets cause cross-leg fanout to drop rather than transcode. | `src/daemon/media_bridge.zig:191`, `src/daemon/media_bridge.zig:213`, `src/daemon/media_bridge.zig:221`, `src/daemon/media_bridge.zig:262`, `src/daemon/media_bridge.zig:278` |

The live server installs bridge callbacks around `LinuxServer.media_bridges`, `media_plane`, and `native_media`. Evidence: `src/daemon/server.zig:190`, `src/daemon/server.zig:244`, `src/daemon/server.zig:3589`, `src/daemon/server.zig:3590`, `src/daemon/server.zig:3646`, `src/daemon/server.zig:3664`, `src/daemon/server.zig:26750`.

## MEDIA command and EVENT-plane signaling

`MEDIA` is the command surface for call presence, codec negotiation, transport credential replies, native-leg registration, stats, ABR/layer hints, captions, reactions, roster, and leave cleanup. Media bytes do not flow through the command handler. Evidence: `src/daemon/server.zig:25968`, `src/daemon/server.zig:25970`, `src/daemon/server.zig:26007`, `src/daemon/server.zig:26023`, `src/daemon/server.zig:26027`, `src/daemon/server.zig:26055`, `src/daemon/server.zig:26163`, `src/daemon/server.zig:26218`, `src/daemon/server.zig:26242`.

`MEDIA OFFER` and `MEDIA ANSWER` negotiate Kagura codecs through the SDP/media-session path, publish capability/profile events, and provision both the RTP/SRTP transport and the native Kagura candidate/stream id. Evidence: `src/daemon/server.zig:26596`, `src/daemon/server.zig:26637`, `src/daemon/server.zig:26639`, `src/daemon/server.zig:26656`, `src/daemon/server.zig:26661`, `src/daemon/server.zig:26669`, `src/daemon/server.zig:26679`, `src/daemon/server.zig:26713`, `src/daemon/server.zig:26725`, `src/daemon/server.zig:26822`, `src/daemon/server.zig:26880`, `src/daemon/server.zig:26884`.

Media presence rides the IRCX EVENT plane as `MEDIA <action> <channel> <nick> [detail]`. `MEDIA` is an IRCX event type ordinary clients may subscribe to, but non-oper delivery is member-scoped: the event's channel is the subject, and `mediaEventAllowed` requires the recipient to be a member of that channel. Non-members do not see call presence, including for private/secret channels. Evidence: `src/daemon/event_spine.zig:198`, `src/daemon/event_spine.zig:202`, `src/daemon/event_spine.zig:213`, `src/daemon/server.zig:17593`, `src/daemon/server.zig:17596`, `src/daemon/server.zig:17676`, `src/daemon/server.zig:17677`, `src/daemon/server.zig:18072`, `src/daemon/server.zig:18079`, `src/daemon/server.zig:18085`, `src/daemon/server.zig:18117`, `src/daemon/server.zig:18122`, `src/daemon/server.zig:18126`.

Targeted secrets and transport material are not broadcast. `sendMediaEventReply` renders caller-only MEDIA replies, and `MACKEY` is derived per participant and sent only to the owning WebSocket session. Evidence: `src/daemon/server.zig:18088`, `src/daemon/server.zig:18104`, `src/daemon/server.zig:26351`, `src/daemon/server.zig:26355`, `src/daemon/server.zig:26365`.

## WebTransport and WASM shims

`src/proto/webtransport.zig` is a pure framing module for QUIC varints, capsules, WebTransport datagrams, and stream signal prefixes. The daemon listener in `src/daemon/webtransport_listener.zig` turns the QUIC + HTTP/3 + WebTransport stack into a live UDP endpoint and bridges each WebTransport session to the daemon's ordinary IRC listener over a loopback TCP proxy. Evidence: `src/proto/webtransport.zig:4`, `src/proto/webtransport.zig:6`, `src/proto/webtransport.zig:24`, `src/proto/webtransport.zig:30`, `src/proto/webtransport.zig:174`, `src/proto/webtransport.zig:215`, `src/daemon/webtransport_listener.zig:4`, `src/daemon/webtransport_listener.zig:5`, `src/daemon/webtransport_listener.zig:7`.

Browser and client WASM exports are separate from the daemon plugin host.

| File | Export surface | Evidence |
| --- | --- | --- |
| `src/wasm/kagura_wasm.zig` | KaguraVox audio encode/decode and KaguraVis video intra/inter encode/decode for `wasm32-freestanding`. | `src/wasm/kagura_wasm.zig:1`, `src/wasm/kagura_wasm.zig:3`, `src/wasm/kagura_wasm.zig:17`, `src/wasm/kagura_wasm.zig:21`, `src/wasm/kagura_wasm.zig:35`, `src/wasm/kagura_wasm.zig:39`, `src/wasm/kagura_wasm.zig:49` |
| `src/wasm/browser_transport.zig` | Browser transport shim core is re-exported from the package root; the wasm32 export wrapper lives in `src/wasm/transport_shim.zig`. | `src/root.zig:18`, `src/root.zig:21`, `src/wasm/browser_transport.zig:1`, `src/wasm/transport_shim.zig:1` |

## Planning notes and divergences

Where older media-transport design intent has not fully landed in the source, the current code verifies these concrete pieces:

| Topic | Current status | Evidence |
| --- | --- | --- |
| Runtime media SFU sizing | SFU rooms now have a runtime participant cap defaulting to 64 and clamped to the inline 256-seat ceiling. The native Kagura call leg remains capped at 64. | `src/daemon/media_room.zig:17`, `src/daemon/media_room.zig:18`, `src/daemon/media_room.zig:37`, `src/daemon/native_media_transport.zig:42`, `src/daemon/native_media_transport.zig:43` |
| Runtime Kagura reassembly sizing | Runtime window defaults exist, but actual `ReassemblyBuffer` capacity remains comptime-bound. | `src/substrate/kagura_frame.zig:34`, `src/substrate/kagura_frame.zig:39`, `src/substrate/kagura_frame.zig:397`, `src/substrate/kagura_frame.zig:418` |
| Mixed-leg calls | The bridge exists as header rewrap only; it requires a shared codec payload and does not transcode. | `src/daemon/media_bridge.zig:10`, `src/daemon/media_bridge.zig:19`, `src/daemon/media_bridge.zig:254`, `src/daemon/media_bridge.zig:272` |
