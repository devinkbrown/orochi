# 20 — Media interop: our codec everywhere, WebRTC as transport and opt-in fallback (pure-SFU)

*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

This document records the planned media interop model and server-side non-goals.

Status: **architecture decided + live offer/answer transport wiring landed; forward-path
polish remains.**
This supersedes the framing in [18-media-transport.md](18-media-transport.md). The earlier
draft of this note framed WebRTC as a *forced mobile gateway with standard codecs*; that
framing was incorrect. The corrected model below is recorded so it does not drift again.

## Decision

**One codec for everyone — ours (KaguraVox/KaguraVis).** Mobile and desktop have *identical*
functionality. WebRTC is a **transport**, not a codec choice. The opt-in standard-codec
fallback is the only optional escape hatch. The server never touches codec bytes in any
mode.

1. **Primary — our codec, all platforms.** `kagura` (KaguraVox audio / KaguraVis video) frames in
   `kagura_frame` containers, with `secure_channel` (TreeKEM/HPKE) for E2E. Desktop runs
   it natively; **browser and mobile run the same codec in WASM** (SIMD+threads). The SFU
   forwards the *identical opaque kagura frame* to every participant — so a phone and a
   desktop in the same call see the same media path. No per-platform media divergence.

2. **Transport is decoupled from codec.** The preferred transport is WebTransport / QUIC
   datagrams over `ryusen`/`transport_stack` + CoilPack. On devices where that isn't
   available (notably older iOS Safari), a **WebRTC DataChannel is used purely as a carrier**
   for our opaque kagura frames — same bytes, same codec, different pipe. WebRTC here is
   *transport only*; its media-track codecs are not used on this path.

3. **Opt-in standard-codec fallback.** A user **having trouble with our custom codec** (e.g.
   a low-end phone that cannot WASM-decode KaguraVis at framerate, or battery constraints) can
   **choose** to use standard WebRTC with the device's hardware codecs (Opus/H.264/VP8).
   This is a deliberate per-user choice, not the default and not forced by platform.

### The hard rule: the server never encodes/decodes/transcodes

Orochi is a **selective-forwarding unit**, not an MCU. The SFU only ever **forwards opaque
codec payloads** and **rewraps transport headers**. No media encode/decode/transcode runs
on the server. Consequences:

- An **all-default call** uses KaguraVox/KaguraVis for everyone (including mobile via WASM); the SFU
  forwards one opaque stream — zero codec work, platform parity.
- If a participant **opts into** the standard-codec fallback, the call **converges on one
  codec every participant supports** (`kakehashi.selectCommon`). Every Orochi client can
  also speak the standard stack, so a shared codec always exists; the forwarded stream is
  understood by all with zero server codec work. The server does **not** bridge by
  transcoding — convergence (or per-kind disable) is a **client** responsibility; the SFU
  only verifies a shared codec exists.

## Kakehashi — the bridge (`src/substrate/kakehashi.zig`)

A transport-neutral `BridgeFrame { codec, timestamp, sequence, keyframe, payload }` the SFU
forwards. Adapters **only rewrap headers around the borrowed, already-encoded payload**.

- `fromNative`/`toNative` ↔ `kagura_frame.MediaFrame` (normalizes the `kagura raw=0` vs
  `sdp raw=3` tag mismatch via its own canonical `Codec`).
- `fromRtp`/`toRtp` ↔ RTP via a dynamic-PT↔Codec `PtMap`.
- `negotiate` is repackage-only: `direct_relay` (shared codec) or `incompatible` (never
  `transcode`). `selectCommon(sets)` = the one codec all participants share.
- `kakehashi_session` — per-call leg/codec/identity state + `forwardTargets`; `transcodeFree()`
  reflects whether `selectCommon` found a codec. `ssrc_map` ties native `stream_id` ↔ RTP `ssrc`.

## Module inventory (built, unit-tested, in the unified build)

| Area | Modules |
| --- | --- |
| Bridge | `kakehashi`, `kakehashi_session`, `ssrc_map`, `rtcp_translate` (control-plane NACK/PLI/FIR ↔ neutral feedback). |
| Native resilience (Suimyaku plane) | `kagura_nack` (retransmit cache + gap tracker), `kagura_fec` (XOR FEC), `kagura_reassembly` (reorder/jitter), `simulcast_select` + `kagura_layer` + `frame_marking` (layer forwarding without decode), `bwe_estimate` (delay-based target bitrate), `media_pacer` (egress pacing), `native_feedback`. |
| WebRTC stack (transport carrier + opt-in standard-codec fallback) | `srtp`/`srtcp`, `dtls_srtp`/`dtls_handshake`/`dtls_keyexchange`/`dtls_fingerprint`, `rtp_ext`/`rtp_red`/`audio_level`/`mid_rid`/`playout_delay`, `rtcp_compound`/`rtcp_xr`/`remb`/`pli_fir`/`twcc_feedback`/`rtx`, `sdp_session`/`ice_candidate`/`stun_ice_attrs`, `dcep`/`sctp_chunk`, `sframe`, `flexfec`. `dcep`/`sctp_chunk` are what let a WebRTC DataChannel carry our opaque kagura frames (transport role); the RTP/codec pieces serve the opt-in standard fallback. |
| Live WebRTC transport (wired) | `media_transport`/`media_socket`/`media_plane` (UDP + ICE/STUN/SRTP-SDES or DTLS-SRTP relay + NACK). |
| Live native transport (wired) | `native_media_transport` plus `MEDIA OFFER`/`MEDIA ANSWER` `NATIVE` signaling; participants receive a native UDP candidate and keyed stream id for KaguraVox/KaguraVis frames. |
| Live cross-leg registration (wired) | `media_bridge` roster entries are created from both offerers and answerers, using `transport=webrtc`/DTLS requests to choose the WebRTC leg and native as the default. |

## Remaining live wiring

1. **Finish Kakehashi in the SFU forward path:** per-channel `kakehashi_session`; on each
   relayed frame, serialize to each target's leg (`toNative`/`toRtp`) via `ssrc_map`; drive
   `simulcast_select` from `bwe_estimate`; answer `rtcp_translate`/`native_feedback`.
2. **Broaden codec negotiation surface:** `MEDIA OFFER` establishes the active profile and
   `MEDIA ANSWER` intersects each answerer against it while provisioning that participant's
   transports. The remaining work is per-kind/per-participant codec-set fanout and explicit
   media-kind denial when no shared codec exists (never transcode).

## Non-goals

- Server-side transcoding / MCU mixing. Never.
- Replacing our codec with WebRTC's. Our codec (KaguraVox/KaguraVis) is the default on **every**
  platform including mobile (via WASM). WebRTC is a **transport carrier** for our codec, plus an
  **opt-in standard-codec fallback** for users who choose it — never the forced default.
- Per-platform feature divergence. Mobile and desktop have the same functionality.
