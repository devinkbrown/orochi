# 20 — Media: our codec everywhere, WebRTC as transport + opt-in fallback (pure-SFU)

Status: **architecture decided + building blocks landed; live daemon wiring pending.**
This supersedes the framing in [18-media-transport.md](18-media-transport.md). The earlier
draft of this note framed WebRTC as a *forced mobile gateway with standard codecs*; that
was wrong. The corrected model below is recorded so it doesn't drift again.

## Decision

**One codec for everyone — ours (OPVOX/OPVIS).** Mobile and desktop have *identical*
functionality; WebRTC is a **transport**, not a codec choice. There is exactly one optional
escape hatch (the opt-in standard-codec fallback). The server never touches codec bytes in
any mode.

1. **Primary — our codec, all platforms.** `kagura` (OPVOX audio / OPVIS video) frames in
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
   a low-end phone that can't WASM-decode OPVIS at framerate, or battery constraints) can
   **choose** to use standard WebRTC with the device's hardware codecs (Opus/H.264/VP8).
   This is a deliberate per-user choice, not the default and not forced by platform.

### The hard rule: the server never encodes/decodes/transcodes

Orochi is a **selective-forwarding unit**, not an MCU. The SFU only ever **forwards opaque
codec payloads** and **rewraps transport headers**. No media encode/decode/transcode runs
on the server — ever. Consequences:

- An **all-default call** uses OPVOX/OPVIS for everyone (incl. mobile via WASM); the SFU
  forwards one opaque stream — zero codec work, perfect parity.
- If a participant **opts into** the standard-codec fallback, the call **converges on one
  codec every participant supports** (`kakehashi.selectCommon`). Every Orochi client can
  also speak the standard stack, so a shared codec always exists; the forwarded stream is
  understood by all with zero server codec work. The server does **not** bridge by
  transcoding — convergence (or per-kind disable) is a **client** responsibility; the SFU
  only verifies a shared codec exists.

## Kakehashi — the bridge (`src/substrate/kakehashi.zig`)

A transport-neutral `BridgeFrame { codec, timestamp, sequence, keyframe, payload }` the SFU
forwards. Adapters **only rewrap headers around the borrowed, already-encoded payload**:
- `fromNative`/`toNative` ↔ `kagura_frame.MediaFrame` (normalizes the `kagura raw=0` vs
  `sdp raw=3` tag mismatch via its own canonical `Codec`).
- `fromRtp`/`toRtp` ↔ RTP via a dynamic-PT↔Codec `PtMap`.
- `negotiate` is repackage-only: `direct_relay` (shared codec) or `incompatible` (never
  `transcode`). `selectCommon(sets)` = the one codec all participants share.
- `kakehashi_session` — per-call leg/codec/identity state + `forwardTargets`; `transcodeFree()`
  reflects whether `selectCommon` found a codec. `ssrc_map` ties native `stream_id` ↔ RTP `ssrc`.

## Module inventory (built, unit-tested, in the unified build)

- **Bridge:** `kakehashi`, `kakehashi_session`, `ssrc_map`, `rtcp_translate` (control-plane
  NACK/PLI/FIR ↔ neutral feedback).
- **Native resilience (Suimyaku plane):** `kagura_nack` (retransmit cache + gap tracker),
  `kagura_fec` (XOR FEC), `kagura_reassembly` (reorder/jitter), `simulcast_select` +
  `kagura_layer` + `frame_marking` (layer forwarding without decode), `bwe_estimate`
  (delay-based target bitrate), `media_pacer` (egress pacing), `native_feedback`.
- **WebRTC stack (transport carrier + opt-in standard-codec fallback):** `srtp`/`srtcp`,
  `dtls_srtp`/`dtls_handshake`/`dtls_keyexchange`/`dtls_fingerprint`, `rtp_ext`/`rtp_red`/
  `audio_level`/`mid_rid`/`playout_delay`, `rtcp_compound`/`rtcp_xr`/`remb`/`pli_fir`/
  `twcc_feedback`/`rtx`, `sdp_session`/`ice_candidate`/`stun_ice_attrs`, `dcep`/`sctp_chunk`,
  `sframe`, `flexfec`. `dcep`/`sctp_chunk` are what let a WebRTC DataChannel carry our opaque
  kagura frames (transport role); the RTP/codec pieces serve the opt-in standard fallback.
- **Live WebRTC transport (already wired):** `media_transport`/`media_socket`/`media_plane`
  (UDP + ICE/STUN/SRTP-SDES relay + NACK).

## Remaining live wiring (serial; not yet done)

1. **Native media transport in the daemon.** Today `media_plane` is only the WebRTC/UDP
   leg. The native leg (`kagura_frame` over `ryusen`/CoilPack + `secure_channel`) is
   library-only — it must be brought into the daemon as a live transport so our codec runs
   end-to-end on the default path. `native_media_link` is the forward-decision glue for it.
   **This is the gating arc.**
2. **Hook Kakehashi into the SFU forward path:** per-channel `kakehashi_session`; on each
   relayed frame, serialize to each target's leg (`toNative`/`toRtp`) via `ssrc_map`; drive
   `simulcast_select` from `bwe_estimate`; answer `rtcp_translate`/`native_feedback`.
3. **Codec negotiation surface:** advertise per-participant codec sets in signaling so
   `selectCommon` runs per call; reject/deny a media kind when no shared codec (never
   transcode).

## Non-goals

- Server-side transcoding / MCU mixing. Never.
- Replacing our codec with WebRTC's. Our codec (OPVOX/OPVIS) is the default on **every**
  platform incl. mobile (via WASM). WebRTC is a **transport carrier** for our codec, plus an
  **opt-in standard-codec fallback** for users who choose it — never the forced default.
- Per-platform feature divergence. Mobile and desktop have the same functionality.
