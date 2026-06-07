# 20 — Dual-Stack Media Interop (native ↔ WebRTC), pure-SFU

Status: **architecture decided + building blocks landed; live daemon wiring pending.**
This supersedes the framing in [18-media-transport.md](18-media-transport.md): Mizuchi's
media is a **dual-stack pure SFU**, not standard WebRTC. This note records the corrected
direction (so it doesn't drift again), why, and the module inventory.

## Decision

Two media stacks, bridged, **with the server never touching codec bytes**:

1. **Native (primary) — Suimyaku plane.** Capable / desktop clients. `opcodec`
   (OPVOX/OPVIS) frames in `opcodec_frame` containers over `ryusen`/`transport_stack`
   (custom adaptive transport) + CoilPack, with `secure_channel` (TreeKEM/HPKE) for E2E.
2. **WebRTC (fallback) — gateway.** Mobile / constrained clients. Standard RTP/SRTP with
   the device's **hardware** codecs (Opus/H.264/VP8). Rationale: OPVIS (video) in WASM on a
   phone is too slow / may not load — phones need hardware decode, which only exists for
   standard codecs. (Audio/OPVOX in WASM is plausible; video is the wall.)

### The hard rule: the server never encodes/decodes/transcodes

Mizuchi is a **selective-forwarding unit**, not an MCU. The SFU only ever **forwards opaque
codec payloads** and **rewraps transport headers**. No media encode/decode/transcode runs
on the server — ever. Consequences:

- A mixed native/WebRTC call must **converge on one codec every participant supports**
  (`kakehashi.selectCommon`). The forwarded stream is then understood by all receivers with
  zero server codec work. If no common codec exists, the call is **not transcode-free as
  composed** — a participant renegotiates (e.g. a native client also offering the mobile
  hardware codec), or that media kind is disabled for the mismatched peer. The server does
  **not** bridge it by transcoding.
- Producing a common codec is a **client** responsibility; the SFU only verifies one exists.

## Kakehashi — the bridge (`src/substrate/kakehashi.zig`)

A transport-neutral `BridgeFrame { codec, timestamp, sequence, keyframe, payload }` the SFU
forwards. Adapters **only rewrap headers around the borrowed, already-encoded payload**:
- `fromNative`/`toNative` ↔ `opcodec_frame.MediaFrame` (normalizes the `opcodec raw=0` vs
  `sdp raw=3` tag mismatch via its own canonical `Codec`).
- `fromRtp`/`toRtp` ↔ RTP via a dynamic-PT↔Codec `PtMap`.
- `negotiate` is repackage-only: `direct_relay` (shared codec) or `incompatible` (never
  `transcode`). `selectCommon(sets)` = the one codec all participants share.
- `kakehashi_session` — per-call leg/codec/identity state + `forwardTargets`; `transcodeFree()`
  reflects whether `selectCommon` found a codec. `ssrc_map` ties native `stream_id` ↔ RTP `ssrc`.

## Module inventory (built, unit-tested, in the unified build)

- **Bridge:** `kakehashi`, `kakehashi_session`, `ssrc_map`, `rtcp_translate` (control-plane
  NACK/PLI/FIR ↔ neutral feedback).
- **Native resilience (Suimyaku plane):** `opcodec_nack` (retransmit cache + gap tracker),
  `opcodec_fec` (XOR FEC), `opcodec_reassembly` (reorder/jitter), `simulcast_select` +
  `opcodec_layer` + `frame_marking` (layer forwarding without decode), `bwe_estimate`
  (delay-based target bitrate), `media_pacer` (egress pacing), `native_feedback`.
- **WebRTC gateway (mobile/standard interop):** `srtp`/`srtcp`, `dtls_srtp`/`dtls_handshake`/
  `dtls_keyexchange`/`dtls_fingerprint`, `rtp_ext`/`rtp_red`/`audio_level`/`mid_rid`/
  `playout_delay`, `rtcp_compound`/`rtcp_xr`/`remb`/`pli_fir`/`twcc_feedback`/`rtx`,
  `sdp_session`/`ice_candidate`/`stun_ice_attrs`, `dcep`/`sctp_chunk`, `sframe`, `flexfec`.
- **Live WebRTC transport (already wired):** `media_transport`/`media_socket`/`media_plane`
  (UDP + ICE/STUN/SRTP-SDES relay + NACK) — this is the gateway leg.

## Remaining live wiring (serial; not yet done)

1. **Native media transport in the daemon.** Today `media_plane` is only the WebRTC/UDP
   gateway. The native leg (`opcodec_frame` over `ryusen`/CoilPack + `secure_channel`) is
   library-only — it must be brought into the daemon as a live transport before Kakehashi
   can bridge real native↔WebRTC calls. **This is the gating arc.**
2. **Hook Kakehashi into the SFU forward path:** per-channel `kakehashi_session`; on each
   relayed frame, serialize to each target's leg (`toNative`/`toRtp`) via `ssrc_map`; drive
   `simulcast_select` from `bwe_estimate`; answer `rtcp_translate`/`native_feedback`.
3. **Codec negotiation surface:** advertise per-participant codec sets in signaling so
   `selectCommon` runs per call; reject/deny a media kind when no shared codec (never
   transcode).

## Non-goals

- Server-side transcoding / MCU mixing. Never.
- Replacing the native stack with WebRTC. WebRTC is the **mobile fallback gateway** only.
