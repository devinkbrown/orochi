# S2S Media/Crypto Asset Study: opssl and opcodec

This is a design mapping, not an import plan. `opssl` and `opcodec` are
owner-built C reference libraries from the Ophion ecosystem. Orochi remains
clean-room, pure Zig in core: no C ABI, no linked C library, no inherited LADON
identity model. These libraries are useful as blueprints for algorithms, module
boundaries, tests, and operational lessons.

The relevant Orochi context is:

- Suimyaku S2S has a sovereign `node_id = BLAKE3-160(Ed25519 verify key)`.
  There are no SIDs.
- Tsumugi is the S2S secure channel: Noise-IK-shaped, X-Wing-style
  X25519+ML-KEM-768 handshake, post-handshake ratchet, per-frame AEAD.
- Ryusen is the transport seam: TCP/io_uring today, QUIC/WebTransport/media
  bands later, with band priority and congestion hooks.
- Goryu-Sync handles CRDT convergence and anti-entropy; media must not block it.
- Client surfaces remain IRC and web. Media is a later band, but the core frame
  and transport seams must not preclude it.

## Source Inventory Read

### opssl

Read scope:

- `/home/kain/opssl/README.md`
- `/home/kain/opssl/include/opssl/*.h`
- `/home/kain/opssl/doc/*.txt`
- targeted source inventory for `src/crypto/*`, `src/tls/*`, and `src/x509/*`

Important actual module names and capabilities:

- `src/crypto/mlkem.c`, `mldsa.c`, `x25519.c`, `ed25519.c`, `sha3.c`,
  `hkdf.c`, `hmac.c`, `chacha20_poly1305.c`, `aes_gcm.c`,
  `constant_time.c`, `random.c`
- `src/tls/handshake.c`, `tls13.c`, `record.c`, `keysched.c`, `ktls.c`,
  `dtls.c`
- `src/x509/cert.c`, `chain.c`, `pem.c`, `fingerprint.c`, `asn1.c`,
  `pkey.c`, `trust_store.c`
- headers: `opssl/crypto.h`, `conn.h`, `ctx.h`, `cert.h`, `ktls.h`,
  `types.h`, `cbs.h`
- build options: `postquantum`, `ktls`, `session_export`

Notable APIs:

- `opssl_mlkem_new`, `opssl_mlkem_keygen`, `opssl_mlkem_encaps`,
  `opssl_mlkem_decaps`, with ML-KEM-768 sizes `pk=1184`, `sk=2400`,
  `ct=1088`, `ss=32`
- `opssl_x25519_keygen`, `opssl_x25519_derive`
- `opssl_aead_seal`, `opssl_aead_open`, including ChaCha20-Poly1305 and
  AES-GCM
- `opssl_x509_from_pem`, `opssl_x509_from_der`, `opssl_x509_get_spki`,
  `opssl_x509_fingerprint`, `opssl_x509_verify`
- `opssl_conn_export_keying_material`, `opssl_conn_get_fingerprint`
- `opssl_conn_export`, `opssl_conn_import`
- `opssl_ktls_promote`, `opssl_ktls_promote_late`, `opssl_ktls_adopt`,
  `opssl_ktls_extract_keys`

### opcodec

Read scope:

- `/home/kain/ophion/subprojects/opcodec/README.md`
- `/home/kain/ophion/subprojects/opcodec/OPCODEC.md`
- `/home/kain/ophion/subprojects/opcodec/BWE_INTEGRATION.md`
- `/home/kain/ophion/subprojects/opcodec/include/opcodec/*.h`
- active Ophion LADON module references under `/home/kain/ophion/docs/reference/modules/`
- historical LADON media wire doc found only in
  `/home/kain/ophion/.claude/worktrees/.../doc/technical/ladon-media-wire.md`

The active Ophion tree has LADON source and module references, but the
`doc/technical/ladon-media-wire.md` path named by opcodec is not present in the
main source tree. Treat that wire Markdown as historical supporting context and
prefer the active opcodec headers/source plus active LADON module inventory.

Important actual module names and capabilities:

- OPVOX audio: `audio`, `psych`, `bwe`, `tns`, `pns`, `pvq`, `pitch`, `ns2`,
  `dtx`, `aec2`, `epsc`, `sam`, `separator`, `opfield`
- OPVIS video: `video`, `saliency`, `tfi`, `gbs`, `hdr`, `screen`, `svf`,
  `lvc`, `cdef`, `tnr`, `vplc`, `vidutil`
- session/transport: `avsession`, `secure`, `fec`, `jitter`, `netadapt`
- browser target: `build-wasm.sh`, `cross/emscripten.ini`, `src/wasm_api.c`

Notable APIs and wire facts:

- `opvox_encoder_init`, `opvox_encode`, `opvox_decode`; 20 ms frames at
  8/16/32/48 kHz; `OPVOX_MAX_ENCODED = 512`
- `opvis_encoder_create`, `opvis_encode`, `opvis_decode`; I/P/B/SKIP/INTERP,
  OPVIS v1 header with frame type, quality, dimensions, frame number, color
  flags, payload length
- `opav` packet format: type, sequence number, timestamp, payload length,
  payload
- `opsec` v2 encrypted frame:
  `[version][frame_type][sender_id][counter][epoch][codec_id][flags]`
  plus encrypted payload and 16-byte tag
- `opsec` uses per-sender key derivation, nonce XOR salt, generation ratchet,
  512-packet anti-replay, previous-key grace
- `opfec` is XOR 1D/2D FEC up to 8 packets with interleaving; useful as a
  first-pass local recovery model, not sufficient as Orochi's long-term
  rateless media FEC
- `opjit` tracks reorder, adaptive delay, NACK entries, burst loss
- `netadapt` tracks RTT/loss/jitter, Kalman-like BWE, stable/probing/draining/
  recovery, codec quality and FEC recommendations

## opssl -> Orochi Crypto and Transport

### What To Port To Zig

Port algorithms and discipline, not the C API shape.

`crypto/mlkem.zig`

- Implement ML-KEM-768 first, ML-KEM-1024 second. ML-KEM-768 is the default
  Tsumugi handshake component because the current S2S plan names X-Wing-style
  X25519+ML-KEM-768.
- Use opssl's `mlkem.c` as an implementation inventory: FIPS 203 parameters,
  NTT path, keygen/encaps/decaps test structure, ACVP/KAT harness shape.
- Zig API should be parameterized at comptime:
  `MlKem(.ml_kem_768).keygen`, `.encaps`, `.decaps`, with fixed-size public
  key, secret key, ciphertext, and shared-secret types. No runtime "level" switch
  in core protocol code.
- Decapsulation failure must use implicit rejection and constant-time selection.
  It must never branch on secret-dependent validity.

`crypto/xwing.zig`

- Implement the hybrid combiner explicitly. Do not use naive
  `HKDF(x25519_ss || mlkem_ss)`.
- Tsumugi should derive:
  `root = KDF("orochi-tsumugi-xwing-v1", x25519_ss || mlkem_ss ||
  x25519_pub_i || x25519_pub_r || mlkem_ct || transcript_hash ||
  meshpass_hash || negotiated_bands)`.
- Use SHA3/SHAKE or HKDF-HMAC with careful domain separation. The deep research
  correctly warns that the ciphertexts/transcript must be mixed for a robust
  KEM combiner.

`crypto/ct.zig`

- Port opssl's constant-time discipline into a Zig type discipline:
  `Secret(T)`, `SecretBytes(N)`, `CtBool`, `ctSelect`, `ctEq`, secure zero.
- In crypto code, `CtBool` must not implicitly become `bool`. Declassification
  requires a named reason such as `.aead_tag_verified` or
  `.public_certificate_result`.
- Add build-time checks later for branches, indexes, allocator sizes, and
  switch conditions derived from secret wrappers.

`crypto/aead.zig` and `proto/tsumugi.zig`

- Orochi already has AEAD and Tsumugi ratchet code. opssl reinforces that
  ChaCha20-Poly1305 and AES-GCM are the right primitives.
- S2S default remains ChaCha20-Poly1305 because it is fast on non-AES hardware
  and matches opcodec `secure`. AES-GCM is a negotiated fast path only when both
  sides advertise hardware support.
- AEAD open must authenticate before state commit. Replay counters and skipped
  keys advance only after tag success.

`crypto/x509.zig`, `crypto/x509_verify.zig`

- Port the X.509 capability set needed by IRC/client surfaces and TLS/WebSocket:
  DER, PEM, TBSCertificate, SPKI extraction, SAN DNS/IP, validity, key usage,
  basic constraints, signature verification, trust store lookup.
- CERTFP/SASL-EXTERNAL needs fingerprints:
  DER-SHA256 as default, DER-SHA512 and SPKI-SHA256 as optional stable identity
  forms; SHA1 only for explicit legacy compatibility, never as a security
  default.
- `opssl_x509_get_spki`, `opssl_x509_fingerprint`, and
  `opssl_conn_export_keying_material` are the blueprint. In Orochi the APIs
  should feed existing `proto/certfp.zig`, `proto/sasl_external_verify.zig`,
  and the web/TLS listener path.

`crypto/tls13.zig`

- Use opssl's TLS 1.3 records, key schedule, exporter, session ticket, and kTLS
  lessons as reference. Do not port TLS 1.2 into core unless a compatibility
  policy explicitly requires it.
- S2S Tsumugi is not "TLS with another name"; Tsumugi stays the mesh secure
  channel. TLS exists for client IRC TLS, HTTPS/WebSocket/WebTransport
  termination, and optional outer carrier deployments.

### Tsumugi Wire/State To Carry

The Tsumugi handshake needs to carry:

- protocol version and feature bitmap
- initiator/responder `node_id`
- Ed25519 static public keys and signatures
- MeshPass and realm root hash
- X25519 ephemeral public keys
- ML-KEM-768 public key from responder and ML-KEM ciphertext from initiator
- negotiated bands, media rights, and max frame families
- transcript hash and final confirmation MAC/signature

The established Tsumugi state needs to carry:

- peer `node_id`, local role, realm, MeshPass hash
- current root generation
- send/recv chain keys
- nonce base, send counter, receive counter
- skipped-key cache and replay bitmap
- byte/frame/time rekey budgets
- negotiated bands and priority weights
- peer capabilities: `mlkem768`, `mlkem1024`, `aead_chacha20`, `aead_aesgcm`,
  `ktls_outer`, `quic_datagram`, `media_band`, `raptorq`

For `/UPGRADE` or live migration, this state must be serializable as a sealed
snapshot:

- `TsumugiLinkSnapshot`: peer identity, generation, root/chain keys, counters,
  skipped-key cache, replay window, negotiated capabilities
- `RyusenTransportSnapshot`: fd or QUIC connection handle, backend kind, read
  accumulator, partial frame decoder, write queue, credits, priority scheduler
  deficit counters, last HLC seen/sent
- `MeshSessionSnapshot`: active/passive view membership context, outstanding
  anti-entropy ranges, route hints, media track registry

The snapshot itself must be encrypted with a daemon-local upgrade key, include a
monotonic snapshot id, and be single-use. Do not move raw key blobs through
normal logs, crash dumps, or unpinned heap memory.

### kTLS In Ryusen

`opssl_ktls_promote`, `opssl_ktls_promote_late`, `opssl_ktls_adopt`, and
`opssl_ktls_extract_keys` are the exact operational blueprint.

Fit:

- kTLS is a Ryusen transport backend optimization for TLS-record links. It is
  not the security model.
- It works for client TLS, WebSocket-over-TLS, possible TLS-wrapped S2S carriers,
  and bulk relay paths where TLS is the outer record layer.
- It does not offload custom Tsumugi AEAD frames, and it does not apply to QUIC
  datagrams.

Ryusen should model:

```text
CryptoOwner =
  TsumugiUserland      // S2S mesh crypto, default
  Tls13Userland        // client/web TLS before promotion
  KtlsKernel           // TLS records owned by Linux kernel
  QuicUserland         // QUIC/TLS 1.3 stack owns packet protection
```

For `KtlsKernel`, the event loop owns only the fd and cleartext read/write API;
TLS keys live in the kernel. On upgrade, transfer the socket by fd-passing and
adopt it as kTLS-active in the new process. That is the best path because no
traffic keys cross process boundaries.

For non-kTLS TLS links, use the session-export idea: serialize cipher suite,
traffic secrets, IVs, sequence numbers, pending records, and handshake state.
In Orochi this should be `Tls13SessionSnapshot`, sealed and versioned like
`TsumugiLinkSnapshot`.

### Session Export/Import And `/UPGRADE`

opssl's `session_export` option and `opssl_conn_export`/`opssl_conn_import`
show the right live-migration story:

1. Stop reading new application frames on the old process.
2. Drain pending writes or mark them in the snapshot.
3. Snapshot crypto state, sequence numbers, frame decoder buffer, link credits,
   priority scheduler state, and peer identity.
4. Pass the fd and sealed snapshot to the new process.
5. New process imports state, resumes counters exactly, and sends a signed
   `UPGRADE_RESUME` control frame.
6. Peer accepts only if generation, counter, HLC, and transcript binding match.

For S2S, `/UPGRADE` is not merely TLS session migration. It is link-session
migration: Tsumugi ratchet, Ryusen transport, Goryu anti-entropy work, and media
track control state must move as one coherent object. The invariant is "no
re-handshake, no replay window reset, no lost causal position."

## opcodec -> Orochi Media Bands

### Band Layout

Keep the S2S band model from the current design:

- band 0: control
- band 1: membership
- band 2: anti-entropy
- band 3: IRC/events
- band 4: services
- band 5: media control
- bands >=64: media tracks

Map opcodec/LADON as follows:

- LADON `VOICE_JOIN`, `VIDEO_JOIN`, `MEDIA_OFFER`, `MEDIA_ANSWER`,
  `MEDIA_STATS`, `MEDIA_NACK`, `MEDIA_BYE`, `VIDEO_KEYREQ`, `SPATIAL_*`,
  `SIMULCAST_*`, `ABR_REPORT`, `QUALITY_HINT` become band 5 control schemas.
- OPVOX audio frames ride one media band per audio track.
- OPVIS camera/screen frames ride one media band per video or screen track.
- Data-channel/whiteboard/annotation style payloads can use separate media-data
  bands only after core media control exists.

Do not preserve LADON's 8-bit media frame type registry as Orochi's identity
model. Treat those type bytes as source taxonomy only.

### SID-Free, NodeId-Based Media Identity

LADON data frames carry nick, channel, `sender_id`, seq, FEC info, and encrypted
payload. Orochi should separate identity from hot-path compact handles:

```text
MediaTrackAnnounce {
  track_id: u128,              // random or BLAKE3-derived stable track id
  owner_node: NodeId,
  owner_user: UserId or account assertion,
  channel_cid: ChannelId,
  kind: audio | video | screen | data,
  codec: opvox | opvis | external,
  clock_rate: u32,
  rights: speak | publish | relay | mix,
  fec: none | xor | raptorq,
  encryption: tsumugi_link | media_e2ee,
  max_bitrate: u32,
  simulcast_layers: optional
}

MediaFrame {
  track_id: u128,
  seq: u64,
  timestamp: u64,
  frame_kind: audio | video_key | video_delta | video_b | skip | fec_repair,
  fec_group: optional,
  dependency: optional previous seq / keyframe id,
  payload: bytes
}
```

`sender_id` may exist only as a per-link compression table entry negotiated on
band 5. It is never a mesh identity, never globally meaningful, and never
replaces `node_id`.

Nick and channel names should not be repeated in every media data frame. Band 5
announces bind track to user/channel. Bands >=64 carry compact track ids,
sequence, timestamps, and payload.

### OPVOX Audio Mapping

OPVOX is a strong fit for a later media band:

- 20 ms frames align with jitter buffer and voice scheduling.
- 8/16/32/48 kHz modes let Ryusen shift bitrate without changing transport.
- `psych`, `bwe`, `tns`, `pns`, `pvq`, `pitch`, `ns2`, `dtx`, `epsc`, `sam`,
  and `opfield` give useful adaptation levers.
- `sam` is valuable for emergency low-bandwidth audio and should be exposed as
  an audio track mode, not as a separate protocol.
- `opfield` spatial metadata should be control-plane metadata attached to tracks
  or mixed rooms, not baked into the mesh identity.

Suggested band payload:

```text
OPVOXFramePayload {
  opvox_header: bytes,     // codec bitstream header from OPVOX
  codec_frame: bytes,
  optional epsc: bytes,
  optional aec2: bytes,
  optional opfield_position: quantized position update id
}
```

Spatial audio (`opfield`) is a reason to keep band 5 extensible. Position,
mixing intent, HOA/binaural mode, and listener capability changes are control
updates. Audio samples stay on media bands.

### OPVIS Video Mapping

OPVIS maps cleanly to media bands:

- OPVIS frame types I/P/B/SKIP/INTERP map to `frame_kind`.
- `saliency` and SARDO become encoder-side quality decisions; the mesh does not
  need to parse saliency maps unless a mixer/transcoder is active.
- `tfi` means the sender may omit INTERP frames; receivers synthesize them.
  Transport should preserve timing and dependencies rather than assuming every
  displayed frame has a packet.
- `screen` mode and `svf` keyframe forcing should surface in band 5 quality and
  keyframe control.
- `vplc`, `tnr`, `cdef`, `vidutil`, and `lvc` are codec/runtime details unless
  a server-side WASM mixer decodes the stream.

For B-frames, carry both decode timestamp and presentation timestamp. LADON's
historical DTS/PTS split is the right idea; Orochi should make it explicit:

```text
VideoFrameTiming {
  dts: u64,
  pts: u64,
  max_reorder_ms: u16,
}
```

### Browser Path

Keep both browser paths:

- WebSocket: universal fallback, reliable, acceptable for IRC and low-rate media
  control; media frames may suffer TCP head-of-line blocking.
- WebTransport: preferred media path, QUIC streams/datagrams, connection
  migration, lower latency, better fit for media bands.

Browser codec path:

- Use opcodec's WASM build shape as the blueprint: OPVOX/OPVIS in a single WASM
  module with `_opvox_wasm_*` and `_opvis_wasm_*` style entry points.
- In browsers, use WebCodecs/WebAudio where useful, but keep opcodec/WASM as the
  custom IRC-tuned codec path.
- Browser AEAD should use WebCrypto or Tsumugi-derived keys exposed through a
  minimal JS/WASM boundary. Avoid giving long-lived root secrets to codec WASM
  when a short-lived media key is enough.

Server path:

- Default server media role is relay, not decode. It validates control rights,
  schedules bands, forwards frames, and observes congestion metadata.
- Mixing, recording, moderation preview, transcription, and transcoding are
  separate services. Those can run in OroWasm sandboxes or external workers.

### Does opcodec `secure` Compose With Tsumugi?

For normal S2S relay, opcodec `secure` is redundant with Tsumugi link AEAD.
Double-encrypting every frame adds overhead and failure modes without improving
relay-to-relay authenticity, because Tsumugi already authenticates the S2S outer
frame and binds source node, band, stream, generation, and counters.

Use one of three modes:

1. `tsumugi_link`: default S2S mode. Codec payload is plaintext inside the
   encrypted Tsumugi frame. Relays that terminate Tsumugi can inspect only the
   metadata needed for scheduling and authorization.
2. `media_e2ee`: optional client-to-client or publisher-to-subscriber privacy.
   An inner opcodec-style `opsec` envelope protects media payload from Orochi
   relays. Tsumugi still protects link metadata and routing.
3. `mixed_service`: server-side mixer/transcoder is authorized to decrypt media.
   The media key is issued to the mixer service by signed control-plane policy.

If `opsec` is used, it must be domain-separated from Tsumugi:

- independent media root key derived by a named exporter:
  `HKDF(tsumugi_exporter, "orochi media e2ee v1", track_id || epoch)`
- separate counters and epochs
- AAD includes `track_id`, `seq`, `timestamp`, codec id, and owner `node_id`
- inner `sender_id` replaced or bound to `node_id + track_id`

`opsec` concepts worth porting/reimagining:

- per-sender keys and salts for group media
- nonce = salt XOR counter
- generation ratchet and previous-key grace
- 512-packet anti-replay for video reorder
- traffic-analysis padding/dummy frames for privacy-sensitive calls

But do not let `opsec` drive the core S2S ratchet. Tsumugi is the mesh security
authority.

### FEC And RaptorQ

opcodec `fec` is useful as a first local-recovery tool:

- XOR 1D/2D FEC up to 8 packets
- low CPU
- predictable overhead
- good for small burst loss when latency budget is tight

Orochi's long-term media FEC should be RaptorQ-style rateless FEC for bands >=64:

- sender emits source symbols plus repair symbols
- receiver decodes after any `k + epsilon` symbols
- no per-loss NACK round trip for normal media playout
- repair budget can be adapted continuously by Ryusen BWE/ECN feedback

Interplay:

- OPVOX low-latency audio can start with XOR interleaving because the group sizes
  are tiny and latency cost is bounded.
- OPVIS video, keyframes, screen frames, and high-loss WAN links should prefer
  RaptorQ repair symbols.
- Goryu-Sync anti-entropy and RaptorQ share the "rateless" design direction but
  solve different problems: RIBLT reconciles set difference; RaptorQ repairs
  packet loss.
- Band 5 should negotiate `fec = none | xor_low | xor_med | raptorq` per track.

### BWE Feeding L4S/ECN Congestion Control

opcodec `netadapt` provides useful input signals: RTT, jitter, loss, acked bytes,
bandwidth estimate, burst-loss flag, and target bitrate recommendation.

Ryusen should consume media BWE, not duplicate it blindly:

```text
MediaStats -> TrackBwe -> RyusenScheduler -> TransportCC
                         -> codec recommendation
                         -> FEC repair budget
                         -> L4S/ECN marking response
```

For QUIC/WebTransport media bands:

- ECN CE marks and L4S signals feed scalable congestion control.
- Loss without ECN means recovery/FEC adjustment.
- Rising RTT with low loss means queue buildup; reduce video first, then FEC,
  preserve OPVOX audio.
- Burst-loss flag from `jitter` increases interleaving or RaptorQ repair before
  dropping bitrate.
- `netadapt` state transitions map to Ryusen policy:
  `STABLE` permits probing, `PROBING` raises video/simulcast layer, `DRAINING`
  drops B-frames and lowers OPVIS quality, `RECOVERY` restores additively.

The mesh scheduler must protect bands 0-4. Media congestion must never starve
control, membership, anti-entropy, IRC events, or services.

## Clean-Room Reuse Policy

### Pure-Zig Port

Core infrastructure must be pure Zig:

- ML-KEM-768/1024
- X25519/Ed25519 integration and X-Wing combiner
- HKDF/HMAC/SHA3/SHAKE as needed by Tsumugi
- ChaCha20-Poly1305 and AES-GCM
- constant-time wrappers and zeroization
- Tsumugi handshake, ratchet, replay, exporter
- X.509/CERTFP/SASL-EXTERNAL support
- Ryusen scheduler, transport snapshots, kTLS syscalls where applicable
- media control schemas, track registry, authorization, congestion interfaces
- RaptorQ implementation if it is used by core band scheduling

Reason: these pieces own trust boundaries, key material, admission, live
migration, and mesh correctness. They must be inspectable, testable, and
deterministic inside Orochi.

### OroWasm Sandbox

Candidate WASM components:

- OPVOX encode/decode
- OPVIS encode/decode
- `psych`, `bwe`, `tns`, `pns`, `pvq`, `sam`, `opfield`
- `saliency`, `tfi`, `screen`, `lvc`, `cdef`, `tnr`, `vplc`, `vidutil`
- optional server-side mixer/transcoder/recorder workers

Reason: media codecs are large, math-heavy, and less central to S2S trust. A
WASM sandbox gives memory isolation, deterministic resource limits, and a clean
host ABI while avoiding C interop in core.

OroWasm host ABI should be narrow:

```text
alloc/free frame buffers
encode/decode one frame
query codec caps
set bitrate/quality/FEC recommendation
read/write codec stats
no direct sockets
no direct filesystem
no access to Tsumugi root keys
```

The server should not require codec WASM to relay media. Decode only when a
policy-authorized service needs it.

### Historical/Reference Only

Do not port directly:

- LADON 8-byte header and 8-bit frame registry
- LADON `sender_id` as identity
- Msgpack tuple wire format
- C opaque-handle API shape
- thread-local error stacks
- TLS 1.2 state machine unless a later compatibility decision explicitly adds it
- opcodec's `secure` as the default S2S encryption layer

## Phased Plan

### Phase 0: Documentation And Tests

- Keep this document as the asset map.
- Add future KAT/test inventory for ML-KEM, X25519, X-Wing combiner, X.509
  fingerprints, Tsumugi snapshot import/export, media control schemas.
- Confirm license policy before any line-level porting from GPL C sources.

### Phase 1: Crypto Foundation

- Implement `crypto/mlkem.zig` with ML-KEM-768 KATs.
- Implement `crypto/xwing.zig` combiner and transcript tests.
- Harden `crypto/secret.zig`, `crypto/aead.zig`, and `proto/tsumugi.zig`
  around counter exhaustion, replay, skipped-key commit, and explicit
  declassification.
- Add exporter labels for `media_e2ee`, SASL channel binding, and upgrade
  snapshots.

### Phase 2: Tsumugi Handshake And Migration

- Add Tsumugi handshake wire schemas over current `s2s_frame`.
- Bind MeshPass, `node_id`, realm root, negotiated bands, and media rights.
- Implement `TsumugiLinkSnapshot` and import/export tests.
- Add `/UPGRADE` resume control frames and fail-closed peer validation.

### Phase 3: X.509 And Client Auth Surface

- Port X.509 DER/PEM/SPKI/fingerprint handling in Zig.
- Wire CERTFP and SASL-EXTERNAL to TLS exporter/channel binding.
- Keep S2S node identity Ed25519/MeshPass-based; do not make X.509 the mesh
  identity.

### Phase 4: Ryusen Transport Backends

- Model `CryptoOwner` and transport snapshots.
- Add kTLS backend for TLS-record links and upgrade fd adoption.
- Keep Tsumugi userland crypto as default S2S.
- Add congestion telemetry interface for future QUIC/WebTransport media bands.

### Phase 5: Media Control Seam

- Add band 5 media-control schemas:
  track announce, subscribe, unsubscribe, stats, nack, keyframe request,
  quality hint, simulcast selection, spatial updates, media bye.
- Add band >=64 frame envelope with `track_id`, seq, timestamp, frame kind,
  dependency, FEC metadata, payload.
- Ensure the scheduler treats media as drop/degrade-able and never blocks
  control or Goryu-Sync.

### Phase 6: Browser And WASM Prototype

- Define OroWasm ABI for OPVOX/OPVIS-style codecs.
- Prototype browser WebSocket media fallback and WebTransport preferred path.
- Keep browser codec keying separate: short-lived track keys only, no Tsumugi
  root exposure.

### Phase 7: Media FEC And BWE

- Start with XOR/interleaved FEC for OPVOX-like audio.
- Add RaptorQ for video/keyframes/high-loss media.
- Connect `TrackBwe` to Ryusen L4S/ECN congestion decisions.
- Add policy: audio preserved first, video quality/simulcast/B-frames reduced
  before core bands are affected.

## Risks

- **License contamination:** both libraries are GPL. Treat as blueprint unless
  Orochi's licensing explicitly permits direct code translation.
- **Constant-time regressions in Zig:** Zig makes APIs safer but does not
  magically prevent timing leaks. CT wrappers and tests are mandatory.
- **ML-KEM implementation complexity:** NTT, rejection sampling, and implicit
  rejection are easy to get subtly wrong. KATs and differential tests are
  non-negotiable.
- **Double encryption confusion:** Tsumugi and opcodec `secure` must have clear
  roles. Default link security is Tsumugi; inner media E2EE is optional and
  domain-separated.
- **kTLS scope creep:** kTLS helps TLS records, not custom Tsumugi or QUIC media.
  It is a backend optimization only.
- **Migration key exposure:** session snapshots carry live traffic keys. Seal,
  pin, zeroize, single-use, and suppress core dumps around upgrade windows.
- **Media starving control:** scheduler policy must be tested under overload so
  media bands cannot delay membership, anti-entropy, pings, or IRC events.
- **Server-side codec attack surface:** decode/transcode only in OroWasm or a
  separate worker process with resource limits.
- **Browser fragmentation:** WebTransport is the right media target, but
  WebSocket must remain a functional fallback.
- **BWE conflicts:** codec BWE and transport congestion control can fight each
  other. Ryusen should own the final policy and feed recommendations back to
  codecs.

## Bottom Line

Port opssl's crypto primitives and operational patterns into pure Zig where they
touch trust: ML-KEM, X-Wing, constant-time discipline, X.509/CERTFP, TLS
exporters, kTLS-aware migration, and session snapshot design.

Do not port opcodec into core. Use its OPVOX/OPVIS module taxonomy, frame
timing, `secure` concepts, `fec`, `jitter`, and `netadapt` as the design
blueprint for media bands. Relay media by default; decode only in OroWasm or an
authorized worker. Keep Tsumugi as the S2S security authority, reserve inner
opcodec-style AEAD for optional media E2EE, and make media congestion/feed-back
serve Ryusen without ever blocking core IRC and CRDT convergence.
