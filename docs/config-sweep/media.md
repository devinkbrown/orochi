# Orochi media subsystem — hardcoded operational/tuning constant sweep

READ-ONLY survey. Scope: substrate media primitives (`media_session.zig`,
`audio_mix.zig`, `opcodec_frame.zig`, `red_fec.zig`, `proto/rtp_profile.zig`,
`proto/sdp_lite.zig`, `suimyaku/media.zig`) plus daemon media-control features
(`media_room.zig`, `media_pin.zig`, `quality_hint.zig`, `spotlight.zig`,
`transcript.zig`, `recording_consent.zig`, `recording_index.zig`,
`reaction_tally.zig`, `reaction_leaderboard.zig`).

Excluded: RTP/RTCP wire-format constants mandated by spec (`header_len`,
`rtcp_*_report_len`, `rtp_version`, `MEDIA_BAND_FLOOR`/`min_band_id=64` band
floor, `HEADER_BYTES`, `FEC_HEADER_SIZE`/`FEC_OVERHEAD`, ULPFEC 16-frame
generation cap, 10-bit block length, RFC-3550 jitter gain `/16.0`), enum
discriminants, magic strings, crypto suite tags, pure compile-time type widths,
and test-only literals. Chat-side pin/typing modules (`pin_board`, `pin_vote`,
`session_pin`, `pinned_messages`, `typing_state`) are out of media-call scope.

Note: `audio_mix.Mixer` and `suimyaku/media` `Session`/`LayerDeclaration`/
`ForwardSet`/`ReassemblyBuffer` take their core sizes as runtime/comptime params
(no embedded literal), so the lift targets are the *call sites* and the
documented defaults. Borderline entries are marked.

---

## [media] — top-level media / reassembly

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/substrate/opcodec_frame.zig:190 | `ReassemblyConfig.window` | 64 | Out-of-order reorder/jitter window depth (frames); frames outside are late-dropped | media.reorder_window_frames | uint | 64 | 8..1024 |
| src/substrate/media_session.zig:173,196 | `Receiver(256, 64)` / `.{ .window = 16 }` call sites | max_payload 256, window_cap 64, runtime window 16 | Receiver reassembly buffer payload cap + reorder window wiring (borderline: currently only in tests but is the canonical wiring) | media.max_payload_bytes / media.reorder_window_frames | uint | 256 / 16 | 64..65535 / 8..1024 |

## [media.audio] — conference mixer / audio

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/substrate/audio_mix.zig:60-61 | `Mixer.init` `energy_threshold` (doc "1e-6 reasonable default") | 1e-6 | RMS² gate below which a participant is silent / not an active speaker | media.audio.energy_threshold | float | 1e-6 | 0.0..1.0 |
| src/substrate/audio_mix.zig:61 | `Mixer.init` `frame_size` (no embedded default; caller-supplied) | — (caller) | Samples per audio frame for the mixer; sets mix buffer length | media.audio.frame_size_samples | uint | 960 | 120..4096 |
| src/substrate/audio_mix.zig:88 | default participant `gain` | 1.0 | Initial per-participant linear gain on join | media.audio.default_gain | float | 1.0 | 0.0..8.0 |

## [media.video] — codec quality / simulcast geometry / ABR

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/substrate/suimyaku/media.zig:291 | `SimulcastLayer.init` max width guard | 3840 | Max accepted layer width (4K) | media.video.max_layer_width | uint | 3840 | 16..7680 |
| src/substrate/suimyaku/media.zig:291 | `SimulcastLayer.init` max height guard | 2160 | Max accepted layer height (4K) | media.video.max_layer_height | uint | 2160 | 16..4320 |
| src/substrate/suimyaku/media.zig:294 | `SimulcastLayer.init` max fps guard | 60 | Max accepted layer frame rate | media.video.max_layer_fps | uint | 60 | 1..240 |
| src/substrate/suimyaku/media.zig:313 | `ReceiverConstraints.max_fps` default | 60 | Default receiver fps ceiling when unspecified | media.video.default_receiver_max_fps | uint | 60 | 1..240 |

## [media.abr] — adaptive bitrate controller (suimyaku/media.zig `AbrConfig`/`abrHint`)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/substrate/suimyaku/media.zig:584 | `AbrConfig.min_bitrate_kbps` | 32 | Floor bitrate; below this ABR pauses the stream | media.abr.min_bitrate_kbps | uint | 32 | 8..2000 |
| src/substrate/suimyaku/media.zig:585 | `AbrConfig.max_bitrate_kbps` | 6000 | Ceiling bitrate ABR will ramp to | media.abr.max_bitrate_kbps | uint | 6000 | 100..50000 |
| src/substrate/suimyaku/media.zig:586 | `AbrConfig.high_loss_percent` | 8 | Packet-loss % at/above which the link is "congested" → decrease | media.abr.high_loss_percent | uint | 8 | 1..100 |
| src/substrate/suimyaku/media.zig:587 | `AbrConfig.high_rtt_ms` | 350 | RTT (ms) at/above which the link is "congested" → decrease | media.abr.high_rtt_ms | duration(ms) | 350 | 20..5000 |
| src/substrate/suimyaku/media.zig:616 | `abrHint` nack/sec congestion trigger (`>= 20`) | 20 | NACKs/sec at/above which the link is "congested" | media.abr.high_nack_per_second | uint | 20 | 1..1000 |
| src/substrate/suimyaku/media.zig:619 | decrease loss-scaled factor (`mulDiv(cur, 60, 100)`) | 60% | Bitrate retained on congestion (loss-driven scale) | media.abr.congestion_decrease_percent | uint | 60 | 10..95 |
| src/substrate/suimyaku/media.zig:620 | decrease network-scaled factor (`mulDiv(available, 80, 100)`) | 80% | Fraction of available bandwidth targeted on congestion | media.abr.congestion_utilization_percent | uint | 80 | 10..100 |
| src/substrate/suimyaku/media.zig:624 | high-loss FEC-level escalation threshold (`>= 15` → fec_level 3 else 2) | 15 | Loss % at which FEC level jumps to max while decreasing | media.abr.fec_escalate_loss_percent | uint | 15 | 1..100 |
| src/substrate/suimyaku/media.zig:629 | headroom-to-increase ratio (`available > cur + cur/4`) | 25% (÷4) | Spare-bandwidth margin required before ABR increases | media.abr.increase_headroom_percent | uint | 25 | 5..200 |
| src/substrate/suimyaku/media.zig:632 | increase step factor (`mulDiv(cur, 115, 100)`) | 115% | Bitrate ramp-up multiplier per increase step | media.abr.increase_step_percent | uint | 115 | 101..400 |
| src/substrate/suimyaku/media.zig:641 | hold-state low-loss FEC gate (`<= 1` → fec 0 else 1) | 1 | Loss % at/below which steady-state runs with no FEC | media.abr.hold_no_fec_loss_percent | uint | 1 | 0..100 |
| src/substrate/suimyaku/media.zig:608,624,612 | ABR `fec_level` values (0/1/2/3) | 0..3 | FEC redundancy level emitted per ABR state (borderline: derived ladder, not a single knob) | media.abr.max_fec_level | uint | 3 | 0..8 |

## [media.sfu] — roster / capacity bounds

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/daemon/media_room.zig:12 | `max_participants` (`media.Session(64)`) | 64 | Max participants per channel media call (SFU roster size) | media.sfu.max_participants_per_room | uint | 64 | 2..1024 |
| src/daemon/media_room.zig:36 | `max_breakout_bytes` | 32 | Max length of a breakout (sub-room) label | media.sfu.max_breakout_label_bytes | uint | 32 | 8..256 |
| src/substrate/suimyaku/media.zig:9 | `max_participant_id_bytes` | 64 | Max participant identifier length | media.sfu.max_participant_id_bytes | uint | 64 | 16..256 |
| src/substrate/suimyaku/media.zig:10 | `max_rid_bytes` | 16 | Max simulcast RID length | media.sfu.max_rid_bytes | uint | 16 | 4..64 |
| src/substrate/suimyaku/media.zig:11 | `max_codecs` | 8 | Max codecs per media capability set | media.sfu.max_codecs | uint | 8 | 1..32 |
| src/substrate/suimyaku/media.zig:12 | `max_crypto_suites` | 4 | Max crypto suites per capability set | media.sfu.max_crypto_suites | uint | 4 | 1..16 |

## [media.captions] — live transcript ring

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/daemon/transcript.zig:8 | `max_text_bytes` | 400 | Max caption text length | media.captions.max_text_bytes | uint | 400 | 64..4000 |
| src/daemon/transcript.zig:9 | `max_speaker_bytes` | 64 | Max caption speaker-name length | media.captions.max_speaker_bytes | uint | 64 | 16..256 |
| src/daemon/transcript.zig:10 | `max_per_channel` | 128 | Retained caption ring depth per channel (FIFO eviction) | media.captions.ring_depth_per_channel | uint | 128 | 16..4096 |
| src/daemon/transcript.zig:11 | `max_channels` | 4096 | Max channels holding live transcripts | media.captions.max_channels | uint | 4096 | 64..1048576 |

## [media.spotlight]

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/daemon/spotlight.zig:5 | `max_channels` | 4096 | Max channels with active spotlight sets | media.spotlight.max_channels | uint | 4096 | 64..1048576 |
| src/daemon/spotlight.zig:6 | `max_spotlights_per_channel` | 256 | Max spotlighted participants per channel | media.spotlight.max_per_channel | uint | 256 | 1..4096 |
| src/daemon/spotlight.zig:7 | `max_channel_bytes` | 128 | Max channel-name length (spotlight) | media.spotlight.max_channel_bytes | uint | 128 | 16..512 |
| src/daemon/spotlight.zig:8 | `max_participant_bytes` | 64 | Max participant-id length (spotlight) | media.spotlight.max_participant_bytes | uint | 64 | 16..256 |

## [media.pins] — pinned media references (call assets)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/daemon/media_pin.zig:4 | `max_channels` | 4096 | Max channels holding pinned media | media.pins.max_channels | uint | 4096 | 64..1048576 |
| src/daemon/media_pin.zig:5 | `max_pins_per_channel` | 50 | Max pinned media references per channel | media.pins.max_per_channel | uint | 50 | 1..1024 |
| src/daemon/media_pin.zig:6 | `max_channel_len` | 128 | Max channel-name length (pins) | media.pins.max_channel_bytes | uint | 128 | 16..512 |
| src/daemon/media_pin.zig:7 | `max_url_len` | 2048 | Max pinned media URL length | media.pins.max_url_bytes | uint | 2048 | 64..16384 |
| src/daemon/media_pin.zig:8 | `max_actor_len` | 128 | Max actor (pinned-by) name length | media.pins.max_actor_bytes | uint | 128 | 16..512 |

## [media.recording] — consent store + session index

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/daemon/recording_consent.zig:6 | `max_entries` | 262144 | Max total (channel,participant) consent entries | media.recording.max_consent_entries | uint | 262144 | 1024..16777216 |
| src/daemon/recording_consent.zig:7 | `max_channel_bytes` | 128 | Max channel-name length (consent) | media.recording.max_channel_bytes | uint | 128 | 16..512 |
| src/daemon/recording_consent.zig:8 | `max_participant_bytes` | 64 | Max participant-id length (consent) | media.recording.max_participant_bytes | uint | 64 | 16..256 |
| src/daemon/recording_index.zig:7 | `max_channels` | 4096 | Max channels in recording index | media.recording.max_channels | uint | 4096 | 64..1048576 |
| src/daemon/recording_index.zig:8 | `max_sessions_per_channel` | 1024 | Max recording sessions tracked per channel | media.recording.max_sessions_per_channel | uint | 1024 | 16..65536 |
| src/daemon/recording_index.zig:9 | `max_key_bytes` | 128 | Max channel/id/by key length (recording index) | media.recording.max_key_bytes | uint | 128 | 16..512 |

## [media.reactions] — call reaction tally + leaderboard

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/daemon/reaction_tally.zig:3 | `max_messages` | 4096 | Max messages tracked for reactions | media.reactions.max_messages | uint | 4096 | 64..1048576 |
| src/daemon/reaction_tally.zig:4 | `max_msgid_len` | 128 | Max message-id length | media.reactions.max_msgid_bytes | uint | 128 | 16..512 |
| src/daemon/reaction_tally.zig:5 | `max_emoji_len` | 64 | Max emoji token length | media.reactions.max_emoji_bytes | uint | 64 | 8..256 |
| src/daemon/reaction_tally.zig:6 | `max_reactor_len` | 128 | Max reactor name length | media.reactions.max_reactor_bytes | uint | 128 | 16..512 |
| src/daemon/reaction_tally.zig:7 | `max_emojis_per_message` | 64 | Distinct emojis per message | media.reactions.max_emojis_per_message | uint | 64 | 1..1024 |
| src/daemon/reaction_tally.zig:8 | `max_reactors_per_emoji` | 1024 | Max reactors per (message,emoji) bucket | media.reactions.max_reactors_per_emoji | uint | 1024 | 8..65536 |

## Borderline / wire-adjacent (included per instructions, lift with caution)

| file:line | symbol / context | current value | what it controls | proposed TOML key | type | default | min..max |
|---|---|---|---|---|---|---|---|
| src/proto/sdp_lite.zig:403 (test) | default `Fec.redundancy` seen in round-trips | 12 / 8 | FEC redundancy default carried in SDP-lite offers (no production default exists yet; redundancy is a `u8` field) | media.fec.default_redundancy | uint | 4 | 0..32 |
| src/substrate/red_fec.zig:121 | `max_blocks` in RED decode | 32 | Max RED redundancy blocks parsed per packet (borderline: parser bound, near-wire) | media.fec.max_red_blocks | uint | 32 | 1..64 |
