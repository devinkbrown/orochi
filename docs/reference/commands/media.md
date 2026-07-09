# Media and presence commands

*Per-channel voice, video, and screen-share control plane plus presence updates.*

The `feature.misc` module registers `MEDIA`, which the `media` config flag feature-gates (`src/daemon/modules/feature_misc.zig:52`). The same module registers `ACTIVITY` (`src/daemon/modules/feature_misc.zig:54`).

## MEDIA

- Syntax: `MEDIA <subcommand> <#channel> [args...]`
- Description: Media control plane for per-channel SFU and call state. The implemented subcommands are `ROSTER`, `OFFER`, `ANSWER`, `PROFILE`, `STATS`, `LAYER`, `ABR`, `BREAKOUT`, `POS`, `CAPTION`, `TRANSCRIPT`, `HAND`, `REACT`, `LEAVE`, `JOIN`, `MUTE`, `UNMUTE`, and `SPEAKING`. Media bytes never flow over the IRC control socket; control replies and call-state notifications are `EVENT <target> MEDIA ...` Event Spine lines plus standard failures.
- Privileges: Registered client; caller must be a member of the target channel. The command is unavailable if the `media` feature is disabled.
- Parameters: Subcommand and existing channel. `JOIN`/`MUTE`/`UNMUTE`/`SPEAKING` accept kind `voice`, `video`, or `screen` with `voice` default. `OFFER`/`ANSWER` use codec CSV values `kaguravox`, `kaguravis`, `raw`; either command optionally accepts `transport=webrtc` or `webrtc`. `LAYER` sets the receiver's native simulcast ceiling as `<max_spatial> <max_temporal>`. `ABR` reports receiver bandwidth/loss as `<current_kbps> <available_kbps> <loss_pct> <rtt_ms> [nack_per_sec]`; the daemon applies the Suimyaku ABR hint to the native simulcast ceiling without transcoding. A standards WebRTC peer additionally requests **DTLS-SRTP keying** (RFC 5764/8122) by carrying its own certificate fingerprint as a single token `fingerprint=sha-256:<colon-hex>` (the alg is colon-joined to the hex so it survives IRC tokenization; optionally `setup=active`).
- DTLS-SRTP (`TRANSPORT` keying): when the `[media].dtls_srtp` server option is on **and** the `OFFER` or `ANSWER` carried a well-formed `fingerprint=`, the `TRANSPORT` reply advertises the server's DTLS certificate fingerprint and DTLS role in RFC 8122 form — `fingerprint=sha-256 <colon-hex> setup=passive` (orochi is the DTLS server) — **instead of** the SDES `srtp=<base64 group key>` token. The daemon stores the peer's offered fingerprint keyed by `(channel, participant)`; on DTLS handshake completion the terminator verifies the peer's presented certificate against it and **fails closed on a mismatch** (no SRTP keys are exported, so no media flows). When `[media].dtls_srtp` is off, or the peer carries no `fingerprint=`, the reply uses the legacy SDES form (`srtp=<base64 group key>`). A `fingerprint=` request while DTLS-SRTP is disabled/unavailable is rejected (`FAIL MEDIA DTLS_UNAVAILABLE`) rather than downgraded.
- Replies/events: `EVENT <target> MEDIA ...` lines including `ROSTER`, `ROSTER-END`, `OFFER-ACK`, `ANSWER-ACK`, `PROFILE`, `CAPS`, `KIND-DENIED`, `TRANSPORT`, `NATIVE`, `STATS`, `STATS-END`, `LAYER`, `ABR`, `BREAKOUT`, `POS`, `CAPTION`, `TRANSCRIPT`, `TRANSCRIPT-END`, `HAND`, `REACT`, `JOIN`, `LEAVE`, `MUTE`, `UNMUTE`, and `SPEAKING`/`SILENT`. `CAPS` publishes each participant's advertised codec/FEC set as `codecs=<csv> fec=<scheme>` after a successful `OFFER` or `ANSWER`; `KIND-DENIED` is a caller-targeted reply (`kind=<voice|video> reason=no_common_codec`) when an advertised media kind cannot join the negotiated transcode-free codec set; `ABR` is a caller-targeted reply such as `action=decrease bitrate=320 fec=2 keyframe=true spatial<=0 temporal<=0`; `ROSTER` includes capability fields for participants whose capabilities are known. `TRANSPORT` carries either `srtp=<base64>` (legacy SDES) or `fingerprint=sha-256 <colon-hex> setup=passive` (DTLS-SRTP), never both. Participant-specific secrets (`TRANSPORT`, `NATIVE`, `MACKEY`) are targeted Event Spine replies to the requesting client, not broadcast to every subscriber.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_UNKNOWNCOMMAND 421` if feature-disabled by registry, IRCv3 `FAIL MEDIA` codes including `NO_OFFER`, `NOT_IN_CALL`, `BAD_LAYER`, `BAD_ABR`, `BREAKOUT_FAILED`, `INVALID_POSITION`, `POS_FAILED`, `INVALID_REACTION`, `INVALID_KIND`, `JOIN_FAILED`, `NOT_PUBLISHING`, `INVALID_SUBCOMMAND`, `NO_CODECS`, `NEGOTIATE_FAILED`, `NO_COMMON_CODEC`, `BAD_FINGERPRINT` (malformed `fingerprint=` token), `DTLS_UNAVAILABLE` (DTLS keying requested but not enabled/available).
- Example: `MEDIA JOIN #zig voice`
- Offer/answer transport: successful `OFFER` replies with `OFFER-ACK`, then provisions the caller's `TRANSPORT` and `NATIVE` legs. Successful `ANSWER` replies with `ANSWER-ACK`, then provisions the answerer's `TRANSPORT` and `NATIVE` legs against the active call profile.
- DTLS example: `MEDIA OFFER #zig kaguravox transport=webrtc fingerprint=sha-256:3C:57:42:...:BA setup=active` -> `:server EVENT nick MEDIA TRANSPORT #zig ufrag=... pwd=... candidate=203.0.113.5:38405 fingerprint=sha-256 9F:...:1D setup=passive`
- ABR example: `MEDIA ABR #zig 1200 400 10 60 25` -> `:server EVENT nick MEDIA ABR #zig action=decrease bitrate=320 fec=2 keyframe=true spatial<=0 temporal<=0`
- Sources: `src/daemon/modules/feature_misc.zig:52`, `src/daemon/server.zig:9111`, `src/daemon/server.zig:9436`, `src/daemon/server.zig:9556`, `src/daemon/server.zig:9584`

## ACTIVITY

- Syntax: `ACTIVITY <target> <state> [text]`
- Description: Presence/activity update surface. The handler applies target parsing and broadcasts activity state to the relevant recipients.
- Privileges: Registered client.
- Parameters: Target, state, optional text as parsed by handler.
- Replies: Activity notification lines.
- Errors: Handler-specific target/parameter failures.
- Example: `ACTIVITY #zig coding :docs`
- Sources: `src/daemon/modules/feature_misc.zig:54`, `src/daemon/server.zig:10619`
