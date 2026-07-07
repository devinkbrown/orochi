# Media and presence commands

*Per-channel voice, video, and screen-share control plane plus presence updates.*

The `feature.misc` module registers `MEDIA`, which the `media` config flag feature-gates (`src/daemon/modules/feature_misc.zig:52`). The same module registers `ACTIVITY` (`src/daemon/modules/feature_misc.zig:54`).

## MEDIA

- Syntax: `MEDIA <subcommand> <#channel> [args...]`
- Description: Media control plane for per-channel SFU and call state. The implemented subcommands are `ROSTER`, `OFFER`, `ANSWER`, `PROFILE`, `STATS`, `LAYER`, `BREAKOUT`, `POS`, `CAPTION`, `TRANSCRIPT`, `HAND`, `REACT`, `LEAVE`, `JOIN`, `MUTE`, `UNMUTE`, and `SPEAKING`. Media bytes never flow over the IRC control socket; replies are `NOTE MEDIA` lines and standard failures.
- Privileges: Registered client; caller must be a member of the target channel. The command is unavailable if the `media` feature is disabled.
- Parameters: Subcommand and existing channel. `JOIN`/`MUTE`/`UNMUTE`/`SPEAKING` accept kind `voice`, `video`, or `screen` with `voice` default. `OFFER`/`ANSWER` use codec CSV values `kaguravox`, `kaguravis`, `raw`; `OFFER` optionally accepts `transport=webrtc` or `webrtc`. A standards WebRTC peer additionally requests **DTLS-SRTP keying** (RFC 5764/8122) by carrying its own certificate fingerprint as a single token `fingerprint=sha-256:<colon-hex>` (the alg is colon-joined to the hex so it survives IRC tokenization; optionally `setup=active`). `ANSWER` accepts the same `fingerprint=` token.
- DTLS-SRTP (`TRANSPORT` keying): when the `[media].dtls_srtp` server option is on **and** the `OFFER` carried a well-formed `fingerprint=`, the `TRANSPORT` reply advertises the server's DTLS certificate fingerprint and DTLS role in RFC 8122 form — `fingerprint=sha-256 <colon-hex> setup=passive` (orochi is the DTLS server) — **instead of** the SDES `srtp=<base64 group key>` token. The daemon stores the peer's offered fingerprint keyed by `(channel, participant)`; on DTLS handshake completion the terminator verifies the peer's presented certificate against it and **fails closed on a mismatch** (no SRTP keys are exported, so no media flows). When `[media].dtls_srtp` is off, or the `OFFER` carries no `fingerprint=`, the reply is byte-identical to the legacy SDES form (`srtp=<base64 group key>`). A `fingerprint=` request while DTLS-SRTP is disabled/unavailable is rejected (`FAIL MEDIA DTLS_UNAVAILABLE`) rather than downgraded.
- Replies: `NOTE MEDIA` lines including `ROSTER`, `OFFER-ACK`, `ANSWER-ACK`, `PROFILE`, `TRANSPORT`, `NATIVE`, `STATS`, `LAYER`, `BREAKOUT`, `POS`, `CAPTION`, `TRANSCRIPT`, `HAND`, `REACT`, `JOIN`, `LEAVE`, `MUTE`, `UNMUTE`, `SPEAKING`/`SILENT`, or end lines. `TRANSPORT` carries either `srtp=<base64>` (legacy SDES) or `fingerprint=sha-256 <colon-hex> setup=passive` (DTLS-SRTP), never both.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_UNKNOWNCOMMAND 421` if feature-disabled by registry, IRCv3 `FAIL MEDIA` codes including `NO_OFFER`, `NOT_IN_CALL`, `BAD_LAYER`, `BREAKOUT_FAILED`, `INVALID_POSITION`, `POS_FAILED`, `INVALID_REACTION`, `INVALID_KIND`, `JOIN_FAILED`, `NOT_PUBLISHING`, `INVALID_SUBCOMMAND`, `NO_CODECS`, `NEGOTIATE_FAILED`, `NO_COMMON_CODEC`, `BAD_FINGERPRINT` (malformed `fingerprint=` token), `DTLS_UNAVAILABLE` (DTLS keying requested but not enabled/available).
- Example: `MEDIA JOIN #zig voice`
- DTLS example: `MEDIA OFFER #zig kaguravox transport=webrtc fingerprint=sha-256:3C:57:42:...:BA setup=active` → `:server NOTE MEDIA #zig TRANSPORT ufrag=… pwd=… candidate=203.0.113.5:38405 fingerprint=sha-256 9F:...:1D setup=passive`
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
