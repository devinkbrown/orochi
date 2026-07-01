# Media and presence commands

*Per-channel voice, video, and screen-share control plane plus presence updates.*

The `feature.misc` module registers `MEDIA`, which the `media` config flag feature-gates (`src/daemon/modules/feature_misc.zig:52`). The same module registers `ACTIVITY` (`src/daemon/modules/feature_misc.zig:54`).

## MEDIA

- Syntax: `MEDIA <subcommand> <#channel> [args...]`
- Description: Media control plane for per-channel SFU and call state. The implemented subcommands are `ROSTER`, `OFFER`, `ANSWER`, `PROFILE`, `STATS`, `LAYER`, `BREAKOUT`, `POS`, `CAPTION`, `TRANSCRIPT`, `HAND`, `REACT`, `LEAVE`, `JOIN`, `MUTE`, `UNMUTE`, and `SPEAKING`. Media bytes never flow over the IRC control socket; replies are `NOTE MEDIA` lines and standard failures.
- Privileges: Registered client; caller must be a member of the target channel. The command is unavailable if the `media` feature is disabled.
- Parameters: Subcommand and existing channel. `JOIN`/`MUTE`/`UNMUTE`/`SPEAKING` accept kind `voice`, `video`, or `screen` with `voice` default. `OFFER`/`ANSWER` use codec CSV values `kaguravox`, `kaguravis`, `raw`; `OFFER` optionally accepts `transport=webrtc` or `webrtc`.
- Replies: `NOTE MEDIA` lines including `ROSTER`, `OFFER-ACK`, `ANSWER-ACK`, `PROFILE`, `TRANSPORT`, `NATIVE`, `STATS`, `LAYER`, `BREAKOUT`, `POS`, `CAPTION`, `TRANSCRIPT`, `HAND`, `REACT`, `JOIN`, `LEAVE`, `MUTE`, `UNMUTE`, `SPEAKING`/`SILENT`, or end lines.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_UNKNOWNCOMMAND 421` if feature-disabled by registry, IRCv3 `FAIL MEDIA` codes including `NO_OFFER`, `NOT_IN_CALL`, `BAD_LAYER`, `BREAKOUT_FAILED`, `INVALID_POSITION`, `POS_FAILED`, `INVALID_REACTION`, `INVALID_KIND`, `JOIN_FAILED`, `NOT_PUBLISHING`, `INVALID_SUBCOMMAND`, `NO_CODECS`, `NEGOTIATE_FAILED`, `NO_COMMON_CODEC`.
- Example: `MEDIA JOIN #zig voice`
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
