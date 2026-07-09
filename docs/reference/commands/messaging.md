# Messaging commands

*Text delivery, tag-only messages, redaction, history playback, metadata, and caller-side filtering.*

The messaging module registers `PRIVMSG`, `NOTICE`, `TAGMSG`, `REDACT`, `CHATHISTORY`, `MARKREAD`, `PINS`, `METADATA`, `MONITOR`, and `SILENCE` (`src/daemon/modules/messaging.zig:59`). `ACCEPT` is registered by the user query module (`src/daemon/modules/user_query.zig:82`).

## PRIVMSG

- Syntax: `PRIVMSG <target> :<text>`
- Description: Sends text to a nick, a channel, or a status-prefixed channel target. The handler applies UTF-8 and content gates, channel mode gates, `SILENCE`, echo-message, history recording, away replies, mesh relay, and the caller's `MAXTARGETS` fan-out cap. A connection class can tighten that cap with `max_targets`.
- Privileges: Registered client.
- Parameters: `target` and non-empty text.
- Replies: Delivery line to recipients; `RPL_AWAY 301` when messaging an away user.
- Errors: `ERR_NOSUCHNICK 401`, `ERR_NOSUCHCHANNEL 403`, `ERR_CANNOTSENDTOCHAN 404`, `ERR_TOOMANYTARGETS 407`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NEEDREGGEDNICK 477`, `ERR_NEEDMOREPARAMS 461`, IRCv3 `FAIL` for invalid UTF-8 or content filter blocks.
- Example: `PRIVMSG #ops :status?`
- Sources: `src/daemon/modules/messaging.zig:47`, `src/daemon/server.zig:20164`, `src/daemon/server.zig:20169`

## NOTICE

- Syntax: `NOTICE <target> :<text>`
- Description: Uses the same delivery engine as `PRIVMSG`, including the caller's `MAXTARGETS` fan-out cap and any tighter per-class `max_targets` cap. Delivery-failure numerics are suppressed for `NOTICE` to prevent automatic error loops.
- Privileges: Registered client.
- Parameters: `target` and text.
- Replies: Delivery line to recipients.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_TOOMANYTARGETS 407` for the fan-out cap; most delivery errors are intentionally suppressed.
- Example: `NOTICE suzu :heads up`
- Sources: `src/daemon/modules/messaging.zig:48`, `src/daemon/server.zig:20164`, `src/daemon/server.zig:20169`

## CTCP and DCC

- CTCP payloads are parsed for normal message policy, automatic replies, and `+C` no-CTCP enforcement.
- DCC is intentionally parser-only in Orochi: the server provides no DCC proxy, filehost, or relay behavior, and clients must not assume a server-mediated DCC surface.
- Sources: `src/proto/ctcp.zig`, `src/daemon/server.zig`

## TAGMSG

- Syntax: `TAGMSG <target>`
- Description: Sends an IRCv3 tag-only message to a nick or channel using the normal target checks.
- Privileges: Registered client.
- Parameters: `target` is required.
- Replies: Raw `TAGMSG` to recipients.
- Errors: `ERR_NEEDMOREPARAMS 461`, target/channel errors from the handler.
- Example: `@+typing=active TAGMSG #chat`
- Sources: `src/daemon/modules/messaging.zig:49`, `src/daemon/server.zig:10576`

## REDACT

- Syntax: `REDACT <target> <msgid> [:reason]`
- Description: Emits a message-redaction event for a known message id. When the daemon has a signing identity, the successful redaction is recorded in the ProofMark audit ring and the redaction reason carries `proof=<id>`.
- Privileges: Registered client.
- Parameters: Target, message id, optional reason.
- Replies: Redaction line to target scope; signed redactions include `proof=<id>` in the trailing reason.
- Errors: `ERR_NEEDMOREPARAMS 461` for malformed invocation; target errors from handler.
- Example: `REDACT #chat abc123 :cleanup`
- Sources: `src/daemon/modules/messaging.zig:50`, `src/daemon/server.zig:7932`

## CHATHISTORY

- Syntax: `CHATHISTORY <subcommand> <target> ...`
- Description: Reassembles the original line and delegates to the chathistory parser/handler. Used for IRCv3 history playback over the live Lotus ring; retained messages carry BLAKE3 content hashes, edits update the stored content address before replay, `history-policy` channel PROP values can tighten replay visibility, and the node status feed publishes a deterministic Lotus root that changes on edits and redaction tombstones.
- Privileges: Registered client.
- Parameters: Parsed by the chathistory subsystem from the raw line.
- Replies: History batches and standard batch framing.
- Errors: Parser/handler failures surface as command-specific failure replies.
- Example: `CHATHISTORY LATEST #chat * 20`
- Sources: `src/daemon/modules/messaging.zig:51`, `src/daemon/server.zig:5491`

## MARKREAD

- Syntax: `MARKREAD <target> <timestamp|msgid>`
- Description: Updates the caller's bouncer read marker for a target.
- Privileges: Registered client.
- Parameters: Parsed marker arguments.
- Replies: No numeric success reply.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid parameters.
- Example: `MARKREAD #chat 2026-06-10T12:00:00Z`
- Sources: `src/daemon/modules/messaging.zig:69`, `src/daemon/server.zig:14155`

## PINS

- Syntax: `PINS <#channel> [LIST|ADD <msgid>|DEL <msgid>|CLEAR]`
- Description: Lists or edits the channel's pinned message ids through the live `PINS` channel PROP. The command uses the same validation, signed channel-prop storage, local IRCX PROP notification, and mesh propagation path as `PROP <#channel> PINS :...`.
- Privileges: Channel member or operator may list; channel operator or network operator may add, delete, or clear.
- Parameters: Channel; optional subcommand and message id.
- Replies: `:<server> PINS <#channel> :<comma-separated-msgids>` with an empty trailing value when no pins remain.
- Errors: `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_BADVALUE 906`, `ERR_NEEDMOREPARAMS 461`, IRCv3 `FAIL PINS INVALID_SUBCOMMAND`.
- Example: `PINS #chat ADD 01HMSGID`
- Sources: `src/daemon/modules/messaging.zig:70`, `src/daemon/server.zig:14234`

## METADATA

- Syntax: `METADATA <target> <subcommand> [key] [value]`
- Description: Implements IRCv3 metadata operations over the live metadata store.
- Privileges: Registered client.
- Parameters: Target, subcommand, and optional key/value as parsed by the handler.
- Replies: `RPL_KEYVALUE 761`, `RPL_METADATAEND 762` when listing/querying.
- Errors: `ERR_KEYNOTSET 766`, `ERR_KEYINVALID 767`, `ERR_KEYNOPERMISSION 769`, `ERR_NEEDMOREPARAMS 461`.
- Example: `METADATA * LIST`
- Sources: `src/daemon/modules/messaging.zig:53`, `src/daemon/server.zig:7875`

## MONITOR

- Syntax: `MONITOR <+|-|C|L|S> [nick[,nick]...]`
- Description: Manages the caller's monitor set and emits online/offline/list numerics.
- Privileges: Registered client.
- Parameters: Parsed monitor operation and optional nick list.
- Replies: `RPL_MONONLINE 730`, `RPL_MONOFFLINE 731`, `RPL_MONLIST 732`, `RPL_ENDOFMONLIST 733`.
- Errors: `ERR_MONLISTFULL 734`, `ERR_NEEDMOREPARAMS 461`.
- Example: `MONITOR + alice,bob`
- Sources: `src/daemon/modules/messaging.zig:54`, `src/daemon/server.zig:5262`

## SILENCE

- Syntax: `SILENCE [<mask>|+<mask>|-<mask>]`
- Description: Lists, adds, or removes sender masks in the caller's silence list. Incoming private messages from matching masks are silently dropped.
- Privileges: Registered client.
- Parameters: Bare command lists; `+mask` adds; `-mask` removes.
- Replies: `RPL_SILELIST 271`, `RPL_ENDOFSILELIST 272`.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid masks.
- Example: `SILENCE +*!*@bad.example`
- Sources: `src/daemon/modules/messaging.zig:55`, `src/daemon/server.zig:5384`, `src/daemon/server.zig:11145`

## ACCEPT

- Syntax: `ACCEPT [+nick|-nick|*|...]`
- Description: Manages the caller-id allow list keyed by the caller's nick. Bare command or `*` lists entries.
- Privileges: Registered client.
- Parameters: One or more add/remove/list tokens.
- Replies: `RPL_ACCEPTLIST 281`, `RPL_ENDOFACCEPT 282`.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid input.
- Example: `ACCEPT +alice -mallory`
- Sources: `src/daemon/modules/user_query.zig:82`, `src/daemon/server.zig:6005`
