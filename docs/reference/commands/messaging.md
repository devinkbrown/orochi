# Messaging Commands

The messaging module registers `PRIVMSG`, `NOTICE`, `TAGMSG`, `REDACT`, `CHATHISTORY`, `MARKREAD`, `METADATA`, `MONITOR`, and `SILENCE` (`src/daemon/modules/messaging.zig:46`). `ACCEPT` is registered by the user query module (`src/daemon/modules/user_query.zig:82`).

## PRIVMSG

- Syntax: `PRIVMSG <target> :<text>`
- Description: Sends text to a nick, a channel, or a status-prefixed channel target. The handler applies UTF-8/content gates, channel mode gates, `SILENCE`, echo-message, history recording, away replies, and mesh relay.
- Privileges: Registered client.
- Parameters: `target` and non-empty text.
- Replies: Delivery line to recipients; `RPL_AWAY 301` when messaging an away user.
- Errors: `ERR_NOSUCHNICK 401`, `ERR_NOSUCHCHANNEL 403`, `ERR_CANNOTSENDTOCHAN 404`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NEEDREGGEDNICK 477`, `ERR_NEEDMOREPARAMS 461`, IRCv3 `FAIL` for invalid UTF-8 or content filter blocks.
- Example: `PRIVMSG #ops :status?`
- Sources: `src/daemon/modules/messaging.zig:47`, `src/daemon/server.zig:10740`, `src/daemon/server.zig:10919`

## NOTICE

- Syntax: `NOTICE <target> :<text>`
- Description: Same delivery engine as `PRIVMSG`, but delivery-failure numerics are suppressed for `NOTICE` to prevent automatic error loops.
- Privileges: Registered client.
- Parameters: `target` and text.
- Replies: Delivery line to recipients.
- Errors: `ERR_NEEDMOREPARAMS 461`; most delivery errors are intentionally suppressed.
- Example: `NOTICE suzu :heads up`
- Sources: `src/daemon/modules/messaging.zig:48`, `src/daemon/server.zig:10740`, `src/daemon/server.zig:10941`

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
- Description: Emits a message-redaction event for a known message id.
- Privileges: Registered client.
- Parameters: Target, message id, optional reason.
- Replies: Redaction line to target scope.
- Errors: `ERR_NEEDMOREPARAMS 461` for malformed invocation; target errors from handler.
- Example: `REDACT #chat abc123 :cleanup`
- Sources: `src/daemon/modules/messaging.zig:50`, `src/daemon/server.zig:7932`

## CHATHISTORY

- Syntax: `CHATHISTORY <subcommand> <target> ...`
- Description: Reassembles the original line and delegates to the chathistory parser/handler. Used for IRCv3 history playback.
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
- Sources: `src/daemon/modules/messaging.zig:52`, `src/daemon/server.zig:5354`

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
