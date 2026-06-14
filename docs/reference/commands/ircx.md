# IRCX Commands

The IRCX module registers discovery, typed messaging, property, access, event, mode, and list commands (`src/daemon/modules/ircx.zig:47`). `CREATE` lives in [channels.md](channels.md#create).

## IRCX

- Syntax: `IRCX`
- Description: Enables IRCX mode on the session and reports IRCX support. It also works before registration through the special pre-registration path.
- Privileges: Registered client or pre-registration client.
- Parameters: None.
- Replies: `RPL_IRCX 800` with state, version, live SASL package list (`PLAIN,SCRAM-SHA-256,EXTERNAL`), max message size, and option list.
- Errors: None specific.
- Example: `IRCX`
- Sources: `src/daemon/server.zig:3331`, `src/daemon/modules/ircx.zig:48`, `src/daemon/server.zig:7698`

## ISIRCX

- Syntax: `ISIRCX`
- Description: Queries IRCX support without changing the session's IRCX enabled state. It also works before registration.
- Privileges: Registered client or pre-registration client.
- Parameters: None.
- Replies: `RPL_IRCX 800`.
- Errors: None specific.
- Example: `ISIRCX`
- Sources: `src/daemon/server.zig:3335`, `src/daemon/modules/ircx.zig:49`, `src/daemon/server.zig:7698`

## DATA

- Syntax: `DATA <target> <tag> :<message>`
- Description: Sends an IRCX typed message to a nick or channel. Tags must match `[A-Za-z][A-Za-z0-9.]{0,14}`. `SYS`/`ADM` prefixes require oper; `OWN`/`HST` require channel operator/host authority or oper.
- Privileges: Registered client, with reserved tag restrictions.
- Parameters: Target nick/channel, tag, message.
- Replies: Relayed `DATA` line to target(s).
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_BADTAG 904`, `ERR_NOACCESS 913`, `ERR_NOTONCHANNEL 442`, `ERR_NOSUCHNICK 401`.
- Example: `DATA #zig app.status :green`
- Sources: `src/daemon/modules/ircx.zig:50`, `src/daemon/server.zig:7716`

## REQUEST

- Syntax: `REQUEST <target> <tag> :<message>`
- Description: Same handler and validation as `DATA`, but preserves the command verb in the relayed line.
- Privileges: Same as `DATA`.
- Parameters: Same as `DATA`.
- Replies: Relayed `REQUEST` line.
- Errors: Same as `DATA`.
- Example: `REQUEST alice app.ping :hello`
- Sources: `src/daemon/modules/ircx.zig:51`, `src/daemon/server.zig:7721`

## REPLY

- Syntax: `REPLY <target> <tag> :<message>`
- Description: Same handler and validation as `DATA`, but preserves the command verb in the relayed line.
- Privileges: Same as `DATA`.
- Parameters: Same as `DATA`.
- Replies: Relayed `REPLY` line.
- Errors: Same as `DATA`.
- Example: `REPLY alice app.ping :pong`
- Sources: `src/daemon/modules/ircx.zig:52`, `src/daemon/server.zig:7721`

## WHISPER

- Syntax: `WHISPER <#channel> <nick[,nick...]> :<text>`
- Description: Sends a channel-scoped private message to listed recipients only if sender and recipients are on the channel. Channel `+w` nowhisper blocks it.
- Privileges: Registered channel member.
- Parameters: Channel, recipient list, text.
- Replies: `WHISPER` lines to valid recipients.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_NOWHISPER 923`, `ERR_NOSUCHNICK 401`, `ERR_USERNOTINCHANNEL 441`.
- Example: `WHISPER #zig alice,bob :private aside`
- Sources: `src/daemon/modules/ircx.zig:53`, `src/daemon/server.zig:7772`

## PROP

- Syntax: `PROP <entity> [<key[,key...]> [:<value>]]`
- Description: IRCX property list/get/set/delete. One parameter lists all; two gets keys; three sets a value, and an empty trailing value deletes. Built-in channel properties such as `NAME`, `OID`, `CREATION`, `MEMBERCOUNT`, `MEMBERLIMIT`, and write-through `MEMBERKEY`/`MEMBERLIMIT` reflect live channel state.
- Privileges: Registered client; writes require channel operator/owner, user self-ownership, or oper.
- Parameters: Entity, optional key list, optional value.
- Replies: `RPL_PROPLIST 818`, `RPL_PROPEND 819`; mode broadcasts for linked built-ins.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOACCESS 913`, `ERR_BADVALUE 906`.
- Example: `PROP #zig MEMBERCOUNT`
- Sources: `src/daemon/modules/ircx.zig:54`, `src/daemon/server.zig:7610`

## ACCESS

- Syntax: `ACCESS <#channel> <ADD|DELETE|LIST|CLEAR> [level [mask [timeout] [:reason]]]`
- Description: IRCX per-channel access list for levels parsed by the access store. Management requires channel authority or oper.
- Privileges: Registered client with channel management access, or oper.
- Parameters: Parsed by `ircx_access_store.parse`.
- Replies: `RPL_ACCESSADD 801`, `RPL_ACCESSDELETE 802`, `RPL_ACCESSSTART 803`, `RPL_ACCESSENTRY 804`, `RPL_ACCESSEND 805`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NOPRIVILEGES 481`.
- Example: `ACCESS #zig ADD HOST *!*@trusted.example 0 :trusted`
- Sources: `src/daemon/modules/ircx.zig:55`, `src/daemon/server.zig:7419`

## EVENT

- Syntax: `EVENT <ADD|DEL|LIST|BROADCAST|OBSERVE> ...`
- Description: Event Spine control. `ADD`/`DEL` manage the caller's oper event category mask, `LIST` renders subscriptions, `BROADCAST` sends an oper announcement, and `OBSERVE` manages standing operator observation filters. WALLOPS functionality rides `EVENT BROADCAST`; it is not a `+w` user mode path.
- Privileges: Oper checked inside handler.
- Parameters: Subcommand; categories or observe arguments as needed.
- Replies: Raw `EVENT LIST` lines, `NOTE EVENT` observe/broadcast lines, and server notices.
- Errors: `ERR_NOPRIVILEGES 481`, `ERR_NEEDMOREPARAMS 461`.
- Example: `EVENT BROADCAST :network maintenance`
- Sources: `src/daemon/modules/ircx.zig:56`, `src/daemon/server.zig:6543`, `src/daemon/server.zig:6645`

## MODEX

- Syntax: `MODEX <#channel> [named-mode changes...]`
- Description: IRCX named-mode front-end. With no changes, lists active named modes. With changes, translates names to mode letters and delegates to the normal `MODE` engine.
- Privileges: Registered client; actual mutations inherit `MODE` gates.
- Parameters: Channel and optional named mode changes.
- Replies: `RPL_MODEXLIST 806`, `RPL_MODEXEND 807`, or normal `MODE` replies/broadcasts.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, plus delegated `MODE` errors.
- Example: `MODEX #zig +AUTHONLY`
- Sources: `src/daemon/modules/ircx.zig:57`, `src/daemon/server.zig:6470`

## LISTX

- Syntax: `LISTX [filter]`
- Description: IRCX extended channel list. Secret and hidden channels are skipped. Filters use live channel metadata including creation time, topic time, subject/language properties, member count, and registered state; oversized result sets are capped with `RPL_LISTXTRUNC 816`.
- Privileges: Registered client.
- Parameters: Optional LISTX filter.
- Replies: IRCX list start/entry/end numerics `811`, `812`, `817`.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid filters.
- Example: `LISTX >10`
- Sources: `src/daemon/modules/ircx.zig:58`, `src/daemon/server.zig:4836`
