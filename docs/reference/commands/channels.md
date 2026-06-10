# Channel Commands

The channel command module registers the base membership and moderation commands (`src/daemon/modules/channel_ops.zig:51`). Extended service commands for channel administration are registered in `services.ext` (`src/daemon/modules/services_ext.zig:47`).

## JOIN

- Syntax: `JOIN <#chan[,#chan...]> [key[,key...]]`
- Description: Joins channels from positional comma lists. `joinOne` enforces channel name length, `CHANLIMIT`, Warden quarantine, TLS/account/invite/key/bans, join throttle, limit forwarding, IRCX tier keys, automatic topic/NAMES, bouncer rewind, and mesh membership propagation.
- Privileges: Registered client.
- Parameters: Channel list; optional key list.
- Replies: `JOIN` broadcast, `RPL_TOPIC 332` or `RPL_NOTOPIC 331`, `RPL_NAMREPLY 353`, `RPL_ENDOFNAMES 366`; may emit `ERR_LINKCHANNEL 470` for forward.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_TOOMANYCHANNELS 405`, `ERR_BANNEDFROMCHAN 474`, `ERR_SECUREONLYCHAN 489`, `ERR_NEEDREGGEDNICK 477`, `ERR_INVITEONLYCHAN 473`, `ERR_BADCHANNELKEY 475`, `ERR_THROTTLE 480`, `ERR_CHANNELISFULL 471`, `ERR_UNAVAILRESOURCE 437`.
- Example: `JOIN #zig,#ops hunter2,`
- Sources: `src/daemon/modules/channel_ops.zig:52`, `src/daemon/server.zig:3852`, `src/daemon/server.zig:3892`

## PART

- Syntax: `PART <#chan[,#chan...]> [:reason]`
- Description: Parts comma-separated channels with a shared optional reason, broadcasts `PART`, removes membership, and announces membership removal to mesh peers.
- Privileges: Registered client.
- Parameters: Channel list; optional reason.
- Replies: `PART` broadcast.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`.
- Example: `PART #zig :later`
- Sources: `src/daemon/modules/channel_ops.zig:53`, `src/daemon/server.zig:4009`

## NAMES

- Syntax: `NAMES <#channel>`
- Description: Emits the current channel names list.
- Privileges: Registered client.
- Parameters: Channel name.
- Replies: `RPL_NAMREPLY 353`, `RPL_ENDOFNAMES 366`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`.
- Example: `NAMES #zig`
- Sources: `src/daemon/modules/channel_ops.zig:54`, `src/daemon/server.zig:4060`

## MODE

- Syntax: `MODE <#channel|nick|ISIRCX> [modes [args...]]`
- Description: Channel mode query/set, own user-mode query/set, IRCX `MODE ISIRCX` discovery, and oper-only user `+z` gag control. Channel mode query returns mode letters and hides `+k/+l` values from non-members. Channel setting supports member tiers, list modes, boolean flags, key/limit, throttle, forward, and IRCX extension flags.
- Privileges: Registered client; channel mutations require channel privilege; some extension flags and user `+z` require oper.
- Parameters: Target plus optional mode string and arguments.
- Replies: `RPL_CHANNELMODEIS 324`, `RPL_UMODEIS 221`, list numerics (`367/368`, `346/347`, `348/349`, `728/729`), `RPL_IRCX 800`, or `MODE` broadcasts.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NOSUCHNICK 401`, `ERR_USERNOTINCHANNEL 441`, `ERR_USERSDONTMATCH 502`, `ERR_BANLISTFULL 478`, `ERR_NOPRIVILEGES 481`.
- Example: `MODE #zig +nt`
- Sources: `src/daemon/modules/channel_ops.zig:55`, `src/daemon/server.zig:4139`, `src/daemon/server.zig:4534`

## KICK

- Syntax: `KICK <#channel> <nick> [:reason]`
- Description: Removes a channel member. Kicker must be operator-or-higher and cannot kick a higher-ranked member unless server-oper.
- Privileges: Registered channel member with operator rank or server oper.
- Parameters: Channel, target nick, optional reason truncated to configured `KICKLEN`.
- Replies: `KICK` broadcast before removal.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_USERNOTINCHANNEL 441`.
- Example: `KICK #zig badnick :rules`
- Sources: `src/daemon/modules/channel_ops.zig:56`, `src/daemon/server.zig:4581`

## INVITE

- Syntax: `INVITE <nick> <#channel>`
- Description: Invites a nick. Existing `+i` channels require channel operator unless the caller is server oper.
- Privileges: Registered client; channel operator for invite-only channels.
- Parameters: Nick and channel.
- Replies: `RPL_INVITING 341` to inviter and `INVITE` line to target.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_USERONCHANNEL 443`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_NOSUCHNICK 401`.
- Example: `INVITE alice #zig`
- Sources: `src/daemon/modules/channel_ops.zig:57`, `src/daemon/server.zig:4959`

## TOPIC

- Syntax: `TOPIC <#channel> [:topic]`
- Description: With one parameter, returns current topic or no-topic. With topic text, sets and broadcasts it; `+t` requires operator status. Text is UTF-8 boundary truncated to configured `TOPICLEN`.
- Privileges: Registered client; setter must be on channel and satisfy `+t` gate.
- Parameters: Channel; optional topic.
- Replies: `RPL_TOPIC 332`, `RPL_NOTOPIC 331`, or `TOPIC` broadcast.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`.
- Example: `TOPIC #zig :Orochi development`
- Sources: `src/daemon/modules/channel_ops.zig:58`, `src/daemon/server.zig:11168`, `src/daemon/server.zig:11231`

## KNOCK

- Syntax: `KNOCK <#channel> [:reason]`
- Description: Sends a knock request to channel operators. Refused if the channel does not exist, caller is already on it, or the channel is open.
- Privileges: Registered client.
- Parameters: Channel and optional reason.
- Replies: `RPL_KNOCK 710` to operators and `RPL_KNOCKDLVR 711` to caller.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_KNOCKONCHAN 714`, `ERR_CHANOPEN 713`.
- Example: `KNOCK #private :please`
- Sources: `src/daemon/modules/channel_ops.zig:59`, `src/daemon/server.zig:5151`

## CREATE

- Syntax: `CREATE <#channel> [modes]`
- Description: IRCX create-or-join. Non-opers delegate to normal `JOIN`; an oper creating an existing channel takes founder status without evicting members and purges stale IRCX state.
- Privileges: Registered client; oper gets takeover behavior.
- Parameters: Channel and optional modes parsed by the IRCX create parser.
- Replies: Same as `JOIN` or takeover messages.
- Errors: `ERR_NEEDMOREPARAMS 461` for invalid create syntax; join errors from `JOIN`.
- Example: `CREATE #new`
- Sources: `src/daemon/modules/channel_ops.zig:60`, `src/daemon/server.zig:7820`

## RENAME

- Syntax: `RENAME <old-channel> <new-channel> [:reason]`
- Description: Renames a channel when the caller is on it and has operator authority.
- Privileges: Registered channel operator.
- Parameters: Old channel, new channel, optional reason.
- Replies: Rename notification/broadcast from handler.
- Errors: `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`, parser errors as `ERR_NEEDMOREPARAMS 461`.
- Example: `RENAME #old #new :new name`
- Sources: `src/daemon/modules/channel_ops.zig:61`, `src/daemon/server.zig:5195`

## AKICK

- Syntax: `AKICK <#channel> <ADD|DEL|LIST> [mask] [:reason]`
- Description: Real server command for registered-channel auto-kick lists. Matching masks are denied at join.
- Privileges: Registered client; channel operator or oper required inside handler.
- Parameters: Channel, subcommand, optional mask/reason.
- Replies: Server `NOTICE` list/add/delete responses.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_CHANOPRIVSNEEDED 482`.
- Example: `AKICK #zig ADD *!*@bad.example :spam`
- Sources: `src/daemon/modules/services_ext.zig:47`, `src/daemon/server.zig:6718`

## CLEAR

- Syntax: `CLEAR <#channel> USERS [KEEP <rank>] [ALLOW <acct[,acct]>] [:reason]`
- Description: Mass-kicks members below a keep rank, except allowed accounts. Requires founder rank or server oper.
- Privileges: Registered client; channel founder or oper.
- Parameters: Parsed by the mass-kick parser from reassembled command text.
- Replies: `KICK` broadcasts plus final server `NOTICE` count.
- Errors: `ERR_NOSUCHCHANNEL 403`, `ERR_NOTONCHANNEL 442`, `ERR_CHANOPRIVSNEEDED 482`; parser errors are sent as server notices.
- Example: `CLEAR #zig USERS KEEP op :reset`
- Sources: `src/daemon/modules/services_ext.zig:55`, `src/daemon/server.zig:7035`

## TEMPMODE

- Syntax: `TEMPMODE ADD <#chan> <flag> [param] <duration> | TEMPMODE CANCEL <#chan> <flag> [param] | TEMPMODE SWEEP`
- Description: Adds a boolean channel mode now and schedules an automatic revert, cancels scheduled reverts, or lets an oper sweep due reverts.
- Privileges: Registered client; channel operator or oper for add/cancel; oper for `SWEEP`.
- Parameters: Subcommand-specific channel, mode flag, optional parameter, duration.
- Replies: `MODE` broadcast for adds; server `NOTICE` for cancel/sweep.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHCHANNEL 403`, `ERR_CHANOPRIVSNEEDED 482`, `ERR_UNKNOWNMODE 472`, `ERR_NOPRIVILEGES 481`.
- Example: `TEMPMODE ADD #zig m 60000`
- Sources: `src/daemon/modules/services_ext.zig:56`, `src/daemon/server.zig:7120`
