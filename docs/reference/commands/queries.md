# User query commands

*Presence, identity, and channel lookups, plus away state, realname changes, and built-in help.*

These commands are registered by `user.query` (`src/daemon/modules/user_query.zig:71`), along with disabled and heartbeat helpers from `feature.misc` (`src/daemon/modules/feature_misc.zig:56`).

## ISON

- Syntax: `ISON <nick>...`
- Description: Returns the subset of requested nicks that are online.
- Privileges: Registered client.
- Parameters: One or more nick tokens; the handler accepts an empty list and returns an empty result.
- Replies: `RPL_ISON 303`.
- Errors: Registry `ERR_NEEDMOREPARAMS 461` is not configured for this command; handler has no command-specific errors.
- Example: `ISON alice bob carol`
- Sources: `src/daemon/modules/user_query.zig:72`, `src/daemon/server.zig:4622`

## USERHOST

- Syntax: `USERHOST <nick>...`
- Description: Returns up to five live userhost entries, including target oper and away state.
- Privileges: Registered client.
- Parameters: Nick list.
- Replies: `RPL_USERHOST 302`.
- Errors: None specific in handler.
- Example: `USERHOST alice bob`
- Sources: `src/daemon/modules/user_query.zig:73`, `src/daemon/server.zig:4640`

## WHOIS

- Syntax: `WHOIS [server] <nick>`
- Description: Emits a local WHOIS sequence covering account, away state, channels, oper and admin visibility, bot mode, certificate fingerprint, TLS status, actual host (for opers and self), and optional GeoIP text (for opers and self).
- Privileges: Registered client.
- Parameters: Target nick is the last parameter.
- Replies: `RPL_WHOISUSER 311`, `RPL_WHOISSERVER 312`, `RPL_WHOISOPERATOR 313`, `RPL_WHOISIDLE 317`, `RPL_ENDOFWHOIS 318`, `RPL_WHOISCHANNELS 319`, `RPL_WHOISSPECIAL 320`, `RPL_WHOISLOGGEDIN 330`, `RPL_WHOISCERTFP 276`, `RPL_WHOISSECURE 671`, `RPL_WHOISACTUALLY 338`, plus other WHOIS numerics produced by the writer.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHNICK 401`.
- Example: `WHOIS alice`
- Sources: `src/daemon/modules/user_query.zig:74`, `src/daemon/server.zig:4863`

## LIST

- Syntax: `LIST [filters...]`
- Description: Lists non-secret, non-hidden channels. ELIST-style filters are parsed; malformed filters fall back to listing all visible channels.
- Privileges: Registered client.
- Parameters: Optional list filters.
- Replies: `RPL_LISTSTART 321`, `RPL_LIST 322`, `RPL_LISTEND 323`.
- Errors: None specific in handler.
- Example: `LIST >10`
- Sources: `src/daemon/modules/user_query.zig:75`, `src/daemon/server.zig:4810`

## WHO

- Syntax: `WHO <channel|nick> [%fields[,token]]`; `WHOX <channel|nick> %fields[,token]`
- Description: Plain WHO emits channel or nick rows. When the second parameter starts with `%` and parses as WHOX, the handler emits WHOX rows instead. `WHOX` is a command-name alias for clients that send the extended form directly.
- Privileges: Registered client.
- Parameters: Target; optional WHOX selector.
- Replies: Plain `RPL_WHOREPLY 352` and `RPL_ENDOFWHO 315`; WHOX `RPL_WHOSPCRPL 354` and `RPL_ENDOFWHO 315`.
- Errors: `ERR_NEEDMOREPARAMS 461`.
- Example: `WHOX #zig %tcuhsnfar`
- Sources: `src/daemon/modules/user_query.zig:76`, `src/daemon/server.zig:4741`, `src/daemon/server.zig:4663`

## WHOWAS

- Syntax: `WHOWAS <nick>`
- Description: Looks up the recorded WHOWAS snapshot for a nick.
- Privileges: Registered client.
- Parameters: Nick.
- Replies: `RPL_WHOWASUSER 314`, `RPL_WHOWASREAL 360`, `RPL_ENDOFWHOWAS 369` when data exists.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_WASNOSUCHNICK 406`.
- Example: `WHOWAS alice`
- Sources: `src/daemon/modules/user_query.zig:77`, `src/daemon/server.zig:5120`

## AWAY

- Syntax: `AWAY [:message]`
- Description: Sets or clears the caller's away message. It is accepted before registration only when the `pre-away` capability is present.
- Privileges: Registered client, or pre-registration client with `pre-away`.
- Parameters: Optional away message; no parameter clears away.
- Replies: `RPL_NOWAWAY 306`, `RPL_UNAWAY 305`; away-notify fanout to capable peers.
- Errors: None specific in handler.
- Example: `AWAY :lunch`
- Sources: `src/daemon/server.zig:3349`, `src/daemon/modules/user_query.zig:78`, `src/daemon/server.zig:8249`

## SETNAME

- Syntax: `SETNAME :<realname>`
- Description: Changes the caller's realname and notifies common-channel peers with the relevant capability.
- Privileges: Registered client.
- Parameters: New realname.
- Replies: SETNAME/chghost-style notification to capable peers; no numeric success reply.
- Errors: Handler validation errors only.
- Example: `SETNAME :Kain`
- Sources: `src/daemon/modules/user_query.zig:79`, `src/daemon/server.zig:8278`

## HELP

- Syntax: `HELP [topic]`
- Description: Returns built-in help for a topic, or general help if no topic is supplied.
- Privileges: Registered client.
- Parameters: Optional topic.
- Replies: Server `NOTICE` help lines.
- Errors: `ERR_HELPNOTFOUND 524` when no topic exists.
- Example: `HELP WARD`
- Sources: `src/daemon/modules/user_query.zig:83`, `src/daemon/server.zig:7961`

## HELPOP

- Syntax: `HELPOP [topic]`
- Description: Alias of `HELP`; registered separately but dispatched to the same handler.
- Privileges: Registered client.
- Parameters: Optional topic.
- Replies: Same as `HELP`.
- Errors: Same as `HELP`.
- Example: `HELPOP OPER`
- Sources: `src/daemon/modules/user_query.zig:84`, `src/daemon/server.zig:7961`

## AUTOJOIN

- Syntax: `AUTOJOIN <LIST|ADD|DEL|CLEAR> [#channel]`
- Description: Manages the logged-in account's autojoin list, which the daemon applies after account login.
- Privileges: Registered client; account login required inside handler.
- Parameters: Subcommand and optional channel.
- Replies: Server `NOTICE` responses.
- Errors: Account-required and parser failures as notices or failure replies.
- Example: `AUTOJOIN ADD #zig`
- Sources: `src/daemon/modules/user_query.zig:85`, `src/daemon/server.zig:5627`, `src/daemon/server.zig:8513`

## GROUP

- Syntax: `GROUP ...`
- Description: Account-grouping command surface. The handler delegates to the group implementation and emits its responses.
- Privileges: Registered client.
- Parameters: Parsed by handler.
- Replies: Server `NOTICE` or failure replies from handler.
- Errors: Handler-specific validation failures.
- Example: `GROUP LIST`
- Sources: `src/daemon/modules/user_query.zig:86`, `src/daemon/server.zig:5668`

## WELCOME

- Syntax: `WELCOME [topic]`
- Description: Sends welcome/onboarding text to the caller.
- Privileges: Registered client.
- Parameters: Optional handler-specific selector.
- Replies: Server notices/welcome text.
- Errors: Handler-specific validation failures.
- Example: `WELCOME`
- Sources: `src/daemon/modules/user_query.zig:87`, `src/daemon/server.zig:5738`

## SUMMON

- Syntax: `SUMMON <nick> <#channel>`
- Description: Oper-only force-join. Orochi repurposes the obsolete host-paging
  command as a direct operator command that resolves the target user, runs the
  same join path as `FORCEJOIN`, and returns `RPL_SUMMONING 342`.
- Privileges: Operator.
- Parameters: Target nick and channel name.
- Replies: `RPL_SUMMONING 342`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOSUCHNICK 401`, join validation errors.
- Example: `SUMMON alice #ops`
- Sources: `src/daemon/modules/feature_misc.zig:36`, `src/daemon/server.zig` `handleSummon`
