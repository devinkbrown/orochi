# Informational Commands

Stateless server information commands are registered by `query.info` (`src/daemon/modules/query_info.zig:60`). Registry introspection is provided by `diag.introspect` (`src/daemon/modules/introspect.zig:95`).

## VERSION

- Syntax: `VERSION`
- Description: Returns the current daemon version text.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_VERSION 351`.
- Errors: None specific.
- Example: `VERSION`
- Sources: `src/daemon/modules/query_info.zig:61`, `src/daemon/server.zig:8088`

## TIME

- Syntax: `TIME`
- Description: Returns the server wall-clock time formatted by the daemon.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_TIME 391`.
- Errors: None specific.
- Example: `TIME`
- Sources: `src/daemon/modules/query_info.zig:62`, `src/daemon/server.zig:8065`

## ADMIN

- Syntax: `ADMIN`
- Description: Returns configured admin location/email details.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_ADMINME 256`, `RPL_ADMINLOC1 257`, `RPL_ADMINLOC2 258`, `RPL_ADMINEMAIL 259`.
- Errors: `ERR_NOADMININFO 423` if unavailable.
- Example: `ADMIN`
- Sources: `src/daemon/modules/query_info.zig:63`, `src/daemon/server.zig:8075`

## INFO

- Syntax: `INFO`
- Description: Returns implementation information lines and an end marker.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: None specific.
- Example: `INFO`
- Sources: `src/daemon/modules/query_info.zig:64`, `src/daemon/server.zig:10089`

## MOTD

- Syntax: `MOTD`
- Description: Returns configured MOTD lines or no-MOTD error.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_MOTDSTART 375`, `RPL_MOTD 372`, `RPL_ENDOFMOTD 376`.
- Errors: `ERR_NOMOTD 422`.
- Example: `MOTD`
- Sources: `src/daemon/modules/query_info.zig:65`, `src/daemon/server.zig:8040`

## LUSERS

- Syntax: `LUSERS`
- Description: Returns current local/global user and channel counts.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_LUSERCLIENT 251`, `RPL_LUSEROP 252`, `RPL_LUSERUNKNOWN 253`, `RPL_LUSERCHANNELS 254`, `RPL_LUSERME 255`, `RPL_LOCALUSERS 265`, `RPL_GLOBALUSERS 266`.
- Errors: None specific.
- Example: `LUSERS`
- Sources: `src/daemon/modules/query_info.zig:66`, `src/daemon/server.zig:7995`

## USERS

- Syntax: `USERS`
- Description: Lists registered local users or reports no users.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_USERSSTART 392`, `RPL_USERS 393`, `RPL_ENDOFUSERS 394`, or `RPL_NOUSERS 395`.
- Errors: None specific.
- Example: `USERS`
- Sources: `src/daemon/modules/query_info.zig:67`, `src/daemon/server.zig:10121`

## STATS

- Syntax: `STATS <letter>`
- Description: Returns selected server stats. `u` reports uptime, `o` configured oper bindings, `k/K` and `d/D` report Warden-derived line views, and `z` reports runtime debug counters but is oper-only inside the handler.
- Privileges: Registered client; `STATS z` requires oper.
- Parameters: One stats letter.
- Replies: `RPL_STATSUPTIME 242`, `RPL_STATSOLINE 243`, `RPL_STATSKLINE 216`, `RPL_STATSDLINE 225`, `RPL_STATSDEBUG 249`, terminated by `RPL_ENDOFSTATS 219`.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481` for `z` when not oper.
- Example: `STATS u`
- Sources: `src/daemon/modules/oper_security.zig:127`, `src/daemon/server.zig:5306`

## TRACE

- Syntax: `TRACE`
- Description: Oper-only trace of registered local clients, one user row per client and an end row.
- Privileges: Oper (`.access = .oper`).
- Parameters: None.
- Replies: `RPL_TRACEUSER 205`, `RPL_ENDOFTRACE 262`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `TRACE`
- Sources: `src/daemon/modules/oper_security.zig:125`, `src/daemon/server.zig:6253`

## ETRACE

- Syntax: `ETRACE`
- Description: Oper-only extended trace, emitting local users with class, nick, user, visible host, real host, account, and realname.
- Privileges: Oper (`.access = .oper`).
- Parameters: None.
- Replies: Numeric `709` rows, then `RPL_ENDOFTRACE 262`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `ETRACE`
- Sources: `src/daemon/modules/oper_security.zig:126`, `src/daemon/server.zig:6270`

## MODULES

- Syntax: `MODULES`
- Description: Lists loaded registry modules with command/cap/hook counts and total command count.
- Privileges: Oper enforced inside handler.
- Parameters: None.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `MODULES`
- Sources: `src/daemon/modules/introspect.zig:14`, `src/daemon/modules/introspect.zig:99`

## MODLIST

- Syntax: `MODLIST`
- Description: Alias of `MODULES`.
- Privileges: Oper enforced inside handler.
- Parameters: None.
- Replies: Same as `MODULES`.
- Errors: `ERR_NOPRIVILEGES 481`.
- Example: `MODLIST`
- Sources: `src/daemon/modules/introspect.zig:14`, `src/daemon/modules/introspect.zig:100`

## COMMANDS

- Syntax: `COMMANDS [name]`
- Description: With no argument, lists command names available to the caller after access and feature gates. With a name, shows module id, access, feature gate, minimum params, availability, and summary.
- Privileges: Any client (`.access = .any`).
- Parameters: Optional command name.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: None specific; unknown detail query ends with `No such command`.
- Example: `COMMANDS MESH`
- Sources: `src/daemon/modules/introspect.zig:39`, `src/daemon/modules/introspect.zig:101`
