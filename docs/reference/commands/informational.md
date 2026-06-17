# Informational Commands

Stateless server information commands are registered by `query.info` (`src/daemon/modules/query_info.zig:60`). Registry introspection is provided by `diag.introspect` (`src/daemon/modules/introspect.zig:95`).

## VERSION

- Syntax: `VERSION`
- Description: Returns the current daemon version text. The build token embeds
  the compile target and the **git revision** the binary was built from
  (e.g. `x86_64-linux-<shorthash>`, suffixed `-dirty` for an unclean tree),
  captured at build time via `build.zig` `gitCommit` → `@import("build_info")`.
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
- Description: Returns implementation information lines, then runtime `RPL_INFO` lines for advertised limits, active connection-class count, nick-delay window and held-nick count when nick delay is enabled, established mesh peer count, subsystem inventory, and an end marker.
- Privileges: Registered client.
- Parameters: None.
- Replies: `RPL_INFOSTART 373`, `RPL_INFO 371`, `RPL_ENDOFINFO 374`.
- Errors: None specific.
- Example: `INFO`
- Sources: `src/daemon/modules/query_info.zig:64`, `src/daemon/server.zig:19171`, `src/daemon/server.zig:19206`

## MOTD

- Syntax: `MOTD`
- Description: Returns the Message of the Day, or the no-MOTD error if none is configured. The MOTD is a **personalized per-connection template** (`src/proto/motd_template.zig`): each client's lines are expanded with their own details — a time-of-day greeting, their nick/account/host, live network figures, and oper/login/TLS-aware conditionals — and, when enabled, localized weather (`{weather}`) and headlines (`{news}`). Operators set the body (or override the default) via `[motd] text`; see the config reference for the full placeholder and conditional syntax.
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
- Description: Returns selected server stats. `u` reports uptime, `o` configured oper bindings, `k/K` and `d/D` report Warden-derived line views, `Y/y` reports connection classes, `l/L` reports established S2S peer links, and `z/Z` reports runtime debug counters but is oper-only inside the handler.
- Privileges: Registered client; `STATS z` requires oper.
- Parameters: One stats letter.
- Replies: `RPL_STATSUPTIME 242`, `RPL_STATSOLINE 243`, `RPL_STATSKLINE 216`, `RPL_STATSDLINE 225`, `RPL_STATSYLINE 218`, `RPL_STATSLLINE 211`, `RPL_STATSDEBUG 249`, terminated by `RPL_ENDOFSTATS 219`.
- Notes: `STATS Y` emits one `RPL_STATSYLINE 218` row per connection class as `Y <class>`, with trailing text containing `sendq`, `recvq`, `max_clients`, `max_per_ip`, `max_chan`, `max_targets`, `monitor`, `silence`, `ping`, `ping_timeout`, `reg_timeout`, `flood`, `require_tls`, `require_sasl`, `flood_exempt`, `nick_delay_exempt`, match summary fields `cidrs`, `tls_only`, `account_only`, `oper_only`, and `live` member count. `STATS l` emits one `RPL_STATSLLINE 211` row per established S2S peer link with `sendq_cap`, queued bytes, and `uptime` seconds.
- Errors: `ERR_NEEDMOREPARAMS 461`, `ERR_NOPRIVILEGES 481` for `z` when not oper.
- Example: `STATS u`
- Sources: `src/daemon/modules/oper_security.zig:127`, `src/daemon/server.zig:10310`

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
