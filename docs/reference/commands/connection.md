# Connection Commands

These commands are accepted through the lower command table used by `dispatchRegistered` for connection-level verbs (`src/daemon/server.zig:3502`, `src/daemon/dispatch.zig:1233`). `NICK`, `PONG`, and `QUIT` are also registered module commands (`src/daemon/modules/user_query.zig:80`, `src/daemon/modules/feature_misc.zig:57`).

## PASS

- Syntax: `PASS <token>`
- Description: Records that a pre-registration password was seen. The handler does not validate a server password; it only updates registration state.
- Privileges: Any pre-registration client.
- Parameters: `token` is required but not otherwise inspected by this handler.
- Replies: None on success.
- Errors: `ERR_ALREADYREGISTRED 462` if already registered; `ERR_NEEDMOREPARAMS 461` if missing.
- Example: `PASS unused`
- Sources: `src/daemon/dispatch.zig:1234`, `src/daemon/dispatch.zig:1251`

## NICK

- Syntax: `NICK <nick>`
- Description: Before registration, stores the nick and checks control bytes and configured `NICKLEN`. After registration, `handleNickChange` changes the live nick and updates the world nick registry.
- Privileges: Any client before registration; registered client afterward.
- Parameters: `nick` is required.
- Replies: On registered nick change, broadcasts a `NICK` line to visible peers.
- Errors: `ERR_ERRONEUSNICKNAME 432`, `ERR_NICKNAMEINUSE 433`, `ERR_NONICKNAMEGIVEN 431`, `ERR_NEEDMOREPARAMS 461`.
- Example: `NICK mizu`
- Sources: `src/daemon/dispatch.zig:1235`, `src/daemon/dispatch.zig:1263`, `src/daemon/modules/user_query.zig:80`, `src/daemon/server.zig:8157`

## USER

- Syntax: `USER <username> <mode> <unused> :<realname>`
- Description: Pre-registration only. Stores username and realname after control-byte validation.
- Privileges: Any pre-registration client.
- Parameters: Four parameters are required by the lower command table; the handler uses parameter 1 as username and parameter 4 as realname.
- Replies: May complete registration and emit welcome numerics when `NICK`, `USER`, and capability negotiation permit it.
- Errors: `ERR_ALREADYREGISTRED 462`; `ERR_NEEDMOREPARAMS 461`.
- Example: `USER mizu 0 * :Mizuchi User`
- Sources: `src/daemon/dispatch.zig:1236`, `src/daemon/dispatch.zig:1283`, `src/daemon/dispatch.zig:1482`

## CAP

- Syntax: `CAP <subcommand> [parameters...]`
- Description: Dispatches capability negotiation to the session capability handler, then emits `CAP LS`, `CAP ACK`, or `CAP NAK` lines.
- Privileges: Any client, before or after registration.
- Parameters: At least a subcommand is required; supported subcommands are determined by the capability handler, not by this command wrapper.
- Replies: Raw `CAP` replies; no numeric on normal success.
- Errors: `ERR_INVALIDCAPCMD 410` for invalid subcommands; `ERR_NEEDMOREPARAMS 461` for missing parameters.
- Example: `CAP LS 302`
- Sources: `src/daemon/dispatch.zig:1237`, `src/daemon/dispatch.zig:1300`, `src/daemon/dispatch.zig:1517`

## AUTHENTICATE

- Syntax: `AUTHENTICATE <mechanism-or-payload>`
- Description: Runs SASL. Mechanism selection starts a router for `PLAIN`, `EXTERNAL`, or `SCRAM-SHA-256`; later lines feed mechanism payloads. A successful exchange lowercases and stores the account, emits login numerics, and lets registration finish.
- Privileges: Any pre-registration client with the `sasl` capability negotiated. Already registered clients are rejected.
- Parameters: One mechanism token or payload chunk is required. `*` aborts when used at the appropriate phase.
- Replies: Raw `AUTHENTICATE <challenge>` lines, `RPL_LOGGEDIN 900`, `RPL_SASLSUCCESS 903`.
- Errors: `ERR_ALREADYREGISTRED 462`, `ERR_SASLFAIL 904`, `ERR_SASLABORTED 906`, `ERR_NEEDMOREPARAMS 461`.
- Example: `AUTHENTICATE PLAIN`
- Sources: `src/daemon/dispatch.zig:1238`, `src/daemon/dispatch.zig:1325`, `src/daemon/dispatch.zig:1430`

## PING

- Syntax: `PING <token>`
- Description: The registered fast path routes `PING` to the lower command table. It replies with `PONG <server> :<token>`.
- Privileges: Any client.
- Parameters: `token` is required.
- Replies: Raw `PONG`.
- Errors: `ERR_NEEDMOREPARAMS 461`.
- Example: `PING 12345`
- Sources: `src/daemon/server.zig:3394`, `src/daemon/dispatch.zig:1239`, `src/daemon/dispatch.zig:1472`

## PONG

- Syntax: `PONG <token>`
- Description: A heartbeat acknowledgement. Both the lower table and registered module handler accept it and intentionally emit no reply.
- Privileges: Any client in the lower table; any client in the registered module table.
- Parameters: Lower-table `PONG` requires one token; the registered module handler ignores invocation details.
- Replies: None.
- Errors: Lower table can emit `ERR_NEEDMOREPARAMS 461`.
- Example: `PONG 12345`
- Sources: `src/daemon/dispatch.zig:1240`, `src/daemon/dispatch.zig:1476`, `src/daemon/modules/feature_misc.zig:41`, `src/daemon/modules/feature_misc.zig:57`

## QUIT

- Syntax: `QUIT [:reason]`
- Description: Before registration, marks the session closing. After registration, records WHOWAS/SEEN data, broadcasts quit, removes the client from the world, and closes the connection.
- Privileges: Any client.
- Parameters: Optional reason; registered handler defaults to `Client quit`.
- Replies: Broadcast `QUIT` to visible peers; no numeric success reply.
- Errors: None specific in the handler.
- Example: `QUIT :done`
- Sources: `src/daemon/dispatch.zig:1241`, `src/daemon/dispatch.zig:1478`, `src/daemon/modules/user_query.zig:81`, `src/daemon/server.zig:11217`
