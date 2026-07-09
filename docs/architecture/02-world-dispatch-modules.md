# World, dispatch, and modules

_Local `World` state, the two-layer client command dispatch model, SerpentRegistry modules, typed hooks, and registry introspection._

This document covers local world state and the client command dispatch model. Mesh/S2S state projection is out of scope; see [mesh-s2s.md](mesh-s2s.md).

## World model

`src/daemon/world.zig` models local daemon state: nick ownership, channel membership, and channel topics. Its header explicitly says it has no S2S/CRDT responsibilities. Evidence: `src/daemon/world.zig:1`, `src/daemon/world.zig:3`, `src/daemon/world.zig:4`.

| Structure | Role | Evidence |
| --- | --- | --- |
| `ClientId` | Packed client handle with `shard`, `slot`, and `gen`, matching the sharded reactor model. | `src/daemon/world.zig:41`, `src/daemon/world.zig:42` |
| `Channel` | Per-channel members, topic, modes, key, limit, list modes, invites, forward target, private/hidden flags, IRCX ext flags, OID, and creation time. | `src/daemon/world.zig:115`, `src/daemon/world.zig:117`, `src/daemon/world.zig:118`, `src/daemon/world.zig:120`, `src/daemon/world.zig:126`, `src/daemon/world.zig:141`, `src/daemon/world.zig:149`, `src/daemon/world.zig:152` |
| `World` | Owns allocator, channels map, nick maps, object-id source, clock, RCU mirrors, and lock. | `src/daemon/world.zig:193`, `src/daemon/world.zig:197`, `src/daemon/world.zig:198`, `src/daemon/world.zig:200`, `src/daemon/world.zig:207`, `src/daemon/world.zig:218` |
| RCU nick mirror | Activated lazily and used by `findNick` after activation for case-insensitive nick lookup. | `src/daemon/world.zig:10`, `src/daemon/world.zig:14`, `src/daemon/world.zig:455`, `src/daemon/world.zig:460` |
| RCU channel mirror | Tracks channel existence and per-channel membership for lock-free reads after activation. | `src/daemon/world.zig:25`, `src/daemon/world.zig:35`, `src/daemon/world.zig:213`, `src/daemon/world.zig:1020`, `src/daemon/world.zig:1033` |

## World mutations and reads

| Operation | Behavior | Evidence |
| --- | --- | --- |
| Nick registration | Activates RCU nicks, rejects case-insensitive collisions, updates RCU and fallback maps. | `src/daemon/world.zig:400`, `src/daemon/world.zig:407`, `src/daemon/world.zig:411`, `src/daemon/world.zig:430`, `src/daemon/world.zig:434` |
| Nick lookup | Uses RCU when active; otherwise falls back to the map. | `src/daemon/world.zig:455`, `src/daemon/world.zig:461`, `src/daemon/world.zig:465` |
| Join | Creates channel if needed, grants founder mode to the first member, inserts membership, mirrors into RCU. | `src/daemon/world.zig:477`, `src/daemon/world.zig:479`, `src/daemon/world.zig:483`, `src/daemon/world.zig:486`, `src/daemon/world.zig:491` |
| Part | Removes membership, mirrors removal into RCU, and prunes empty unregistered channels. | `src/daemon/world.zig:1003`, `src/daemon/world.zig:1006`, `src/daemon/world.zig:1009`, `src/daemon/world.zig:1015` |
| Target resolution | Distinguishes channel targets from nick targets. | `src/daemon/world.zig:1119`, `src/daemon/world.zig:1120`, `src/daemon/world.zig:1125` |
| Disconnect cleanup | Removes nick and all channel memberships, pruning empty unregistered channels. | `src/daemon/world.zig:1131`, `src/daemon/world.zig:1133`, `src/daemon/world.zig:1137`, `src/daemon/world.zig:1149` |

## Two-layer dispatch

There are two dispatch layers in current source:

| Layer | Source | Command surface | Evidence |
| --- | --- | --- | --- |
| Pre-registration core | `src/daemon/dispatch.zig` | PASS, NICK, USER, CAP, AUTHENTICATE, PING, PONG, QUIT | `src/daemon/dispatch.zig:1233` |
| Post-registration registry | `src/daemon/registry.zig` + `src/daemon/modules/*.zig` | Comptime module commands declared in `modules/manifest.zig` and dispatched via `module_manifest.Live.dispatchGated` | `src/daemon/modules/manifest.zig:22`, `src/daemon/modules/manifest.zig:40`, `src/daemon/server.zig:3450` |

The server-level route is:

| Stage | Behavior | Evidence |
| --- | --- | --- |
| Parse | `processLine` parses one complete IRC line and adapts it into `dispatch.LineView`. | `src/daemon/server.zig:1192`, `src/daemon/server.zig:1195`, `src/daemon/server.zig:1205` |
| Prereg dispatch | `dispatch.dispatchLine` handles labels, validates table lookup/arity/prereg state, runs a handler, syncs registration, and maybe emits the welcome burst. | `src/daemon/dispatch.zig:1111`, `src/daemon/dispatch.zig:1116`, `src/daemon/dispatch.zig:1140`, `src/daemon/dispatch.zig:1146`, `src/daemon/dispatch.zig:1151`, `src/daemon/dispatch.zig:1157`, `src/daemon/dispatch.zig:1166` |
| Registered dispatch entry | Registered non-PING lines enter `dispatchRegistered`. | `src/daemon/server.zig:3394`, `src/daemon/server.zig:3402`, `src/daemon/server.zig:3413` |
| Registry first | `dispatchRegistered` creates `module_core.Core`, computes caps, and calls `module_manifest.Live.dispatchGated`. | `src/daemon/server.zig:3433`, `src/daemon/server.zig:3437`, `src/daemon/server.zig:3445`, `src/daemon/server.zig:3450` |
| Registry miss | If no registry command matches, OroWasm plugins may own the command. | `src/daemon/server.zig:3471`, `src/daemon/server.zig:3473`, `src/daemon/server.zig:3488` |
| Lower fallback | The remaining direct path is `processLine` for the registration-handshake command table; this keeps PASS/NICK/USER/CAP/AUTHENTICATE/PING/QUIT usable after registration where applicable. | `src/daemon/server.zig:3502`, `src/daemon/server.zig:3504`, `src/daemon/server.zig:3508` |

This diverges from older planning and request wording: `dispatchRegistered` no longer holds a large post-registration daemon-owned if/else command chain. The source comment states, "Everything daemon-owned is now a SerpentRegistry command." Evidence: `src/daemon/server.zig:3502`.

## SerpentRegistry

`registry.zig` statically assembles module metadata, command tables, and hook tables at comptime. Its header says module metadata is validated at comptime, command/hook tables are generated once, and dispatch scans immutable declarations. Evidence: `src/daemon/registry.zig:1`, `src/daemon/registry.zig:3`, `src/daemon/registry.zig:5`, `src/daemon/registry.zig:6`.

| Registry concept | Behavior | Evidence |
| --- | --- | --- |
| `CommandSpec` | Declares command name, min params, access, optional feature gate, summary, handler. | `src/daemon/registry.zig:238`, `src/daemon/registry.zig:240`, `src/daemon/registry.zig:241`, `src/daemon/registry.zig:244`, `src/daemon/registry.zig:248`, `src/daemon/registry.zig:251` |
| `Module` | Declares id, version, category, priority, dependencies/conflicts, commands, hooks, caps, modes, numerics, ISUPPORT, lifecycle callbacks. | `src/daemon/registry.zig:343`, `src/daemon/registry.zig:346`, `src/daemon/registry.zig:356`, `src/daemon/registry.zig:357`, `src/daemon/registry.zig:358`, `src/daemon/registry.zig:362`, `src/daemon/registry.zig:365` |
| Validation | Detects duplicate modules, missing deps, conflicts, cycles, and duplicate commands/caps/modes/numerics. | `src/daemon/registry.zig:372`, `src/daemon/registry.zig:408`, `src/daemon/registry.zig:421`, `src/daemon/registry.zig:431`, `src/daemon/registry.zig:447` |
| Built tables | `Registry` builds command, hook, cap, mode, numeric, and ISUPPORT tables at comptime. | `src/daemon/registry.zig:507`, `src/daemon/registry.zig:515`, `src/daemon/registry.zig:516`, `src/daemon/registry.zig:521` |
| Command lookup | A comptime `StaticStringMapWithEql` indexes command names case-insensitively. | `src/daemon/registry.zig:523`, `src/daemon/registry.zig:527`, `src/daemon/registry.zig:531`, `src/daemon/registry.zig:545` |
| Gated dispatch | Enforces feature gates, access, and arity before calling the handler. | `src/daemon/registry.zig:554`, `src/daemon/registry.zig:560`, `src/daemon/registry.zig:563`, `src/daemon/registry.zig:564`, `src/daemon/registry.zig:567`, `src/daemon/registry.zig:570` |

## Typed hooks

Hooks are typed by `HookId`, and `HookPayload(id)` maps each hook id to a concrete payload pointer type. Veto-capable payloads include `approved: bool`. Evidence: `src/daemon/registry.zig:108`, `src/daemon/registry.zig:127`, `src/daemon/registry.zig:131`, `src/daemon/registry.zig:152`, `src/daemon/registry.zig:173`, `src/daemon/registry.zig:219`.

`callHook` takes a comptime `HookId`, type-erases the typed payload at the registry boundary, runs matching bindings, and stops when a hook returns `.stop`. Evidence: `src/daemon/registry.zig:587`, `src/daemon/registry.zig:591`, `src/daemon/registry.zig:596`, `src/daemon/registry.zig:597`, `src/daemon/registry.zig:599`.

The server currently fires the `client_registered` hook after welcome. Evidence: `src/daemon/server.zig:3385`, `src/daemon/server.zig:3547`, `src/daemon/server.zig:3555`.

## Connection classes and nick-delay integration

Connection classes are not a module but a foundational daemon subsystem. Each connection is matched to a class at registration based on source IP (CIDR), TLS, SASL auth, oper status, and ident/host globs. The first matching class wins; built-in fallback classes (`user` and `server`) exist for all connections. Evidence: `src/daemon/conn_class.zig:1`, `src/daemon/server.zig:7073`.

Per-class enforcement hooks into the registration flow (nick assignment to the world) and the per-connection admission check. The class policy enforces SendQ/RecvQ ceilings, flood lines, max_clients/per_ip/channels, require_tls/sasl, and nick_delay exemption. Evidence: `src/daemon/server.zig:3615`, `src/daemon/server.zig:5675`, `src/daemon/server.zig:10343`.

Nick delay is a daemon-global but per-account and per-nick-class feature. When a nick is released (via QUIT or NICK change), it is held for a configured window to prevent nick camping. During the hold, only the owning account can reclaim it (oper bypass always applies, and `nick_delay_exempt` classes bypass). Evidence: `src/daemon/nick_delay.zig:1`, `src/daemon/server.zig:5949`, `src/daemon/server.zig:5954`.

STATS reporting includes per-class policy and live member count (numeric 218 RPL_STATSYLINE) and per-S2S-peer sendq_cap, queued bytes, and uptime (numeric 211 RPL_STATSLLINE). Nick-delay status is reported by INFO. Evidence: `src/daemon/server.zig:10343`, `src/daemon/server.zig:10356`, `src/daemon/server.zig:10377`, `src/daemon/server.zig:19220`.

## Live module manifest and command families

`modules/manifest.zig` is the single enabled-module list. `Live` is the comptime-assembled and validated registry. Evidence: `src/daemon/modules/manifest.zig:1`, `src/daemon/modules/manifest.zig:22`, `src/daemon/modules/manifest.zig:40`, `src/daemon/modules/manifest.zig:42`.

| Module id | Command family in current source | Evidence |
| --- | --- | --- |
| `query.info` | VERSION, TIME, ADMIN, INFO, MOTD, LUSERS, USERS, LINKS, MAP | `src/daemon/modules/query_info.zig:58`, `src/daemon/modules/query_info.zig:61` |
| `channel.ops` | JOIN, PART, NAMES, MODE, KICK, INVITE, TOPIC, KNOCK, CREATE, RENAME | `src/daemon/modules/channel_ops.zig:49`, `src/daemon/modules/channel_ops.zig:52` |
| `messaging` | PRIVMSG, NOTICE, TAGMSG, REDACT, CHATHISTORY, MARKREAD, METADATA, MONITOR, SILENCE | `src/daemon/modules/messaging.zig:44`, `src/daemon/modules/messaging.zig:47` |
| `accounts` | REGISTER, VERIFY, IDENTIFY, LOGOUT, DROP, ACCOUNTINFO, SASLINFO, ACCOUNTSET, GHOST, CHANNEL/CS, SESSION, CERTADD, WEBAUTHN, KEYTRANS, E2EEKEY, IDENTITY | `src/daemon/modules/accounts.zig`, `src/daemon/server.zig` |
| `ircx` | IRCX, ISIRCX, DATA, REQUEST, REPLY, WHISPER, PROP, ACCESS, EVENT, MODEX, LISTX | `src/daemon/modules/ircx.zig:45`, `src/daemon/modules/ircx.zig:48` |
| `oper.security` | OPER, REHASH, KILL, CLOSE, DRAIN, UNREJECT, WARD, SHUN, UNSHUN, GLOBAL, OPERMOTD, DIE, RESTART, CONNECT, SQUIT, TRACE, ETRACE, STATS, TESTLINE, TESTMASK, USERIP, DEBUG, MESH/NETSTAT, ROUTE, NETHEALTH | `src/daemon/modules/oper_security.zig:104`, `src/daemon/modules/oper_security.zig:110` |
| `user.query` | ISON, USERHOST, WHOIS, LIST, WHO, WHOWAS, AWAY, SETNAME, NICK, QUIT, ACCEPT, HELP, HELPOP, AUTOJOIN, GROUP, WELCOME | `src/daemon/modules/user_query.zig:69`, `src/daemon/modules/user_query.zig:72` |
| `feature.misc` | VHOST, PRIVS, FILTER, MEDIA, TEGAMI, ACTIVITY, GEOIP, SUMMON, PONG | `src/daemon/modules/feature_misc.zig:46`, `src/daemon/modules/feature_misc.zig:49` |
| `diag.introspect` | MODULES, MODLIST, COMMANDS | `src/daemon/modules/introspect.zig:95`, `src/daemon/modules/introspect.zig:99` |
| `ops.upgrade` | UPGRADE | `src/daemon/modules/upgrade.zig:18`, `src/daemon/modules/upgrade.zig:22` |
| `services.ext` | RESV, UNRESV, FORCEOP, FORCEDEOP, FORCEJOIN, FORCEPART, FORCETOPIC, CLEAR, TEMPMODE, CLONES, SEEN | `src/daemon/modules/services_ext.zig:41` |

The `MEDIA` command is feature-gated by the registry feature tag `"media"`; disabled feature tags come from `Config.disabled_features`. Evidence: `src/daemon/modules/feature_misc.zig:52`, `src/daemon/server.zig:951`, `src/daemon/server.zig:3448`.

## MODULES and COMMANDS introspection

The `diag.introspect` module exposes registry-driven introspection:

| Command | Behavior | Evidence |
| --- | --- | --- |
| MODULES / MODLIST | Oper-gated list of loaded modules with per-module command/cap/hook counts and totals. | `src/daemon/modules/introspect.zig:1`, `src/daemon/modules/introspect.zig:14`, `src/daemon/modules/introspect.zig:16`, `src/daemon/modules/introspect.zig:23`, `src/daemon/modules/introspect.zig:32`, `src/daemon/modules/introspect.zig:99` |
| COMMANDS | Access-aware command discovery; with an argument it shows one command's module, access, feature, params, availability, and summary. | `src/daemon/modules/introspect.zig:39`, `src/daemon/modules/introspect.zig:44`, `src/daemon/modules/introspect.zig:51`, `src/daemon/modules/introspect.zig:53`, `src/daemon/modules/introspect.zig:75`, `src/daemon/modules/introspect.zig:101` |

## ISUPPORT source

ISUPPORT comes from `src/proto/protocol_inventory.zig`, not from module declarations. The file is explicitly the canonical protocol inventory for static RPL_ISUPPORT tokens, network name, and CHANMODES. Evidence: `src/proto/protocol_inventory.zig:1`, `src/proto/protocol_inventory.zig:2`.

| Token/source | Evidence |
| --- | --- |
| Default network name `Orochi` | `src/proto/protocol_inventory.zig:16` |
| `CHANMODES=beIZ,k,lfj,imnstCTNMSgWOAVUFD` | `src/proto/protocol_inventory.zig` (`chanmodes_token`) |
| Static token array | `src/proto/protocol_inventory.zig:40` |
| Runtime ISUPPORT override | `src/proto/protocol_inventory.zig:65`, `src/proto/protocol_inventory.zig:73`, `src/proto/protocol_inventory.zig:78` |
| Welcome burst emits current ISUPPORT | `src/daemon/dispatch.zig:1497` |

## Planning notes and divergences

`docs/planning/17-module-system.md` is the design-intent document referenced by `module_core.zig`, `modules/manifest.zig`, and `introspect.zig`. Evidence: `src/daemon/module_core.zig:1`, `src/daemon/modules/manifest.zig:7`, `src/daemon/modules/introspect.zig:6`.

The current source has moved daemon-owned post-registration commands into SerpentRegistry. Treat any planning or older request language that describes a live registered if/else command chain as historical, unless it points to the small non-command branches in `dispatchRegistered` for multiline, registry, WASM, and preregistration fallback. Evidence: `src/daemon/server.zig:3429`, `src/daemon/server.zig:3433`, `src/daemon/server.zig:3471`, `src/daemon/server.zig:3502`.
