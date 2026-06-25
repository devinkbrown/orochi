# Upgrade and OroWasm

*Helix in-place upgrade and the OroWasm control-plane plugin host.*

Cryptographic details are out of scope; see [crypto.md](crypto.md).

## Helix UPGRADE command

The `UPGRADE` command is a SerpentRegistry module command in `ops.upgrade`. The module is a thin wrapper: it recovers `module_core.Core` and calls `LinuxServer.handleUpgrade`. Evidence: `src/daemon/modules/upgrade.zig:1`, `src/daemon/modules/upgrade.zig:13`, `src/daemon/modules/upgrade.zig:15`, `src/daemon/modules/upgrade.zig:18`, `src/daemon/modules/upgrade.zig:22`.

`handleUpgrade` is Linux-only and oper-only at runtime. It publishes an oper event, serializes registered sessions into snapshot blobs, seals a Helix arena, clears `FD_CLOEXEC` on the listener and arena fds, builds an exec plan for `/proc/self/exe --supervisor`, and commits via `execve`. Evidence: `src/daemon/server.zig:6070`, `src/daemon/server.zig:6076`, `src/daemon/server.zig:6077`, `src/daemon/server.zig:6081`, `src/daemon/server.zig:6086`, `src/daemon/server.zig:6090`, `src/daemon/server.zig:6127`, `src/daemon/server.zig:6146`, `src/daemon/server.zig:6148`, `src/daemon/server.zig:6155`.

## State and fd handoff

| Piece | Current source behavior | Evidence |
| --- | --- | --- |
| Session snapshot | Encodes nick, realname, account, real/visible host, away state, logged-in/away/oper flags, fd, and channel memberships. | `src/daemon/helix/session_snapshot.zig:1`, `src/daemon/helix/session_snapshot.zig:10`, `src/daemon/helix/session_snapshot.zig:14`, `src/daemon/helix/session_snapshot.zig:15` |
| Snapshot collection | `handleUpgrade` walks registered clients, skips the requesting oper connection, captures fd, captures channel memberships/member modes, encodes snapshot blobs, and clears CLOEXEC on carried client fds. | `src/daemon/server.zig:6097`, `src/daemon/server.zig:6099`, `src/daemon/server.zig:6100`, `src/daemon/server.zig:6103`, `src/daemon/server.zig:6106`, `src/daemon/server.zig:6110`, `src/daemon/server.zig:6114`, `src/daemon/server.zig:6121` |
| Sealed arena | `helix_live.prepare` creates a memfd arena, writes encoded capsules, seals it, initializes control socket state, and advances the supervisor model. | `src/daemon/helix/live.zig:48`, `src/daemon/helix/live.zig:58`, `src/daemon/helix/live.zig:60`, `src/daemon/helix/live.zig:65`, `src/daemon/helix/live.zig:67`, `src/daemon/helix/live.zig:72`, `src/daemon/helix/live.zig:74` |
| Memfd implementation | `handoff.Arena.create` uses Linux `memfd_create` with sealing; `seal` applies seal, shrink, grow, and write seals. | `src/daemon/helix/handoff.zig:1`, `src/daemon/helix/handoff.zig:45`, `src/daemon/helix/handoff.zig:52`, `src/daemon/helix/handoff.zig:78`, `src/daemon/helix/handoff.zig:80` |
| Listener and arena exec plan | Current `handleUpgrade` uses `buildArenaListenerExecPlan`, carrying the sealed arena and listener fd via environment variables to `--supervisor`. | `src/daemon/server.zig:6148`, `src/daemon/helix/live.zig:242`, `src/daemon/helix/live.zig:260`, `src/daemon/helix/live.zig:262` |
| Listener-only fallback | If state sealing fails or planning fails, `upgradeListenerOnly` re-execs while preserving only the listening socket. | `src/daemon/server.zig:6134`, `src/daemon/server.zig:6137`, `src/daemon/server.zig:6233`, `src/daemon/server.zig:6237` |

## Successor adoption

The successor path is driven by `orochi --supervisor`. `main.zig` checks the Helix handoff environment fds, adopts the inherited listener fd into server config, stores the arena fd for later session adoption, then boots normally. Evidence: `src/main.zig:51`, `src/main.zig:57`, `src/main.zig:58`, `src/main.zig:61`, `src/main.zig:68`, `src/main.zig:75`.

After the server starts and its ring exists, `main.zig` calls `srv.adoptInheritedSessions()`. Evidence: `src/main.zig:280`, `src/main.zig:292`, `src/main.zig:294`.

| Adoption stage | Behavior | Evidence |
| --- | --- | --- |
| Env parsing | `resumeFromEnv` reads `/proc/self/environ` for arena, control, and listener fd variables; if none exist, it returns null. | `src/daemon/helix/live.zig:268`, `src/daemon/helix/live.zig:279`, `src/daemon/helix/live.zig:282`, `src/daemon/helix/live.zig:296`, `src/daemon/helix/live.zig:299` |
| Listener adoption | `initReactor` uses `config.inherited_listener_fd` for the single-reactor, non-SO_REUSEPORT path. | `src/daemon/server.zig:974`, `src/daemon/server.zig:1480`, `src/daemon/server.zig:1482` |
| Arena read | `adoptInheritedSessions` reads capsules from `resume_arena_fd`, decodes each first field as a session snapshot, and closes the arena when consumed. | `src/daemon/server.zig:6167`, `src/daemon/server.zig:6169`, `src/daemon/server.zig:6170`, `src/daemon/server.zig:6181`, `src/daemon/server.zig:6186` |
| Client reattach | `adoptInheritedClient` allocates a connection slot around inherited fd, restores session, injects session state, re-registers nick, restores channel memberships, and arms recv. | `src/daemon/server.zig:6193`, `src/daemon/server.zig:6198`, `src/daemon/server.zig:6210`, `src/daemon/server.zig:6211`, `src/daemon/server.zig:6217`, `src/daemon/server.zig:6220`, `src/daemon/server.zig:6224` |

## Helix supervisor model

`src/daemon/helix/supervisor.zig` holds the pure state machine. It exposes states from `idle` through `committed`/`rolled_back`; events such as request, freeze, drain, serialized, fd handoff, attestation, timeout, worker exit, and operator abort; plus actions such as freeze, drain, serialize, pass fds, await attestation, commit, and rollback. Evidence: `src/daemon/helix/supervisor.zig:1`, `src/daemon/helix/supervisor.zig:22`, `src/daemon/helix/supervisor.zig:33`, `src/daemon/helix/supervisor.zig:46`.

`prepare` currently advances through request, accept frozen, drain complete, and capsules serialized. Evidence: `src/daemon/helix/live.zig:74`, `src/daemon/helix/live.zig:75`, `src/daemon/helix/live.zig:77`, `src/daemon/helix/live.zig:79`, `src/daemon/helix/live.zig:81`.

`handOff` can pass fds over the control socket and advance to `awaiting_attestation`, but the live `handleUpgrade` path currently uses the environment-based arena/listener exec plan rather than `handOff`. Evidence for `handOff`: `src/daemon/helix/live.zig:92`, `src/daemon/helix/live.zig:99`, `src/daemon/helix/live.zig:113`; evidence for live path: `src/daemon/server.zig:6148`.

## OroWasm host

OroWasm is a pure-Zig control-plane plugin host. It is re-exported from `src/root.zig`, and the server owns a `wasm_bridge.Bridge` in `LinuxServer`. Evidence: `src/root.zig:14`, `src/root.zig:16`, `src/daemon/server.zig:1288`, `src/daemon/server.zig:1291`, `src/daemon/server.zig:1563`.

## Plugin dispatch path

| Stage | Behavior | Evidence |
| --- | --- | --- |
| Server consult | `dispatchRegistered` checks the bridge only after SerpentRegistry misses and only when plugin count is nonzero and the bridge has the command. | `src/daemon/server.zig:3471`, `src/daemon/server.zig:3473` |
| Host bindings | The server supplies reply, log, and now_ms callbacks over an opaque per-command context. | `src/daemon/server.zig:3482`, `src/daemon/server.zig:3484`, `src/daemon/server.zig:3485`, `src/daemon/server.zig:3486` |
| Bridge dispatch | `Bridge.dispatch` finds the owning plugin command, builds a hostcall callback, calls the exported function with default fuel, maps denied/trap outcomes, and returns handled. | `src/wasm/host/bridge.zig:79`, `src/wasm/host/bridge.zig:82`, `src/wasm/host/bridge.zig:84`, `src/wasm/host/bridge.zig:85`, `src/wasm/host/bridge.zig:86`, `src/wasm/host/bridge.zig:89` |
| Server error mapping | Denied hostcalls and traps become numeric errors to the client. | `src/daemon/server.zig:3488`, `src/daemon/server.zig:3490`, `src/daemon/server.zig:3494` |

## Plugin loading and capabilities

| Source | Behavior | Evidence |
| --- | --- | --- |
| `Bridge.init` | Creates `PluginStore` with allowed caps reply, log, and time. | `src/wasm/host/bridge.zig:31`, `src/wasm/host/bridge.zig:34`, `src/wasm/host/bridge.zig:35` |
| Directory load | `loadFromDir` opens a plugin directory, loads `*.wasm` files up to 8 MiB, and uses the file stem as fallback plugin name. | `src/wasm/host/bridge.zig:40`, `src/wasm/host/bridge.zig:43`, `src/wasm/host/bridge.zig:52`, `src/wasm/host/bridge.zig:53`, `src/wasm/host/bridge.zig:55` |
| Metadata parse | Bridge parses imports/exports to infer requested capabilities and command exports; `cmd_*` exports become commands. | `src/wasm/host/bridge.zig:63`, `src/wasm/host/bridge.zig:67`, `src/wasm/host/bridge.zig:234`, `src/wasm/host/bridge.zig:249`, `src/wasm/host/bridge.zig:259` |
| ABI schema | Host functions are independently versioned and capability-gated. | `src/wasm/host/abi.zig:1`, `src/wasm/host/abi.zig:8`, `src/wasm/host/abi.zig:22`, `src/wasm/host/abi.zig:69`, `src/wasm/host/abi.zig:121` |
| Capability negotiation | Granted caps are the intersection of requested caps and host policy; manifest major version must be compatible. | `src/wasm/host/abi.zig:139`, `src/wasm/host/abi.zig:142`, `src/wasm/host/abi.zig:143` |
| Store lifecycle | `PluginStore` owns loaded plugins, command registrations, hook registrations, and deinitializes them on unload/deinit. | `src/wasm/host/plugin.zig:68`, `src/wasm/host/plugin.zig:72`, `src/wasm/host/plugin.zig:73`, `src/wasm/host/plugin.zig:74`, `src/wasm/host/plugin.zig:81`, `src/wasm/host/plugin.zig:117` |

## Interpreter

`src/wasm/host/interp.zig` is a minimal pure-Zig wasm32 interpreter, not a general-purpose runtime. It parses a small wasm32 subset, executes integer, local, control, and memory instructions, counts fuel per instruction, and traps unsupported opcodes. Evidence: `src/wasm/host/interp.zig:1`, `src/wasm/host/interp.zig:3`, `src/wasm/host/interp.zig:4`, `src/wasm/host/interp.zig:5`, `src/wasm/host/interp.zig:6`.

| Interpreter guard | Evidence |
| --- | --- |
| Configurable max memory, default 64 KiB | `src/wasm/host/interp.zig:28` |
| `callWithHostcalls` takes fuel and optional hostcall callback | `src/wasm/host/interp.zig:113` |
| Each instruction decrements fuel and `FuelExhausted` traps at zero | `src/wasm/host/interp.zig:155`, `src/wasm/host/interp.zig:156` |
| Unsupported opcodes trap | `src/wasm/host/interp.zig:158`, `src/wasm/host/interp.zig:189` |
| Memory slices are bounds-checked | `src/wasm/host/interp.zig:119`, `src/wasm/host/interp.zig:122` |
| Imports require a host callback and type matching | `src/wasm/host/interp.zig:212`, `src/wasm/host/interp.zig:216`, `src/wasm/host/interp.zig:218` |

## Browser WASM is separate

`src/wasm/kagura_wasm.zig` exports browser and client codec functions for OPVOX and OPVIS. It is a `wasm32-freestanding` codec surface and should not be confused with the daemon's OroWasm plugin host. Evidence: `src/wasm/kagura_wasm.zig:1`, `src/wasm/kagura_wasm.zig:3`, `src/wasm/kagura_wasm.zig:17`, `src/wasm/kagura_wasm.zig:35`.

## Planning notes and divergences

| Topic | Current-code finding | Evidence |
| --- | --- | --- |
| Helix client fd reattach | `handleUpgrade` now clears CLOEXEC on client fds and successor `adoptInheritedClient` reattaches them. Some comments still describe client fd reattach as a remaining increment. | stale comment: `src/daemon/server.zig:6074`; current code: `src/daemon/server.zig:6121`, `src/daemon/server.zig:6198`, `src/daemon/server.zig:6224` |
| Channel membership carry-over | `session_snapshot.zig` header still says caps/umodes/channel membership are later, but the current format and server adoption restore channel memberships. | stale comment: `src/daemon/helix/session_snapshot.zig:8`; current code: `src/daemon/helix/session_snapshot.zig:15`, `src/daemon/server.zig:6219` |
| Control-socket fd pass | The helper exists in `helix_live.handOff`, but the live `handleUpgrade` path uses env-passed arena/listener fds through `buildArenaListenerExecPlan`. | helper: `src/daemon/helix/live.zig:92`; live path: `src/daemon/server.zig:6148` |
| Plugin hooks | `PluginStore` can register plugin hooks, but `Bridge.dispatch` only dispatches plugin commands in the current server path. | hook storage: `src/wasm/host/plugin.zig:74`; command dispatch: `src/wasm/host/bridge.zig:79`; server consult: `src/daemon/server.zig:3473` |
