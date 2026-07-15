# Helix upgrade

*Hot-restart Orochi in place with the Helix workflow, preserving every shard's listener and live sessions.*

Helix is Orochi's in-place upgrade workflow. The operator-facing command is `UPGRADE`, implemented as an oper-only hot re-exec on Linux (`src/daemon/server.zig:16851`, `src/daemon/server.zig:16852`).

## Preconditions

| Requirement | Detail | Source |
|---|---|---|
| Linux | Non-Linux builds reply that `UPGRADE` is Linux-only. | `src/daemon/server.zig:17417` |
| Operator privilege | The command requires the `server_restart` privilege before proceeding. | `src/daemon/server.zig:16852` |
| Re-exec path | The daemon re-execs the configured on-disk launch path, falling back to `/proc/self/exe`. | `src/daemon/server.zig:17556` |

## Workflow

1. The old process publishes an operator event and selects every registered connection except the requesting oper's own connection (`src/daemon/server.zig:17425`, `src/daemon/server.zig:17193`).
2. On a multi-reactor node, it parks every sibling reactor between loop turns before reading foreign-shard connection state. A shard that does not park within the bounded wait refuses the upgrade instead of being dropped (`src/daemon/server.zig:5746`, `src/daemon/server.zig:17443`).
3. It snapshots connection state and channel memberships across every shard (`src/daemon/server.zig:17102`, `src/daemon/server.zig:17215`, `src/daemon/server.zig:17236`).
4. It serializes the snapshots into Helix state pieces and seals them into a memfd arena (`src/daemon/server.zig:17514`, `src/daemon/helix/live.zig:58`).
5. It clears close-on-exec for every per-shard listener, the carried client sockets, and the arena fd; then it builds an exec plan for the configured on-disk binary with `--supervisor` and commits the exec (`src/daemon/server.zig:17538`, `src/daemon/server.zig:17557`, `src/daemon/server.zig:17566`).
6. The successor starts in `--supervisor` mode, adopts the inherited listener fd for each shard, keeps every `SO_REUSEPORT` accept queue served, and stores the inherited arena fd for session adoption (`src/main.zig:151`, `src/daemon/server.zig:3410`).
7. After the new server starts, it reads the arena and re-attaches carried-over client, TLS, WebSocket, session-registry, and secured-mesh state on a best-effort basis. Carried clients are deterministically re-pinned across the live shard set (`src/main.zig:998`, `src/daemon/server.zig:17582`).

Session-registry carry preserves every attachment row, including multiple live or
detached rows sharing one reusable logical-session token. The successor therefore
does not collapse a multi-client session into a single owner. It also carries the
portable bit, detached snapshots, and staged signed replicas. Once preserved secured
links are adopted, the successor re-offers portable state to rebuild the
process-local token-to-authenticated-peer authorization bindings.

The Helix live path passes inherited fds through environment variables. A single-shard or legacy handoff uses `OROCHI_HELIX_LISTEN_FD`; a multi-shard predecessor additionally passes the full shard-ordered set in `OROCHI_HELIX_LISTEN_FDS`. The sealed arena uses `OROCHI_HELIX_ARENA_FD` (`src/daemon/helix/live.zig:119`, `src/daemon/helix/live.zig:135`, `src/daemon/helix/live.zig:276`).

## Fallbacks

If state sealing fails, `UPGRADE` falls back to a listener-only re-exec: the listen port stays bound, but session carry-over is skipped (`src/daemon/server.zig:17514`, `src/daemon/server.zig:17525`, `src/daemon/server.zig:18333`). If the successor cannot read or adopt a carried item, it drops that item without aborting the process (`src/daemon/server.zig:17582`).

## Rollback boundary

Hot rollback is safe only when the older binary understands the listener handoff
emitted by the running predecessor. In particular, do **not** hot-roll back a
multi-shard Orochi 0.5.2+ process to a pre-0.5.2 binary: the older successor adopts
only shard 0's listener and leaves the sibling inherited fds in the `SO_REUSEPORT`
group without reactors accepting from them, black-holing a share of new connections.
Install the previous binary and use a cold restart across that boundary. See the
[runbook rollback procedure](../RUNBOOK.md#rollback).
