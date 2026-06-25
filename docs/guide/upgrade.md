# Helix upgrade

*Hot-restart Orochi in place with the Helix workflow, preserving the listener and live sessions.*

Helix is Orochi's in-place upgrade workflow. The operator-facing command is `UPGRADE`, implemented as an oper-only hot re-exec on Linux (`src/daemon/server.zig:6070`, `src/daemon/server.zig:6076`).

## Preconditions

| Requirement | Detail | Source |
|---|---|---|
| Linux | Non-Linux builds reply that `UPGRADE` is Linux-only. | `src/daemon/server.zig:6081` |
| Operator status | The command checks `conn.session.isOper()` before proceeding. | `src/daemon/server.zig:6077` |
| Re-exec path | The daemon must run from an executable path that can be re-execed as `/proc/self/exe`. | `src/daemon/server.zig:6148` |

## Workflow

1. The old process publishes an operator event and snapshots every registered session except the requesting oper's own connection (`src/daemon/server.zig:6085`, `src/daemon/server.zig:6097`, `src/daemon/server.zig:6100`).
2. It captures channel memberships and member modes into the session snapshot (`src/daemon/server.zig:6105`).
3. It serializes snapshots into Helix state pieces and seals them into a memfd arena (`src/daemon/server.zig:6114`, `src/daemon/server.zig:6124`, `src/daemon/helix/live.zig:58`, `src/daemon/helix/live.zig:67`).
4. It clears close-on-exec for the listener and arena fds, builds an exec plan for `/proc/self/exe --supervisor`, and commits the exec (`src/daemon/server.zig:6145`, `src/daemon/server.zig:6148`, `src/daemon/server.zig:6155`).
5. The successor starts in `--supervisor` mode, adopts the inherited listener fd, keeps the port bound, and stores the inherited arena fd for session adoption (`src/main.zig:51`, `src/main.zig:57`, `src/main.zig:61`, `src/main.zig:68`).
6. After the new server starts, it reads the arena and re-attaches carried-over client connections on a best-effort basis (`src/main.zig:292`, `src/daemon/server.zig:6163`, `src/daemon/server.zig:6178`).

The Helix live path passes inherited fds through environment variables: `OROCHI_HELIX_ARENA_FD`, `OROCHI_HELIX_CONTROL_FD`, and `OROCHI_HELIX_LISTEN_FD` (`src/daemon/helix/live.zig:119`).

## Fallbacks

If state sealing fails, `UPGRADE` falls back to a listener-only re-exec: the listen port stays bound, but session carry-over is skipped (`src/daemon/server.zig:6124`, `src/daemon/server.zig:6136`). If the successor cannot read or adopt a session, it drops that carried item without aborting the process (`src/daemon/server.zig:6163`, `src/daemon/server.zig:6170`).
