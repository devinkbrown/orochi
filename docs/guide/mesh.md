# Mesh and S2S

Orochi S2S uses the Suimyaku mesh runtime. Configure identity in `[node]`, mesh settings in `[mesh]`, and the inbound S2S listener in `[listen].s2s`.

```toml
[node]
id = 1
secret_key = "env:OROCHI_NODE_SECKEY"

[listen]
irc = 6680
s2s = 7700

[mesh]
realm = "example"
mesh_pass = "env:OROCHI_MESH_PASS"
```

`[listen].s2s` maps to `server.Config.s2s_port`; `0` disables the inbound S2S listener (`src/daemon/config_boot.zig:26`, `src/daemon/server.zig:1046`). The server binds it alongside the IRC listener when non-zero (`src/daemon/server.zig:1490`).

## Secured vs Plaintext Links

When `[node].secret_key` is configured, `main.zig` derives a node identity using `[mesh].realm`, sets `server.Config.node_identity`, copies `mesh_pass` if configured, and enables PQ-secured S2S (`src/main.zig:147`, `src/main.zig:149`, `src/main.zig:152`, `src/main.zig:153`). Without a node identity, S2S stays plaintext (`src/main.zig:141`).

Outbound `CONNECT <host> <port>` is an oper command requiring `mesh_admin` (`src/daemon/server.zig:6304`, `src/daemon/server.zig:6308`). If the local server has secured S2S enabled, CONNECT starts a secured handshake; otherwise it starts a plaintext S2S link (`src/daemon/server.zig:6339`, `src/daemon/server.zig:6354`). `SQUIT <server>` tears down a peer link and also requires `mesh_admin` (`src/daemon/server.zig:6371`, `src/daemon/server.zig:6374`).

## Oper Views

The oper security module exposes the current mesh inspection commands (`src/daemon/modules/oper_security.zig:123`, `src/daemon/modules/oper_security.zig:132`):

| Command | View |
|---|---|
| `MESH` or `NETSTAT` | Direct S2S peer/link health, reachability, partition summary, `MESH LOG`, and `MESH GRANTS` (`src/daemon/server.zig:10218`, `src/daemon/server.zig:10308`). |
| `ROUTE` | Current routing view: local node plus established one-hop peers; multi-hop routing is noted as future substrate work (`src/daemon/server.zig:10452`). |
| `NETHEALTH` | SWIM-style liveness view using local node, established peers, RTT, and idle time (`src/daemon/server.zig:10474`). |
| `CONNECT` | Opens outbound S2S to a peer (`src/daemon/server.zig:6304`). |
| `SQUIT` | Tears down an S2S link by server name (`src/daemon/server.zig:6371`). |

`MESH` reflects both plaintext and secured S2S peers in the same report (`src/daemon/server.zig:10343`).
