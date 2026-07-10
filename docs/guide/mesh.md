# Mesh and S2S

*Configure server-to-server linking over the [Suimyaku](../reference/glossary.md) mesh, including secured and plaintext links and operator inspection views.*

Orochi server-to-server (S2S) linking runs on the [Suimyaku](../reference/glossary.md) mesh runtime. Configure node identity in `[node]`, mesh settings in `[mesh]`, and the inbound S2S listener in `[listen].s2s`.

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

`[listen].s2s` maps to `server.Config.s2s_port`; `0` disables the inbound S2S listener (`src/daemon/config_boot.zig:70`, `src/daemon/server.zig:1738`). The server binds it alongside the IRC listener when the value is non-zero (`src/daemon/server.zig:3298`, `src/daemon/server.zig:3299`).

## Secured vs. plaintext links

Post-quantum-secured S2S is enabled by default when a node identity and CSPRNG are available. An explicit `[node].secret_key` takes precedence; otherwise `main.zig` loads or creates `orochi-node.key` beside the config path, derives the identity using `[mesh].realm`, sets `server.Config.node_identity`, and copies `mesh_pass` if configured (`src/main.zig:310`, `src/main.zig:323`, `src/main.zig:331`, `src/main.zig:338`, `src/main.zig:348`, `src/main.zig:351`). Only keyfile or identity setup failure leaves S2S plaintext (`src/main.zig:329`, `src/main.zig:335`, `src/main.zig:345`). The live secured check is `node_identity != null and crypto_io != null` (`src/daemon/server.zig:6177`, `src/daemon/server.zig:6179`).

Outbound `CONNECT <host> <port>` is an operator command that requires `mesh_admin` (`src/daemon/server.zig:17161`, `src/daemon/server.zig:17165`). If the local server has secured S2S enabled, `CONNECT` starts a secured handshake; otherwise it starts a plaintext S2S link (`src/daemon/server.zig:17187`, `src/daemon/server.zig:17238`, `src/daemon/server.zig:17252`). `SQUIT <server>` tears down a peer link by handshake-learned server name and also requires `mesh_admin` (`src/daemon/server.zig:17312`, `src/daemon/server.zig:17315`, `src/daemon/server.zig:17343`, `src/daemon/server.zig:17345`).

## Operator views

The operator security module exposes the current mesh inspection commands (`src/daemon/modules/oper_security.zig:180`, `src/daemon/modules/oper_security.zig:183`):

| Command | View |
|---|---|
| `MESH` or `NETSTAT` | Direct S2S peer/link health, multi-hop reachability, partition summary, `MESH LOG`, `MESH ADMISSION`, and `MESH GRANTS` (`src/daemon/server.zig:28746`, `src/daemon/server.zig:28748`, `src/daemon/server.zig:28761`, `src/daemon/server.zig:28780`, `src/daemon/server.zig:28835`). |
| `ROUTE` | Current routing view: local node plus established one-hop peers; multi-hop routing is noted as future substrate work (`src/daemon/server.zig:28909`, `src/daemon/server.zig:28918`). |
| `NETHEALTH` | [Sazanami](../reference/glossary.md)-style liveness view using local node, established peers, RTT, idle time, and the live quorum/component summary (`src/daemon/server.zig:28931`, `src/daemon/server.zig:28943`, `src/daemon/server.zig:28961`). |
| `CONNECT` | Opens outbound S2S to a peer (`src/daemon/server.zig:17161`, `src/daemon/server.zig:17180`). |
| `SQUIT` | Tears down an S2S link by server name (`src/daemon/server.zig:17312`, `src/daemon/server.zig:17322`). |

`MESH ADMISSION` reports [MeshPass](../reference/glossary.md) admission mode, secured-S2S status, signed-frame policy, root count, token presence, and minimum revocation epoch without exposing shared secret or token bytes (`src/daemon/server.zig:28759`, `src/daemon/server.zig:28763`, `src/daemon/server.zig:28773`).

`MESH` reflects both plaintext and secured S2S peers in the same report (`src/daemon/server.zig:28801`, `src/daemon/server.zig:28807`).
