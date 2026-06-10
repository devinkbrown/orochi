# Operators

Orochi operators are SASL-only. `OPER` never accepts a password; it returns an error telling the user to authenticate by SASL (`src/daemon/server.zig:8300`). After successful SASL, an account matching `[[opers]]` is elevated automatically (`src/daemon/server.zig:8308`).

## Account Binding

```toml
[sasl]
account_db = "/var/lib/orochi/accounts.wal"

[[opers]]
account = "alice"
class = "netadmin"
title = "Network Guardian"
```

`account_db` opens a OroStore account backend and wires PLAIN, SCRAM-SHA-256, and EXTERNAL into the live server (`src/main.zig:177`, `src/main.zig:193`). `[[opers]].account` is required and must be non-empty (`src/daemon/config_format.zig:433`, `src/daemon/config_format.zig:481`). `class` names an operator group, and `title` is optional WHOIS/operator display text (`src/daemon/config_format.zig:436`, `src/daemon/config_format.zig:441`).

## Privilege Classes

Define privilege bundles with `[[oper_groups]]`:

```toml
[[oper_groups]]
name = "observer"
privileges = ["audit_read", "event_subscribe"]

[[oper_groups]]
name = "netadmin"
inherits = "observer"
privileges = ["server_rehash", "server_restart", "mesh_admin", "client_kill"]
```

Privilege strings must match the `oper.Privilege` enum names exactly (`src/daemon/oper.zig:36`):

| Privilege | Meaning in source |
|---|---|
| `server_rehash` | REHASH and config reload authority. |
| `server_restart` | RESTART authority. |
| `server_shutdown` | DIE/shutdown authority. |
| `client_moderate` | WARD/SHUN/quarantine-style client controls. |
| `channel_moderate` | FORCE/CLEAR/channel takeover class controls. |
| `client_kill` | KILL authority. |
| `mesh_admin` | CONNECT/SQUIT and mesh routing control. |
| `service_admin` | Services administration. |
| `server_admin` | Network administrator tier. |
| `oper_grant` | Grant/revoke operator status. |
| `oper_spy` | Private/audit visibility such as real host/IP. |
| `event_subscribe` | Event Spine subscription authority. |
| `audit_read` | Audit read authority. |
| `oper_override` | Force/SA-style override authority. |

Unknown privilege strings are ignored during config boot conversion (`src/daemon/config_boot.zig:159`). If an oper class is missing, or its effective privileges are empty, current boot falls back to full privileges (`src/daemon/config_boot.zig:174`, `src/daemon/config_boot.zig:179`). Use explicit, non-empty groups.

Group inheritance is bounded to 32 parent links (`src/daemon/operator_groups.zig:11`). Effective privileges are the union of the group and ancestors (`src/daemon/operator_groups.zig:88`).

## Reload Behavior

When booted with a config file, `REHASH` re-reads the same path (`src/main.zig:112`, `src/daemon/server.zig:10031`). Current `REHASH` rebuilds account-to-oper bindings but assigns full privileges rather than recomputing `[[oper_groups]]` (`src/daemon/server.zig:10052`, `src/daemon/server.zig:10062`). Existing sessions keep their current oper state (`src/daemon/server.zig:10028`).
