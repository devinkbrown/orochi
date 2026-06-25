# m_ircx_event — IRCX EVENT command

_Source-verified module reference for `m_ircx_event`, which provides the IRCX EVENT command for oper event monitoring._

## Overview

`m_ircx_event` is a C module implemented in `modules/m_ircx_event.c`. It provides the IRCX EVENT command for oper event monitoring.

The command table is derived from the module registration source. The configuration table lists module-owned options plus core config fields read directly by the module.

## Commands

| Command | Required | Description |
| --- | --- | --- |
| `EVENT` | 0 | Registered command; handler access: registered. |

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| `ConfigFileEntry.kline_reason` | ircd.toml/core default | Read by this module from the core configuration store. |

## Examples

```irc
EVENT
```

## Notes

- Hooks used: `account_login`, `account_logout`, `after_client_exit`, `burst_channel`, `can_kick`, `channel_ban_add`, `channel_ban_remove`, `channel_destroy`, `channel_join`, `channel_modes_set`, `channel_part`, `client_exit`, `doing_admin`, `doing_info`, `doing_links`, `doing_motd`, `doing_stats`, `doing_stats_p`, `doing_trace`, `doing_whois`, ...
- Module flags: `MAPI_FLAG_AUTOLOAD`, `MAPI_FLAG_SINGLETON`.
