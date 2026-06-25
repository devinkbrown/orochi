# m_ircx_access — IRCX ACCESS command

_Source-verified module reference for `m_ircx_access`, which provides the IRCX ACCESS command._

## Overview

`m_ircx_access` is a C module implemented in `modules/m_ircx_access.c`. It provides the IRCX ACCESS command.

The command table is derived from the module registration source. The configuration table lists module-owned options plus core config fields read directly by the module.

## Commands

| Command | Required | Description |
| --- | --- | --- |
| `ACCESS` | 2 | Registered command; handler access: registered. |
| `BTACCESS` | 4 | Registered command; handler access: client/server as handled by source. |
| `DENY` | source-defined | Registered command; handler access: dynamic alias. |
| `TACCESS` | 5 | Registered command; handler access: client/server as handled by source. |

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| `ConfigChannel.max_access` | ircd.toml/core default | Read by this module from the core configuration store. |

## Examples

```irc
ACCESS
BTACCESS
DENY
```

## Notes

- Hooks used: `burst_channel`, `can_join`, `channel_join`, `channel_lowerts`.
- Module flags: `MAPI_FLAG_AUTOLOAD`, `MAPI_FLAG_SINGLETON`.
