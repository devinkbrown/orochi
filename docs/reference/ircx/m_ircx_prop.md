# m_ircx_prop — IRCX PROP command

_Source-verified module reference for `m_ircx_prop`, which provides the IRCX PROP command._

## Overview

`m_ircx_prop` is a C module implemented in `modules/m_ircx_prop.c`. It provides the IRCX PROP command.

The command table is derived from the module registration source. The configuration table lists module-owned options plus core config fields read directly by the module.

## Commands

| Command | Required | Description |
| --- | --- | --- |
| `BTPROP` | 4 | Registered command; handler access: client/server as handled by source. |
| `PROP` | 2 | Registered command; handler access: client/server as handled by source. |
| `TPROP` | 5 | Registered command; handler access: client/server as handled by source. |

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| `ConfigChannel.max_prop` | ircd.toml/core default | Read by this module from the core configuration store. |

## Examples

```irc
BTPROP
PROP
TPROP
```

## Notes

- Module flags: `MAPI_FLAG_AUTOLOAD`, `MAPI_FLAG_SINGLETON`.
