# m_ircx_oper — IRCX operator tools

_Source-verified module reference for `m_ircx_oper`, which provides IRCX operator tools: GAG mode (+g) and OPFORCE commands._

## Overview

`m_ircx_oper` is a C module implemented in `modules/m_ircx_oper.c`. It provides IRCX operator tools: GAG mode (+g) and OPFORCE commands.

The command table is derived from the module registration source. The configuration table lists module-owned options plus core config fields read directly by the module.

## Commands

| Command | Required | Description |
| --- | --- | --- |
| `GAG` | 2 | Registered command; handler access: registered. |
| `GAG_ADD` | source-defined | Registered command; handler access: client/server as handled by source. |
| `GAG_CLEAR` | source-defined | Registered command; handler access: client/server as handled by source. |
| `GAG_DEL` | source-defined | Registered command; handler access: client/server as handled by source. |
| `OPFORCE` | 3 | Registered command; handler access: registered. |
| `SVSJOIN` | 3 | Registered command; handler access: oper, registered. |

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| None | n/a | No dedicated module configuration was found in source. |

## Examples

```irc
GAG
GAG_ADD
GAG_CLEAR
```

## Notes

- Hooks used: `burst_finished`, `new_local_user`, `privmsg_channel`, `privmsg_user`, `umode_changed`.
- Module flags: `MAPI_FLAG_AUTOLOAD`, `MAPI_FLAG_SINGLETON`.
