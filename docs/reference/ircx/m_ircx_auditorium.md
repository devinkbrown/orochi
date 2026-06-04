# m_ircx_auditorium — Provides IRCX auditorium channel mode (+x) that hides non-ops from each other
> Source-verified module reference for `m_ircx_auditorium`.

## Overview
`m_ircx_auditorium` is a C module implemented in `modules/m_ircx_auditorium.c`. Provides IRCX auditorium channel mode (+x) that hides non-ops from each other.

The command table is derived from the module registration source, and the configuration table lists module-owned options plus core config fields read directly by the module.

## Commands
| Command | Required | Description |
| --- | --- | --- |
| None | n/a | This module does not register a standalone IRC command in its source. |

## Configuration
| Option | Default | Description |
| --- | --- | --- |
| None | n/a | No dedicated module configuration was found in source. |

## Examples
```sh
MODLOAD m_ircx_auditorium
```

## Notes
- Module flags: `MAPI_FLAG_AUTOLOAD`, `MAPI_FLAG_SINGLETON`.
