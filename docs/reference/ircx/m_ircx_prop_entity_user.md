# m_ircx_prop_entity_user — Provides IRCX PROP support for users
> Source-verified module reference for `m_ircx_prop_entity_user`.

## Overview
`m_ircx_prop_entity_user` is a C module implemented in `modules/m_ircx_prop_entity_user.c`. Provides IRCX PROP support for users.

The command table is derived from the module registration source, and the configuration table lists module-owned options plus core config fields read directly by the module.

## Commands
| Command | Required | Description |
| --- | --- | --- |
| None | n/a | This module does not register a standalone IRC command in its source. |

## Configuration
| Option | Default | Description |
| --- | --- | --- |
| `ConfigChannel.max_prop` | ircd.toml/core default | Read by this module from the core configuration store. |

## Examples
```sh
MODLOAD m_ircx_prop_entity_user
```

## Notes
- Hooks used: `burst_client`, `prop_match`.
- Module flags: `MAPI_FLAG_AUTOLOAD`, `MAPI_FLAG_SINGLETON`.
