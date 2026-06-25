# m_ircx_prop_channel_builtins — IRCX built-in channel properties

_Source-verified module reference for `m_ircx_prop_channel_builtins`, which provides the built-in channel properties OID, NAME, CREATION, TOPIC, MEMBERCOUNT, MEMBERKEY, MEMBERLIMIT, PICS, LAG, and CLIENT._

## Overview

`m_ircx_prop_channel_builtins` is a C module implemented in `modules/m_ircx_prop_channel_builtins.c`. It provides the IRCX built-in channel properties OID, NAME, CREATION, TOPIC, MEMBERCOUNT, MEMBERKEY, MEMBERLIMIT, PICS, LAG, and CLIENT.

The command table is derived from the module registration source. The configuration table lists module-owned options plus core config fields read directly by the module.

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
MODLOAD m_ircx_prop_channel_builtins
```

## Notes

- Hooks used: `prop_chan_write`, `prop_change`, `prop_key_exists`, `prop_list_append`, `prop_show`.
- Module flags: `MAPI_FLAG_AUTOLOAD`, `MAPI_FLAG_SINGLETON`.
