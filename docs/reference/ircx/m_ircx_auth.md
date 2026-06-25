# m_ircx_auth — IRCX AUTH command

_Source-verified module reference for `m_ircx_auth`, a multi-step SASL driver for non-CAP clients._

> Historical reference only: this page describes the legacy Ophion C module
> `modules/m_ircx_auth.c`. It is not the Orochi Zig implementation source of
> truth. Orochi's live authentication path is IRCv3 CAP/AUTHENTICATE in
> `src/daemon/dispatch.zig`.

## Overview

`m_ircx_auth` is a C module implemented in `modules/m_ircx_auth.c`. It provides the IRCX AUTH command, a multi-step SASL driver for non-CAP clients.

The command table is derived from the module registration source. The configuration table lists module-owned options plus core config fields read directly by the module.

## Commands

| Command | Required | Description |
| --- | --- | --- |
| `AUTH` | 3 | Registered command; handler access: client/server as handled by source. |

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| None | n/a | No dedicated module configuration was found in source. |

## Examples

```irc
AUTH
```

## Notes

- Module flags: `MAPI_FLAG_AUTOLOAD`, `MAPI_FLAG_SINGLETON`.
