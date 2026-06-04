# IRCv3
> How Ophion registers, advertises, and negotiates IRCv3 client capabilities.

## Overview

Ophion's IRCv3 model is capability-index based. Core code creates `cli_capindex` and registers foundational client capabilities in `init_builtin_capabs()`. Modules register additional capabilities through their MAPI v4 `mapi_cap_list`.

CAP negotiation is handled by the `m_cap` module. When modules add or remove capabilities, `mod_remember_clicaps()` and `mod_notify_clicaps()` compare the capability mask and notify clients that negotiated `cap-notify`.

## Capability Sources

| Source | Default | Description |
|--------|---------|-------------|
| Core registration | Always during server init | `ircd/s_serv.c` registers built-in client capabilities. |
| MAPI cap lists | Module-dependent | `modules.c` calls `capability_put()` for every `mapi_cap_list` entry. |
| Anonymous server caps | Internal only | Server-side anonymous bits such as `CAP_CAP` and `CAP_LADON` are not client CAP names. |
| Orphaning | On module unload | A module-owned cap can be marked orphaned when its module unloads. |

## Supported Client Capabilities

This table lists capability names found in current source. Links point to the owning reference module page where the cap is module-owned; core capabilities link to the most relevant core/module reference page rather than re-documenting behavior here.

| Capability | Default | Description |
|------------|---------|-------------|
| `account-extban` | Module `cap_account_extban` | `$a` account extban support. See [cap_account_extban](../reference/modules/cap_account_extban.md). |
| `account-notify` | Core-registered, owned by `m_services` when loaded | Account change notifications. See [m_services](../reference/modules/m_services.md). |
| `account-tag` | Module `cap_account_tag` | Account name message tag. See [cap_account_tag](../reference/modules/cap_account_tag.md). |
| `away-notify` | Core-registered and module-listed by `m_away` | Away state notifications. See [m_away](../reference/modules/m_away.md). |
| `batch` | Core-registered and module-listed by `cap_batch` | IRCv3 batch framework. See [cap_batch](../reference/modules/cap_batch.md). |
| `bot` | Module `cap_bot_mode` | Bot mode/tag support. See [cap_bot_mode](../reference/modules/cap_bot_mode.md). |
| `cap-notify` | Core-registered and module-listed by `m_cap` | Capability change notifications. See [m_cap](../reference/modules/m_cap.md). |
| `chghost` | Core-registered and module-listed by `m_chghost` | Username/hostname change notifications. See [m_chghost](../reference/modules/m_chghost.md). |
| `draft/channel-rename` | Module `m_channel_rename` | Channel rename notifications. See [m_channel_rename](../reference/modules/m_channel_rename.md). |
| `draft/chathistory` | Module `m_chathistory` | IRCv3 CHATHISTORY retrieval. See [m_chathistory](../reference/modules/m_chathistory.md). |
| `draft/event-playback` | Module `m_chathistory` | Event playback in history batches. See [m_chathistory](../reference/modules/m_chathistory.md). |
| `draft/file-upload` | Module `m_filehost` | File upload extension. See [m_filehost](../reference/modules/m_filehost.md). |
| `draft/message-editing` | Module `cap_message_edit` | Message edit events. See [cap_message_edit](../reference/modules/cap_message_edit.md). |
| `draft/message-redaction` | Module `cap_message_redaction` | Message redaction events. See [cap_message_redaction](../reference/modules/cap_message_redaction.md). |
| `draft/multiline` | Module `m_multiline` | Multiline message batches. See [m_multiline](../reference/modules/m_multiline.md). |
| `draft/netjoin` | Module `cap_batch_netsplit` | Netjoin batch advertisements. See [cap_batch_netsplit](../reference/modules/cap_batch_netsplit.md). |
| `draft/netsplit` | Module `cap_batch_netsplit` | Netsplit batch advertisements. See [cap_batch_netsplit](../reference/modules/cap_batch_netsplit.md). |
| `draft/pre-away` | Core-registered and module-listed by `m_away` | Set away message before registration. See [m_away](../reference/modules/m_away.md). |
| `draft/react` | Module `cap_react` | Message reaction extension. See [cap_react](../reference/modules/cap_react.md). |
| `draft/read-marker` | Module `m_read_marker` | Read marker synchronization. See [m_read_marker](../reference/modules/m_read_marker.md). |
| `draft/reply` | Module `cap_reply` | Reply metadata. See [cap_reply](../reference/modules/cap_reply.md). |
| `draft/search` | Module `m_search` | Search extension. See [m_search](../reference/modules/m_search.md). |
| `draft/typing` | Core-registered and module-listed by `cap_typing` | Typing indicators. See [cap_typing](../reference/modules/cap_typing.md). |
| `echo-message` | Core-registered and module-listed by `cap_message_tags` | Echo sent messages to sender. See [cap_message_tags](../reference/modules/cap_message_tags.md). |
| `extended-join` | Core-registered | JOIN messages include account and realname. See [core join](../reference/modules/m_channel.md). |
| `extended-monitor` | Module `m_monitor` | Monitor events include away/chghost/setname/account changes. See [m_monitor](../reference/modules/m_monitor.md). |
| `invite-notify` | Core-registered, used by `m_invite` | Channel invite notifications. See [m_invite](../reference/modules/m_invite.md). |
| `labeled-response` | Core-registered | Label tags and labeled-response batches. See [core send](../reference/modules/m_cap.md). |
| `message-tags` | Core-registered and module-listed by `cap_message_tags` | IRCv3 message tags and `TAGMSG`. See [cap_message_tags](../reference/modules/cap_message_tags.md). |
| `msgid` | Module `m_chathistory` | Unique message IDs. See [m_chathistory](../reference/modules/m_chathistory.md). |
| `multi-prefix` | Core-registered | Show all status prefixes in NAMES/WHO. See [m_namesx](../reference/modules/m_namesx.md). |
| `no-implicit-names` | Core-registered and module-listed by `m_names` | Suppress automatic NAMES after JOIN. See [m_names](../reference/modules/m_names.md). |
| `ophion/ladon-media` | Module `cap_ladon_media` | LADON media capability with ISUPPORT advertisement. See [cap_ladon_media](../reference/modules/cap_ladon_media.md). |
| `ophion/prop-notify` | Module `cap_prop_notify` | IRCX PROP change notifications. See [cap_prop_notify](../reference/modules/cap_prop_notify.md). |
| `ophion/session-sync` | Module `m_session_sync` | Session synchronization extension. See [m_session_sync](../reference/modules/m_session_sync.md). |
| `sasl` | Module `m_sasl_core` | SASL negotiation entry point. See [m_sasl_core](../reference/modules/m_sasl_core.md). |
| `server-time` | Core-registered and module-listed by `cap_server_time` | UTC message timestamps. See [cap_server_time](../reference/modules/cap_server_time.md). |
| `setname` | Core-registered and module-listed by `m_setname` | Realname changes. See [m_setname](../reference/modules/m_setname.md). |
| `standard-replies` | Core-registered | FAIL/WARN/NOTE replies. See [m_cap](../reference/modules/m_cap.md). |
| `sts` | Module `cap_sts` | Strict Transport Security advertisement. See [cap_sts](../reference/modules/cap_sts.md). |
| `tls` | Module `m_starttls` | STARTTLS negotiation. See [m_starttls](../reference/modules/m_starttls.md). |
| `userhost-in-names` | Core-registered | Include userhost in NAMES output. See [m_namesx](../reference/modules/m_namesx.md). |
| `utf8-only` | Core-registered and module-listed by `cap_utf8_only` | UTF-8 only message policy. See [cap_utf8_only](../reference/modules/cap_utf8_only.md). |

## Negotiation Shape

```irc
C: CAP LS 302
S: CAP * LS :cap-notify sasl server-time message-tags batch
C: CAP REQ :sasl server-time message-tags
S: CAP * ACK :sasl server-time message-tags
C: CAP END
```

Capabilities are represented as bitmasks. `capability_put()` allocates one bit per capability in an index, while `capability_get()` returns the bitmask used by `IsCapable()`.

## SASL Mechanisms

The `sasl` cap is registered by `m_sasl_core`; individual mechanisms are provided by SASL modules. `m_session_token` adds the `SESSION-TOKEN` mechanism through SASL hooks and provides `sasl:session-token`.

| Mechanism | Default | Description |
|-----------|---------|-------------|
| `PLAIN` | Module-dependent | Password-based login. |
| `EXTERNAL` | Module-dependent | TLS client certificate login. |
| `SCRAM-SHA-256` | Module-dependent | SCRAM login. |
| `SCRAM-SHA-512` | Module-dependent | SCRAM login. |
| `SESSION-TOKEN` | `m_session_token` autoload singleton | Token resume; hashes persist in LMDB. See [Upgrade and Migration](upgrade-and-migration.md#session-tokens). |

