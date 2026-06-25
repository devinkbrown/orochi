# IRCv3 (Ophion)

*How Ophion, the C predecessor, registers, advertises, and negotiates IRCv3 client capabilities.*

## Overview

Ophion's IRCv3 model is capability-index based. Core code creates `cli_capindex` and registers foundational client capabilities in `init_builtin_capabs()`. Modules register additional capabilities through their MAPI v4 `mapi_cap_list`.

The `m_cap` module handles CAP negotiation. When modules add or remove capabilities, `mod_remember_clicaps()` and `mod_notify_clicaps()` compare the capability mask and notify clients that negotiated `cap-notify`.

## Capability sources

| Source | Default | Description |
|--------|---------|-------------|
| Core registration | Always during server init | `ircd/s_serv.c` registers built-in client capabilities. |
| MAPI cap lists | Module-dependent | `modules.c` calls `capability_put()` for every `mapi_cap_list` entry. |
| Anonymous server caps | Internal only | Server-side anonymous bits such as `CAP_CAP` and `CAP_LADON` are not client CAP names. |
| Orphaning | On module unload | A module-owned cap can be marked orphaned when its module unloads. |

## Supported client capabilities

This table lists capability names found in current source. Where a cap is module-owned, the link points to its owning reference module page; core capabilities link to the most relevant core or module reference page rather than re-documenting behavior here.

| Capability | Default | Description |
|------------|---------|-------------|
| `account-extban` | Module `cap_account_extban` | `$a` account extban support. See `cap_account_extban`. |
| `account-notify` | Core-registered, owned by `m_services` when loaded | Account change notifications. See `m_services`. |
| `account-tag` | Module `cap_account_tag` | Account name message tag. See `cap_account_tag`. |
| `away-notify` | Core-registered and module-listed by `m_away` | Away state notifications. See `m_away`. |
| `batch` | Core-registered and module-listed by `cap_batch` | IRCv3 batch framework. See `cap_batch`. |
| `bot` | Module `cap_bot_mode` | Bot mode/tag support. See `cap_bot_mode`. |
| `cap-notify` | Core-registered and module-listed by `m_cap` | Capability change notifications. See `m_cap`. |
| `chghost` | Core-registered and module-listed by `m_chghost` | Username/hostname change notifications. See `m_chghost`. |
| `draft/channel-rename` | Module `m_channel_rename` | Channel rename notifications. See `m_channel_rename`. |
| `draft/chathistory` | Module `m_chathistory` | IRCv3 CHATHISTORY retrieval. See `m_chathistory`. |
| `draft/event-playback` | Module `m_chathistory` | Event playback in history batches. See `m_chathistory`. |
| `draft/file-upload` | Module `m_filehost` | File upload extension. See `m_filehost`. |
| `draft/message-editing` | Module `cap_message_edit` | Message edit events. See `cap_message_edit`. |
| `draft/message-redaction` | Module `cap_message_redaction` | Message redaction events. See `cap_message_redaction`. |
| `draft/multiline` | Module `m_multiline` | Multiline message batches. See `m_multiline`. |
| `draft/netjoin` | Module `cap_batch_netsplit` | Netjoin batch advertisements. See `cap_batch_netsplit`. |
| `draft/netsplit` | Module `cap_batch_netsplit` | Netsplit batch advertisements. See `cap_batch_netsplit`. |
| `draft/pre-away` | Core-registered and module-listed by `m_away` | Set away message before registration. See `m_away`. |
| `draft/react` | Module `cap_react` | Message reaction extension. See `cap_react`. |
| `draft/read-marker` | Module `m_read_marker` | Read marker synchronization. See `m_read_marker`. |
| `draft/reply` | Module `cap_reply` | Reply metadata. See `cap_reply`. |
| `draft/search` | Module `m_search` | Search extension. See `m_search`. |
| `draft/typing` | Core-registered and module-listed by `cap_typing` | Typing indicators. See `cap_typing`. |
| `echo-message` | Core-registered and module-listed by `cap_message_tags` | Echo sent messages to sender. See `cap_message_tags`. |
| `extended-join` | Core-registered | JOIN messages include account and realname. See `core join`. |
| `extended-monitor` | Module `m_monitor` | Monitor events include away/chghost/setname/account changes. See `m_monitor`. |
| `invite-notify` | Core-registered, used by `m_invite` | Channel invite notifications. See `m_invite`. |
| `labeled-response` | Core-registered | Label tags and labeled-response batches. See `core send`. |
| `message-tags` | Core-registered and module-listed by `cap_message_tags` | IRCv3 message tags and `TAGMSG`. See `cap_message_tags`. |
| `msgid` | Module `m_chathistory` | Unique message IDs. See `m_chathistory`. |
| `multi-prefix` | Core-registered | Show all status prefixes in NAMES/WHO. See `m_namesx`. |
| `no-implicit-names` | Core-registered and module-listed by `m_names` | Suppress automatic NAMES after JOIN. See `m_names`. |
| `ophion/ladon-media` | Module `cap_ladon_media` | LADON media capability with ISUPPORT advertisement. See `cap_ladon_media`. |
| `ophion/prop-notify` | Module `cap_prop_notify` | IRCX PROP change notifications. See `cap_prop_notify`. |
| `ophion/session-sync` | Module `m_session_sync` | Session synchronization extension. See `m_session_sync`. |
| `sasl` | Module `m_sasl_core` | SASL negotiation entry point. See `m_sasl_core`. |
| `server-time` | Core-registered and module-listed by `cap_server_time` | UTC message timestamps. See `cap_server_time`. |
| `setname` | Core-registered and module-listed by `m_setname` | Realname changes. See `m_setname`. |
| `standard-replies` | Core-registered | FAIL/WARN/NOTE replies. See `m_cap`. |
| `sts` | Module `cap_sts` | Strict Transport Security advertisement. See `cap_sts`. |
| `tls` | Module `m_starttls` | STARTTLS negotiation. See `m_starttls`. |
| `userhost-in-names` | Core-registered | Include userhost in NAMES output. See `m_namesx`. |
| `utf8-only` | Core-registered and module-listed by `cap_utf8_only` | UTF-8 only message policy. See `cap_utf8_only`. |

## Negotiation shape

```irc
C: CAP LS 302
S: CAP * LS :cap-notify sasl server-time message-tags batch
C: CAP REQ :sasl server-time message-tags
S: CAP * ACK :sasl server-time message-tags
C: CAP END
```

Capabilities are represented as bitmasks. `capability_put()` allocates one bit per capability in an index, and `capability_get()` returns the bitmask used by `IsCapable()`.

## SASL mechanisms

`m_sasl_core` registers the `sasl` cap; SASL modules provide individual mechanisms. `m_session_token` adds the `SESSION-TOKEN` mechanism through SASL hooks and provides `sasl:session-token`.

| Mechanism | Default | Description |
|-----------|---------|-------------|
| `PLAIN` | Module-dependent | Password-based login. |
| `EXTERNAL` | Module-dependent | TLS client certificate login. |
| `SCRAM-SHA-256` | Module-dependent | SCRAM login. |
| `SCRAM-SHA-512` | Module-dependent | SCRAM login. |
| `SESSION-TOKEN` | `m_session_token` autoload singleton | Token resume; hashes persist in LMDB. See `Upgrade and Migration`. |

