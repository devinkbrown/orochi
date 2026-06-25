# IRCv3 spec coverage

*The full IRCv3 extension catalog mapped to Orochi modules and implementation status.*

Extensions are drawn from the IRCv3 specifications repository (`github.com/ircv3/ircv3-specifications`).
Always implement to the actual spec text; this table is the work map, not the spec.

Status legend:

| Status | Meaning |
|---|---|
| Implemented | Complete and live. |
| In-flight | Partially implemented or under active work. |
| TODO | Planned, not yet started. |
| Removed | Intentionally excluded (clean-room, no legacy). |

| IRCv3 extension | Orochi | Status |
|---|---|---|
| capability-negotiation | `proto/cap.zig` | Implemented |
| message-tags | `proto/irc_line.zig` (parse) + `proto/msgtags.zig` (emit) | Implemented |
| server-time | `proto/msgtags.zig` | Implemented |
| account-tag | `proto/msgtags.zig` | Implemented |
| message-ids | `proto/msgtags.zig` (msgid) | Implemented |
| batch / client-batch | `proto/batch.zig` | Implemented |
| labeled-response | `proto/batch.zig` + `proto/msgtags.zig` | In-flight (partial) |
| standard-replies | `proto/standard_replies.zig` | In-flight (wave 10) |
| extended-isupport / isupport | `proto/isupport.zig` | In-flight (wave 10) |
| sasl-3.1 / sasl-3.2 | `proto/sasl.zig` (PLAIN/EXTERNAL/SCRAM-256) | Implemented |
| account-registration | `daemon/services.zig` (REGISTER) | Implemented (backend) |
| monitor | `proto/monitor.zig` | Implemented |
| extended-monitor | `proto/extended_monitor.zig` | Implemented (wired into dispatch) |
| away-notify | `proto/away.zig` | Implemented |
| pre-away | `proto/away.zig` | In-flight |
| chghost | `proto/chghost.zig` | Implemented |
| setname | `proto/chghost.zig` | Implemented |
| chathistory | `proto/chathistory.zig` (Lotus) | Implemented |
| read-marker | `proto/read_marker.zig` | In-flight (wave 10) |
| multiline | `proto/multiline.zig` | In-flight (wave 10) |
| message-redaction | `proto/msgedit.zig` | In-flight (wave 10) |
| sts | `proto/sts.zig` | Implemented |
| websocket | `proto/websocket.zig` | Implemented |
| whox | `proto/who.zig` | Implemented |
| account-extban | `proto/extban.zig` | In-flight |
| bot-mode | `proto/bot_mode.zig` (RPL_WHOISBOT 335, BOT isupport) | Implemented (wired into dispatch) |
| echo-message | `proto/echo_message.zig` | Implemented (wired into dispatch) |
| extended-join | `proto/extended_join.zig` | Implemented (wired into dispatch) |
| userhost-in-names / multi-prefix | `proto/names_reply.zig` | In-flight (wave B) |
| invite-notify | `proto/invite_notify.zig` | Implemented (wired into dispatch) |
| channel-rename | channel commands | TODO |
| no-implicit-names | registration | TODO |
| utf8only | `proto/utf8_only.zig` (strict UTF-8 + UTF8ONLY isupport + FAIL) | Implemented (wired into dispatch) |
| metadata | overlaps IRCX PROP (`proto/ircx.zig`) — unify | TODO |
| oper-tag | ties to clean-room `daemon/oper.zig` | TODO |
| network-icon | cosmetic isupport token | TODO |
| account-notify | `proto/account_notify.zig` | Implemented (wired into dispatch) |
| webirc | — | Removed (clean-room: WebSocket only) |
| deprecated: tls (STARTTLS), sasl-dh-* | — | Removed (TLS-native / modern SASL) |

Notes: `metadata` (IRCv3) and IRCX `PROP` are two takes on the same idea — Orochi exposes one
unified property system (lean IRCX `PROP` with a metadata-compatible view). `oper-tag` integrates with
the SASL-only oper system. `labeled-response` rides the `batch` machinery.
