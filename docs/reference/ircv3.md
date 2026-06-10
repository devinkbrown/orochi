# IRCv3 spec coverage (source: github.com/ircv3/ircv3-specifications)

Full extension catalog from the IRCv3 specifications repo, mapped to Orochi modules.
Status: ✅ implemented · 🔧 in-flight · ⬜ TODO · ❌ removed (clean-room/no-legacy).
Always implement to the actual spec text; this table is the work map, not the spec.

| IRCv3 extension | Orochi | Status |
|---|---|---|
| capability-negotiation | `proto/cap.zig` | ✅ |
| message-tags | `proto/irc_line.zig` (parse) + `proto/msgtags.zig` (emit) | ✅ |
| server-time | `proto/msgtags.zig` | ✅ |
| account-tag | `proto/msgtags.zig` | ✅ |
| message-ids | `proto/msgtags.zig` (msgid) | ✅ |
| batch / client-batch | `proto/batch.zig` | ✅ |
| labeled-response | `proto/batch.zig` + `proto/msgtags.zig` | 🔧 partial |
| standard-replies | `proto/standard_replies.zig` | 🔧 (wave 10) |
| extended-isupport / isupport | `proto/isupport.zig` | 🔧 (wave 10) |
| sasl-3.1 / sasl-3.2 | `proto/sasl.zig` (PLAIN/EXTERNAL/SCRAM-256) | ✅ |
| account-registration | `daemon/services.zig` (REGISTER) | ✅ backend |
| monitor | `proto/monitor.zig` | ✅ |
| extended-monitor | `proto/extended_monitor.zig` | ✅ (wire into dispatch) |
| away-notify | `proto/away.zig` | ✅ |
| pre-away | `proto/away.zig` | 🔧 |
| chghost | `proto/chghost.zig` | ✅ |
| setname | `proto/chghost.zig` | ✅ |
| chathistory | `proto/chathistory.zig` (Lotus) | ✅ |
| read-marker | `proto/read_marker.zig` | 🔧 (wave 10) |
| multiline | `proto/multiline.zig` | 🔧 (wave 10) |
| message-redaction | `proto/msgedit.zig` | 🔧 (wave 10) |
| sts | `proto/sts.zig` | ✅ |
| websocket | `proto/websocket.zig` | ✅ |
| whox | `proto/who.zig` | ✅ |
| account-extban | `proto/extban.zig` | 🔧 |
| bot-mode | `proto/bot_mode.zig` (RPL_WHOISBOT 335, BOT isupport) | ✅ (wire into dispatch) |
| echo-message | `proto/echo_message.zig` | ✅ (wire into dispatch) |
| extended-join | `proto/extended_join.zig` | ✅ (wire into dispatch) |
| userhost-in-names / multi-prefix | `proto/names_reply.zig` | 🔧 (wave B) |
| invite-notify | `proto/invite_notify.zig` | ✅ (wire into dispatch) |
| channel-rename | channel commands | ⬜ |
| no-implicit-names | registration | ⬜ |
| utf8only | `proto/utf8_only.zig` (strict UTF-8 + UTF8ONLY isupport + FAIL) | ✅ (wire into dispatch) |
| metadata | overlaps IRCX PROP (`proto/ircx.zig`) — unify | ⬜ |
| oper-tag | ties to clean-room `daemon/oper.zig` | ⬜ |
| network-icon | cosmetic isupport token | ⬜ |
| account-notify | `proto/account_notify.zig` | ✅ (wire into dispatch) |
| **webirc** | — | ❌ removed (clean-room: WebSocket only) |
| deprecated: tls (STARTTLS), sasl-dh-* | — | ❌ removed (TLS-native / modern SASL) |

Notes: `metadata` (IRCv3) and IRCX `PROP` are two takes on the same idea — Orochi should expose ONE
unified property system (lean IRCX PROP, expose a metadata-compatible view). `oper-tag` integrates with
the SASL-only oper system. `labeled-response` should ride the `batch` machinery.
