# Orochi IRCv3 capabilities

*Live CAP registry advertised during capability negotiation, sourced from `src/daemon/dispatch.zig`.*

This reference documents the live capability registry in `src/daemon/dispatch.zig`. `src/proto/cap.zig` is not the live CAP registry. The live registry is `CapId` plus `cap_specs`. CAP LS emits those specs and appends `=<value>` for CAP LS 302 only when the spec or session supplies a value (`src/daemon/dispatch.zig:223`, `src/daemon/dispatch.zig:293`, `src/daemon/dispatch.zig:504`).

## CAP LS 302 table

| Capability | CAP LS 302 Value | Notes | Evidence |
| --- | --- | --- | --- |
| `server-time` | none | Enables server-time tags. | `src/daemon/dispatch.zig:293` |
| `message-tags` | none | Negotiable generic message tags. | `src/daemon/dispatch.zig:294` |
| `echo-message` | none | Echo sent messages to sender. | `src/daemon/dispatch.zig:295` |
| `sasl` | `PLAIN,EXTERNAL,SCRAM-SHA-256` | Live `AUTHENTICATE` routes PLAIN, EXTERNAL, and SCRAM-SHA-256 through the mech router; unconfigured checkers fail closed. | `src/daemon/dispatch.zig:298`, `src/daemon/dispatch.zig:1367` |
| `multi-prefix` | none | Multi-prefix NAMES/WHOIS behavior. | `src/daemon/dispatch.zig:299` |
| `userhost-in-names` | none | Adds userhost detail to NAMES for capable clients. | `src/daemon/dispatch.zig:300` |
| `away-notify` | none | Away state notifications. | `src/daemon/dispatch.zig:301` |
| `setname` | none | SETNAME support. | `src/daemon/dispatch.zig:302` |
| `extended-join` | none | Extended JOIN support. | `src/daemon/dispatch.zig:303` |
| `invite-notify` | none | Invite notifications. | `src/daemon/dispatch.zig:304` |
| `account-tag` | none | Enables account tags. | `src/daemon/dispatch.zig:305` |
| `orochi/session-sync` | none | Orochi vendor cap for sibling-device direct-message mirroring. | `src/daemon/dispatch.zig:308` |
| `orochi/bouncer` | none | Orochi vendor cap for automatic history rewind on join/rejoin. | `src/daemon/dispatch.zig:312` |
| `orochi/topics` | none | Orochi vendor cap for named conversations: clients can receive `+orochi/topic=<label>` without generic `message-tags`, and discover topic-filtered CHATHISTORY. | `src/daemon/dispatch.zig` (`orochi_topics`) |
| `chghost` | none | Receive CHGHOST lines for common-user host changes. | `src/daemon/dispatch.zig:316` |
| `no-implicit-names` | none | Suppress automatic NAMES burst on JOIN for capable clients. | `src/daemon/dispatch.zig:319` |
| `draft/chathistory` | none | CHATHISTORY command and chathistory BATCH replies. | `src/daemon/dispatch.zig:331` |
| `draft/message-redaction` | none | REDACT command. | `src/daemon/dispatch.zig:332` |
| `draft/message-editing` | none | EDIT command. | `src/daemon/dispatch.zig:333` |
| `draft/read-marker` | none | MARKREAD command. | `src/daemon/dispatch.zig:334` |
| `draft/typing` | none | Client-only typing tags relayed through TAGMSG. | `src/daemon/dispatch.zig:335` |
| `draft/react` | none | Client-only reaction tags relayed through TAGMSG. | `src/daemon/dispatch.zig:336` |
| `draft/reply` | none | Client-only reply tags relayed through TAGMSG. | `src/daemon/dispatch.zig:337` |
| `draft/event-playback` | none | CHATHISTORY/bouncer replay includes channel events (JOIN/PART/MODE/TOPIC/KICK/NICK/QUIT) rendered as `:sender CMD <body>`; clients without it get messages only. | `src/daemon/dispatch.zig:337` (`event_playback`) |
| `batch` | none | Server emits BATCH for features such as chathistory and netsplit. | `src/daemon/dispatch.zig:338` |
| `bot` | none | Bot mode/cap; user `+B` is surfaced in WHOIS. | `src/daemon/dispatch.zig:339` |
| `draft/channel-rename` | none | Receive RENAME for common channel renames. | `src/daemon/dispatch.zig:342` |
| `extended-monitor` | none | Extended MONITOR state notifications. | `src/daemon/dispatch.zig:345` |
| `account-notify` | none | ACCOUNT lines on common-user login/logout. | `src/daemon/dispatch.zig:349` |
| `draft/account-registration` | `custom-account-name` (CAP LS 302) | REGISTER/VERIFY account registration discovery; the 302 value signals that custom (non-nick) account names are accepted. | `src/daemon/dispatch.zig` (`account_registration`, `value_302`) |
| `draft/metadata-2` | none | METADATA GET/SET/LIST/CLEAR and 761/762/766 numerics. | `src/daemon/dispatch.zig:354` |
| `standard-replies` | none | FAIL/WARN/NOTE support. | `src/daemon/dispatch.zig:356` |
| `cap-notify` | none | Static cap set support; CAP NEW/DEL do not fire for the static set. | `src/daemon/dispatch.zig:357` |
| `labeled-response` | none | Echoes `@label` on responses and frames multiline replies with labeled-response BATCH. | `src/daemon/dispatch.zig:362`, `src/daemon/dispatch.zig:1125` |
| `draft/pre-away` | none | AWAY may be sent during registration. | `src/daemon/dispatch.zig:368` |
| `draft/channel-context` | none | Relays client-only channel-context tags. | `src/daemon/dispatch.zig:371` |
| `draft/multiline` | `max-bytes=4096,max-lines=24` | Accepts inbound multiline BATCH chunks and reassembles them within enforced limits. | `src/daemon/dispatch.zig:375` |
| `sts` | runtime policy value | Config-gated; omitted unless a live STS policy is enabled for the session. | `src/daemon/dispatch.zig:383`, `src/daemon/dispatch.zig:504` |

## Negotiation behavior

| Operation | Behavior | Evidence |
| --- | --- | --- |
| `CAP LS [302]` | Enters negotiating state, remembers 302 support, and emits live cap specs, chunking to `MAX_CAP_REPLY_BODY` if needed. | `src/daemon/dispatch.zig:468`, `src/daemon/dispatch.zig:504` |
| `CAP REQ` | Parses requested tokens; unknown or unavailable caps NAK the request without partial mutation. | `src/daemon/dispatch.zig:531`, `src/daemon/dispatch.zig:577` |
| `CAP LIST` | Emits currently negotiated cap names. | `src/daemon/dispatch.zig:564` |
| `CAP END` | Marks negotiation complete and releases registration hold. | `src/daemon/dispatch.zig:552` |

## Vendor caps

The live `src/daemon/dispatch.zig` vendor namespace is `orochi/*`: `orochi/session-sync`, `orochi/bouncer`, and `orochi/topics`. No `ocean/*` capability appears in the live registry; do not document an Ocean vendor cap unless one is added to `cap_specs`.
