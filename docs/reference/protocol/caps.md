# Mizuchi IRCv3 Capabilities

This reference documents the capability registry in `src/proto/cap.zig` only. The registry advertises client capabilities whose `kind` is `.client` and `advertised` is true (`src/proto/cap.zig:103`, `src/proto/cap.zig:140`, `src/proto/cap.zig:164`). CAP LS 302 appends `=<value>` only when a `value_302` exists and the client requested 302 (`src/proto/cap.zig:150`, `src/proto/cap.zig:465`).

## CAP LS 302 Table

| Capability | CAP LS 302 Value | Notes | Evidence |
| --- | --- | --- | --- |
| `server-time` | none | Enables server-time tags; tag gate maps `time` / `server-time` to this cap. | `src/proto/cap.zig:372`, `src/proto/cap.zig:354` |
| `message-tags` | none | Negotiable generic message tags. | `src/proto/cap.zig:373` |
| `account-tag` | none | Enables account tags; tag gate maps `account` to this cap. | `src/proto/cap.zig:374`, `src/proto/cap.zig:358` |
| `batch` | none | Enables BATCH; tag gate maps `batch` tag to this cap. | `src/proto/cap.zig:375`, `src/proto/cap.zig:359` |
| `echo-message` | none | Echo sent messages to sender. | `src/proto/cap.zig:376` |
| `cap-notify` | none | Capability notification support. | `src/proto/cap.zig:377` |
| `sts` | `duration=604800` | Strict Transport Security value advertised only under CAP LS 302. | `src/proto/cap.zig:378`, `src/proto/cap.zig:499` |
| `bot` | none | Bot mode/cap; tag gate maps `bot` to this cap. | `src/proto/cap.zig:379`, `src/proto/cap.zig:360` |
| `multiline` | none | Draft multiline cap in this registry; tag gate maps `draft/multiline-concat` to this cap. | `src/proto/cap.zig:380`, `src/proto/cap.zig:363` |
| `chathistory` | none | Chat history capability. | `src/proto/cap.zig:381` |
| `account-notify` | none | Account change notifications. | `src/proto/cap.zig:382` |
| `away-notify` | none | Away state notifications. | `src/proto/cap.zig:383` |
| `setname` | none | SETNAME support. | `src/proto/cap.zig:384` |
| `chghost` | none | CHGHOST support. | `src/proto/cap.zig:385` |
| `extended-monitor` | none | Extended MONITOR support. | `src/proto/cap.zig:386` |
| `labeled-response` | none | Labeled response support; tag gate maps `label` to this cap. | `src/proto/cap.zig:387`, `src/proto/cap.zig:361` |
| `sasl` | `PLAIN,EXTERNAL` | Authentication mechanisms advertised by this registry under CAP LS 302. | `src/proto/cap.zig:388`, `src/proto/cap.zig:500` |
| `msgid` | none | Message ID support; tag gate maps `msgid` to this cap. | `src/proto/cap.zig:389`, `src/proto/cap.zig:362` |
| `account-extban` | none | Account extban support. | `src/proto/cap.zig:390` |
| `tls` | none | TLS capability token. | `src/proto/cap.zig:391` |
| `utf8-only` | none | UTF-8-only network behavior. | `src/proto/cap.zig:392` |
| `no-implicit-names` | none | Suppress automatic NAMES behavior for capable clients. | `src/proto/cap.zig:393` |
| `event-playback` | none | Event playback capability. | `src/proto/cap.zig:394` |
| `read-marker` | none | Read marker support. | `src/proto/cap.zig:395` |
| `channel-rename` | none | Channel rename support. | `src/proto/cap.zig:396` |
| `file-upload` | none | File upload capability token. | `src/proto/cap.zig:397` |
| `search` | none | Search capability token. | `src/proto/cap.zig:398` |
| `reply` | none | Reply metadata capability. | `src/proto/cap.zig:399` |
| `react` | none | Reaction metadata capability. | `src/proto/cap.zig:400` |
| `message-editing` | none | Message editing capability. | `src/proto/cap.zig:401` |
| `message-redaction` | none | Message redaction capability. | `src/proto/cap.zig:402` |
| `typing` | none | Typing indicator capability. | `src/proto/cap.zig:403` |
| `mizuchi/prop-notify` | none | Mizuchi vendor cap for property notifications. | `src/proto/cap.zig:404`, `src/proto/cap.zig:405` |
| `mizuchi/session-sync` | none | Mizuchi vendor cap for session synchronization. | `src/proto/cap.zig:405`, `src/proto/cap.zig:406` |
| `mizuchi/bouncer` | none | Mizuchi vendor cap for bouncer-style behavior. | `src/proto/cap.zig:406`, `src/proto/cap.zig:407` |
| `mizuchi/suimyaku-media` | none | Mizuchi vendor cap for Suimyaku media. | `src/proto/cap.zig:407`, `src/proto/cap.zig:408` |

## Negotiation Behavior

| Operation | Behavior | Evidence |
| --- | --- | --- |
| `CAP LS [302]` | Enters negotiating state, remembers 302 support, and emits advertised client caps, chunking to `MAX_CAP_REPLY_BODY` if needed. | `src/proto/cap.zig:271`, `src/proto/cap.zig:293`, `src/proto/cap.zig:150`, `src/proto/cap.zig:171` |
| `CAP REQ` | Parses requested tokens; unknown, server-kind, or unadvertised cap NAKs the whole raw list without partial mutation. | `src/proto/cap.zig:315`, `src/proto/cap.zig:323`, `src/proto/cap.zig:432` |
| `CAP LIST` | Emits currently negotiated cap names. | `src/proto/cap.zig:305`, `src/proto/cap.zig:448` |
| `CAP END` | Marks negotiation complete and releases registration hold. | `src/proto/cap.zig:286`, `src/proto/cap.zig:343`, `src/proto/cap.zig:260` |

## Vendor Caps

The current `src/proto/cap.zig` vendor namespace is `mizuchi/*`: `mizuchi/prop-notify`, `mizuchi/session-sync`, `mizuchi/bouncer`, and `mizuchi/suimyaku-media` (`src/proto/cap.zig:405`). No `ocean/*` capability appears in this source file; do not document an Ocean vendor cap unless one is added to the registry.
