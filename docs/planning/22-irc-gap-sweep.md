# 22 — Exhaustive IRC protocol-completeness gap sweep

Read-only audit verified against actual code under `src/daemon` and `src/proto`
(handlers, enums, tables). Each item is marked **PRESENT / PARTIAL / MISSING**
with the citing file and a one-line note. This supersedes the higher-level
snapshot in `21-protocol-gaps.md` (which contains at least one factual error —
see §8 WHOX).

Standing decisions honored as **intentionally out of scope**: WEBIRC, identd /
RFC1413, STARTTLS (implicit-TLS only), IRCX AUTH packages, `+w` WALLOPS umode
(replaced by EVENT BROADCAST on the Event Spine), pseudo-client services.

## Architecture note: three numeric enums, two dispatch tiers

Verified there are **three distinct numeric enums**, each live on its own path:

1. `src/daemon/dispatch.zig` `Numeric` (~line 87) — *tiny*; only the
   preregistration + CAP + SASL set (001-005, 410/421/432/451/461/462, 900/903/904/906).
   This file IS the live preregistration/CAP/ISUPPORT path (`processLine`).
2. `src/daemon/server.zig` `Numeric` (line 615) — the *runtime* enum for
   registered-session handlers (MODE, MONITOR, METADATA, STATS, KNOCK, IRCX 8xx/9xx…).
3. `src/proto/numeric.zig` `Numeric` (line 9) — the *comprehensive* RFC/modern
   set used by the proto reply builders (WHOIS 311-319, LUSERS 251-255, ADMIN
   256-259, LINKS, VERSION 351, etc.). Note: this enum stops at 531/9xx and has
   **no 600-799 block**, but that is harmless because MONITOR/METADATA/HELP/671
   live in the server.zig enum or as raw `u16` in proto helpers.

Command dispatch: `LinuxServer.dispatchRegistered` (server.zig:2199) consults the
comptime `SerpentRegistry` (`modules/manifest.zig` → `Live.dispatch`) first, then
OroWasm plugins, then a residual block (SUMMON/PONG) and finally falls through
to `dispatch.zig processLine` for preregistration commands.

---

## 1. Client COMMANDS

Command tables: `src/daemon/modules/*.zig`; preregistration in `dispatch.zig`;
residual in `server.zig:2264`.

### Connection / preregistration (dispatch.zig)
- **NICK / USER / PASS** — PRESENT — dispatch.zig (prereg pipeline).
- **CAP (LS/REQ/ACK/NAK/END, 302)** — PRESENT — dispatch.zig `CapSession`.
- **AUTHENTICATE** — PARTIAL — dispatch.zig:943; only **PLAIN** wired. EXTERNAL/SCRAM exist in `proto/sasl_*` but are not advertised or routed.
- **PING / PONG** — PRESENT — server.zig:936/2180/2269 (inline).
- **QUIT** — PRESENT — `user_query.zig` + inline (server.zig:2174).

### Server info / query (`modules/query_info.zig`)
- ADMIN, INFO, LUSERS, USERS, MOTD, TIME, VERSION, LINKS, MAP — all **PRESENT**.

### User query / identity (`modules/user_query.zig`)
- WHOIS, WHO, WHOWAS, LIST, ISON, USERHOST, AWAY, SETNAME, NICK, ACCEPT, HELP/HELPOP, AUTOJOIN, GROUP, WELCOME — all **PRESENT**.
- **WHOWAS** — PRESENT — backed by `whowas.zig` store.
- **SILENCE** — PRESENT — but lives in `messaging.zig`, not user_query (handler server.zig:3988, numerics 271/272).
- **MONITOR** — PRESENT — `messaging.zig` (730-734).
- **WATCH** — MISSING (intentional) — legacy; MONITOR is the modern replacement. Note as deliberately omitted.

### Channel ops (`modules/channel_ops.zig`)
- JOIN, PART, NAMES, MODE, KICK, INVITE, TOPIC, KNOCK, CREATE, RENAME — all **PRESENT**.

### Messaging (`modules/messaging.zig`)
- PRIVMSG, NOTICE, TAGMSG, REDACT, CHATHISTORY, MARKREAD, METADATA, MONITOR, SILENCE — all **PRESENT**.

### Oper / network (`modules/oper_security.zig`)
- OPER, REHASH, KILL, CLOSE, DRAIN, UNREJECT, WARD, SHUN/UNSHUN, GLOBAL, OPERMOTD, DIE, RESTART, CONNECT, SQUIT, TRACE, ETRACE, STATS, TESTLINE, TESTMASK, USERIP, DEBUG — all **PRESENT**.
- **WALLOPS** — MISSING (intentional) — replaced by `EVENT BROADCAST` on the Event Spine (server.zig:5120).

### Accounts / services (`modules/accounts.zig`)
- REGISTER, VERIFY, IDENTIFY, LOGOUT, DROP, ACCOUNTINFO, SASLINFO, ACCOUNTSET, GHOST, CHANNEL/CS, SESSION — all **PRESENT**.

### Feature / misc (`modules/feature_misc.zig`)
- VHOST, PRIVS, FILTER, MEDIA, TEGAMI, ACTIVITY — all **PRESENT**.

### Diagnostics / ops
- MODULES/MODLIST — PRESENT — `introspect.zig`.
- UPGRADE — PRESENT — `upgrade.zig`.

### Missing standard commands
- **SUMMON** — PARTIAL — stubbed to ERR_SUMMONDISABLED (server.zig:2266). Correct modern behavior.
- **CHGHOST** (command) — N/A — CHGHOST is a *server→client* notify (cap), not a client command; emitted via VHOST. PRESENT as notify.
- No gaps among the requested set besides WATCH (intentional) and WALLOPS (intentional).

---

## 2. NUMERICS

- **Runtime enum** (server.zig:615): broad but **selective** — only codes a
  handler actually emits. PRESENT families: STATS subset, MONITOR (730-734),
  METADATA (761/762/766/767/769), KNOCK (710/711/713/714), TESTLINE (725-727),
  QUIET (728/729), SILENCE (271/272), IRCX 800 + 9xx taxonomy, MAP (15/17).
- **WHOIS family (311-319, 330, 338, 378)** — PRESENT — emitted via `proto/numeric.zig` from `whois.zig`/`whois_extra.zig`.
- **RPL_WHOISSECURE (671)** — PRESENT — `proto/whois_extra.zig:18` (raw u16).
- **LUSERS family (251-255, 265/266)** — PRESENT — `proto/numeric.zig` + `proto/lusers.zig`.
- **ADMIN (256-259), INFO (371/373/374), TIME (391), VERSION (351)** — PRESENT — `proto/numeric.zig`, verified by integration tests (server.zig:9077-9089).
- **LINKS (364/365), MAP (15/16/17)** — PRESENT.
- **USERHOST (302), ISON (303), AWAY (301/305/306)** — PRESENT — `proto/numeric.zig` / `ison_userhost.zig`.
- **Standard-replies (FAIL/WARN/NOTE)** — PRESENT — emitted as raw lines (server.zig:7537, `proto/standard_replies_emit.zig`); not numeric codes (correct — they are not numerics).
- **HELP (704/705/706, 524)** — PRESENT — server.zig:5815.
- **Gap:** `proto/numeric.zig` itself lacks the 600-799 modern block, but no live
  caller needs it there (handled by the other two enums). MISSING-but-harmless.
  Should consolidate eventually for maintainability.

---

## 3. CHANNEL MODES

ISUPPORT advertises `CHANMODES=beIZ,k,lfj,imnstCTNMSgWOA`
(`src/proto/protocol_inventory.zig:56`). Implementation is split between the
generic channel-mode catalog and live server/world handlers.

Group A (list): `b` ban, `e` exempt, `I` invex, `Z` quiet/mute — **PRESENT**.

Group B (param always): `k` key — **PRESENT**.

Group C (param when set): `l` limit, `f` forward, `j` join throttle —
**PRESENT**.

Group D (flag): `i m n s t C T N M S g W O A` — all **PRESENT**.

Previous false-advertising notes for `Z`/`f`/`j`/`O`/`A` are resolved in current
source: the advertised token and live handlers now agree.

---

## 4. USER MODES

`src/proto/usermode.zig` `UserMode` enum (`u4`, 10/16 used):
- `i` invisible, `B` bot, `r` registered, `z` secure-tls, `D` deaf, `g` callerid,
  `C` no-ctcp, `x` cloaked, `R` regonly-pm, `p` hide-chans — all **PRESENT**.
- **`o` oper** — PARTIAL — operator status is tracked on the session
  (`session.isOper`), elevated via OPER, and surfaced (RPL_YOUREOPER/WHOIS 313),
  but is **not a `UserMode` enum entry** — there is no `+o` in RPL_UMODEIS. Minor
  conformance gap (clients reading umode string won't see `o`).
- **`s` server-notices** — MISSING — snomask handled via separate `snomask.zig` /
  Event Spine, not a umode. Intentional per Event-Spine design.
- **`w` wallops** — MISSING (intentional) — Event Spine.
- 6 enum slots remain free (`u4`), so adding `o` is cheap if desired.

---

## 5. CHANTYPES / channel prefixes

- ISUPPORT advertises `CHANTYPES=#` (dispatch.zig:1048).
- `world.isChannelName` (world.zig:860) accepts **`#`, `&`, `%#`, `%&`** — i.e.
  more than advertised. **MISMATCH** — PARTIAL.
  - **`&`** local channels — accepted by parser but **not advertised** → clients won't offer them. Either advertise `CHANTYPES=#&` or drop `&` from the parser.
  - **`%#`/`%&`** — a Orochi-specific membership/UTF8 prefix accepted by the parser, also unadvertised.
- IRCX-specific prefixes (`%` UTF8/quiet-style, `!` safe-channel) — `!` not handled; `%` handled non-standardly. PARTIAL.
- **Action:** reconcile parser ↔ ISUPPORT (low effort, real interop value).

---

## 6. PREFIX / STATUSMSG

- `PREFIX=(Qqov)~.@+` — PRESENT — `chanmode.zig:312` `isupport_prefix` matches ISUPPORT exactly. `MemberMode` is `u3`.
- `STATUSMSG=~.@+` — PRESENT — dispatch.zig:1048.
- Verified consistent. No gap.

---

## 7. EXTBANS

ISUPPORT `EXTBAN=$,acgr` (dispatch.zig:1048). Engine: `proto/extban.zig` +
`proto/extban_eval.zig` (`NodeKind`: hostmask, account, realname, country,
channel, negation).
- **`$a` account** — PRESENT (extban.zig:136).
- **`$r` realname/gecos** — PRESENT (covers the usual `$x` gecos too).
- **`$g`** — PARTIAL — mapped to **geoip country**, not the standard "gateway/
  real-host" meaning. Advertised as `g`; semantics differ from other ircds.
- **`$c` channel** (in-channel) — PRESENT.
- **`~` negation** — PRESENT (extban_eval.zig:59).
- **MISSING standard extbans:**
  - `$m` / mute-quiet **action extbans** (the most-used one) — MISSING.
  - `$z` / `$s` secure-TLS-only ban — MISSING.
  - `$o` oper exemption — MISSING.
  - `$j` join-channel ("banned if in #x") — partially overlaps `$c`; the
    enforce-join variant MISSING.
  - join-time / `$~` complex combinators beyond single negation — MISSING.
- **Action:** `$m` (mute) is the highest-value addition; then `$z`. Both fit the
  existing matcher (`appendNode` in extban.zig:144).

---

## 8. IRCv3 CAPS

Cap table: `dispatch.zig:168` (`CapId`, `u6`) + `cap_specs` (line 217).

**PRESENT (advertised + backed):** server-time, message-tags, echo-message,
sasl (PLAIN only), multi-prefix, userhost-in-names, away-notify, setname,
extended-join, invite-notify, account-tag, account-notify, chghost,
no-implicit-names, batch, bot, extended-monitor, channel-rename (draft),
orochi/bouncer, draft/chathistory, draft/message-redaction, draft/read-marker,
draft/typing, draft/react, draft/reply.

**Closed since this sweep:** `cap-notify`, `labeled-response`, config-gated
`sts`, `standard-replies`, `draft/account-registration`, `draft/metadata-2`,
`draft/multiline`, and `sasl=PLAIN,EXTERNAL,SCRAM-SHA-256` are all advertised
from the live `src/daemon/dispatch.zig` cap table.

**Remaining caps / optional compat:**
1. **utf8only** — enforced + advertised via **ISUPPORT `UTF8ONLY`**, but not as
   a separate IRCv3 cap. Acceptable (ISUPPORT is the ratified surface).
2. **soju.im/* (bouncer-networks etc.)** — MISSING — `orochi/bouncer` is the
   native analogue; soju compat not provided. Optional.
3. **draft/event-playback** — MISSING — chathistory present; event-playback not.
   Optional.

CapId enum is `u6` (64 slots), 36 used — ample headroom.

---

## 9. IRCX

Commands (`modules/ircx.zig`): IRCX, ISIRCX, DATA, REQUEST, REPLY, WHISPER, PROP,
ACCESS, EVENT, MODEX, LISTX — all **PRESENT**. CREATE lives in channel_ops.

- **PROP entity providers** (`proto/ircx_prop_providers.zig:122`) — PRESENT —
  account, member_of, onjoin, onpart, opkey, ownerkey, user_profile,
  creation_time, topic_setter. PARTIAL vs Exchange chatsvc ref: missing
  `language`, `client`/OID, `subject`, `lag`, per-object `memberkey`/`hostkey`
  distinct from opkey/ownerkey. Enumerate against MEMORY `project_exchange_chat_re`.
- **ACCESS levels** (`proto/ircx_access_store.zig:76`) — PRESENT — OWNER, HOST,
  VOICE, GRANT, DENY with precedence; verbs ADD/DELETE/LIST/CLEAR
  (`ircx_saccess.zig:122`). Server-level SACCESS adds GAG/NOCHANNEL/NONICK
  (ircx_saccess.zig:486-500). Looks complete.
- **EVENT categories** (`proto/ircx_event_cmd.zig`) — PRESENT — ADD/DEL/LIST over
  `event_spine.EventCategory` mask; token+code lookup. Mapped onto the Event Spine.
- **LISTX filters** (`proto/listx.zig`) — PRESENT — mask, topic-age (`T>`/`T<`),
  member-count (`N>`/`N<`), created; numerics 811+ (RPL_LISTXSTART). Looks complete.
- **IRCX numerics** — PRESENT — 800 RPL_IRCX, 801-805 ACCESS, 818/819 PROP,
  820/821 MODEX (ircx.zig:422, ircx_modex.zig:14), 9xx error taxonomy
  (server.zig:705-718: 900/903/905/907/908/912-916/924-927, 913 NOACCESS, 923
  NOWHISPER). PARTIAL: verify full 9xx set vs Exchange ref (e.g. 911/917/918/919/
  920-922 not all defined). Inert-until-emitted by design.
- **`+h` HIDDEN / auditorium / nowhisper** — PRESENT — `chanmode_ext.zig` MODEX flags.

**Out of scope (decisions):** IRCX AUTH packages (GateKeeper/Passport/ANON),
WEBIRC, identd, STARTTLS.

---

## PRIORITY-ORDERED IMPLEMENTATION BACKLOG

Ordered by client value; grouped into parallel waves (items in a wave are
independent and can be fanned out to separate workers).

### Wave 1 — cheap high-value cap/ISUPPORT truthfulness (no new state)
1. **Advertise `draft/account-registration` cap + ISUPPORT token** — DONE.
2. **Advertise `draft/metadata-2` cap + notify** — DONE.
3. **Advertise `standard-replies` cap** — DONE.
4. **Fix CHANMODES false-advertising** — DONE; live token is `CHANMODES=beIZ,k,lfj,imnstCTNMSgWOA`.
5. **Reconcile CHANTYPES vs isChannelName** — advertise `&` (and decide on `%`) or stop accepting them. (dispatch.zig:1048 vs world.zig:860)

### Wave 2 — foundational caps (unlock later features)
6. **cap-notify** — DONE for the static cap set; CAP NEW/DEL do not fire because the set is static.
7. **labeled-response + `label` tag echo** — DONE.
8. **STS policy cap** — DONE; advertised only when an STS policy is configured and live.

### Wave 3 — moderation / matching depth
9. **`$m` mute/quiet action-extban** — highest-value extban; matcher extensible. (extban.zig:144)
10. **`$z` secure-TLS extban** — (extban.zig)
11. **Channel modes `+f` forward, `+j` join-throttle** — DONE.
12. **`+o` user mode entry** — add to `usermode.zig` so RPL_UMODEIS reflects oper. (usermode.zig:11; 6 free slots)

### Wave 4 — SASL + multiline + numerics hygiene
13. **SASL EXTERNAL (certfp)** — DONE; advertised in `sasl=PLAIN,EXTERNAL,SCRAM-SHA-256`.
14. **SASL SCRAM-SHA-256** — DONE; advertised in the same cap value.
15. **draft/multiline** — DONE.
16. **Consolidate the three numeric enums** — fold 600-799 into `proto/numeric.zig` to remove drift risk. (maintainability, not conformance)

### Wave 5 — IRCX completeness (lower client value)
17. **PROP provider parity** vs Exchange chatsvc — add language/client-OID/subject/lag/memberkey/hostkey. (ircx_prop_providers.zig:122)
18. **IRCX 9xx numeric conformance sweep** vs recovered Exchange/OfficeIRC ref. (server.zig 9xx; ircx.zig:422)

### Biggest gaps (one-line)
- **CHANMODES `Z`/`f`/`j`/`W`/`O`/`A` are now advertised consistently with live handlers** — previous false-advertising item is closed.
- **cap-notify, labeled-response, STS are now advertised from the live CAP table** — previous Wave 2 item is closed.
- **REGISTER/VERIFY + METADATA caps are now discoverable** — previous Wave 1 item is closed.
- **SASL now advertises PLAIN, EXTERNAL, and SCRAM-SHA-256** — previous Wave 4 item is closed.
- **CHANTYPES parser/ISUPPORT mismatch** (`&`/`%` accepted, only `#` advertised) — Wave 1.
