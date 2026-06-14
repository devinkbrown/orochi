# 21 — IRCv3 + IRCX protocol gap audit

Snapshot of what's implemented vs. missing across the two client-facing protocol
surfaces, with a priority order. In-scope items respect the standing decisions:
**no WEBIRC, no identd, no STARTTLS (implicit-TLS/modern only), oper is SASL-only,
services are real server commands.** Legacy IRCX auth packages and STARTTLS are
therefore intentionally out of scope.

## IRCv3 — implemented capabilities
server-time, message-tags, echo-message, sasl (PLAIN/EXTERNAL/SCRAM-SHA-256), multi-prefix,
userhost-in-names, away-notify, setname, extended-join, invite-notify,
account-tag, account-notify, chghost, no-implicit-names, batch, bot,
extended-monitor, orochi/bouncer, and drafts: chathistory, message-redaction,
read-marker, typing, react, reply, channel-rename, multiline. WHOX,
cap-notify, labeled-response, and config-gated STS are also live.

Commands live: CAP, AUTHENTICATE, NICK/USER, METADATA, MONITOR, TAGMSG, REGISTER,
VERIFY, SETNAME, REDACT, MARKREAD, CHATHISTORY, account family.

## IRCv3 — gaps (priority order)

1. **WHOX** (extended WHO, `RPL_WHOSPCRPL` 354) — DONE.
2. **cap-notify** — DONE for the current static cap set; CAP NEW/DEL do not fire
   because the live cap set is static.
3. **labeled-response** (+ `label` tag echo, batch wrapping) — DONE.
4. **draft/account-registration cap** — DONE; REGISTER/VERIFY are live and the
   cap is advertised.
5. **draft/metadata-2 cap** — DONE; METADATA is live and the cap is advertised.
6. **STS** (strict transport security policy cap) — DONE when an operator enables
   an STS policy and a TLS listener is live; omitted otherwise.
7. **draft/multiline** — DONE; advertised with byte/line limits and wired through
   batch reassembly.
8. **standard-replies cap advertise** — DONE; FAIL/WARN/NOTE are emitted and the
   cap is advertised.

Out of scope (standing decisions): STARTTLS, WEBIRC.

## IRCX — implemented
IRCX, ISIRCX, DATA/REQUEST/REPLY, WHISPER, PROP, ACCESS, EVENT, MODEX, LISTX;
PREFIX=(Qqov)~.@+, channel props, Event-Spine model, +h HIDDEN, extbans.

## IRCX — gaps (priority order)

1. **PROP entity providers** — DONE. Computed providers: channel
   NAME/OID/CREATION/MEMBERCOUNT/MEMBERLIMIT and user MEMBER_OF + ACCOUNT (the
   account provider was the last genuine gap, added 2026-06-14 in `userBuiltinGet`).
   onjoin/onpart/opkey(HOSTKEY)/ownerkey(OWNERKEY) exist as stored props with
   proper access tiers. `user_profile` deferred (no canonical data source).
2. **LISTX filter completeness** — DONE (2026-06-14). The handler now feeds the
   matcher real channel data for every filter — `<mask>`, name/topic/subject/
   language masks, `C`/`T` age thresholds (wall-clock ms), member-count, and
   `R=` registered — plus an `816 RPL_LISTXTRUNC` cap. Engine (`listx.zig`) was
   already complete; the gap was handler wiring.
3. **ACCESS level coverage** — DONE/confirmed. `handleAccess` supports list/add/
   delete/clear over FOUNDER/OWNER/HOST/VOICE/GRANT/DENY with tiered auth
   (`accessCanManage`), numerics 801-805 + 913-916, and JOIN-time DENY (474) /
   GRANT auto-status enforcement (`matchHostmask`). No gap found.
4. **IRCX numeric conformance sweep** — re-verify the IRCX numeric set against the
   recovered Exchange/OfficeIRC reference for any missing replies. (Still open: a
   research sweep against the chatsvc RE, distinct from the now-complete ACCESS
   numeric set above.)

Out of scope: IRCX AUTH packages (GateKeeper/Passport/ANON) — legacy auth, replaced
by SASL.

## Plan
The original high-value IRCv3 sweep items above are now closed for WHOX,
cap-notify, labeled-response, STS, multiline, account-registration,
metadata-2, and standard-replies. Remaining protocol gap work starts with
newer draft/spec compatibility rather than those completed items.
