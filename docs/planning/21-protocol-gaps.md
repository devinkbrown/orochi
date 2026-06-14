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

1. **PROP entity providers** — per the IRCX draft, PROP should expose entity
   property providers (account / member_of / onjoin / onpart / opkey / ownerkey /
   user_profile) on `ircx_prop_store`. Partial; enumerate + fill the missing ones.
2. **LISTX filter completeness** — verify all IRCX LISTX filter tokens
   (`<mask>`, `T>`/`T<` topic-age, `N>`/`N<` member-count, `C`reated) are honored.
3. **ACCESS level coverage** — confirm OWNER/HOST/VOICE/GRANT/DENY + DELETE/CLEAR
   verbs and the IRCX access numerics are complete vs. the Exchange chatsvc ref.
4. **IRCX numeric conformance sweep** — re-verify the IRCX numeric set against the
   recovered Exchange/OfficeIRC reference for any missing replies.

Out of scope: IRCX AUTH packages (GateKeeper/Passport/ANON) — legacy auth, replaced
by SASL.

## Plan
The original high-value IRCv3 sweep items above are now closed for WHOX,
cap-notify, labeled-response, STS, multiline, account-registration,
metadata-2, and standard-replies. Remaining protocol gap work starts with
newer draft/spec compatibility rather than those completed items.
