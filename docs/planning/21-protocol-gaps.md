# 21 — IRCv3 + IRCX protocol gap audit

Snapshot of what's implemented vs. missing across the two client-facing protocol
surfaces, with a priority order. In-scope items respect the standing decisions:
**no WEBIRC, no identd, no STARTTLS (implicit-TLS/modern only), oper is SASL-only,
services are real server commands.** Legacy IRCX auth packages and STARTTLS are
therefore intentionally out of scope.

## IRCv3 — implemented capabilities
server-time, message-tags, echo-message, sasl (PLAIN), multi-prefix,
userhost-in-names, away-notify, setname, extended-join, invite-notify,
account-tag, account-notify, chghost, no-implicit-names, batch, bot,
extended-monitor, orochi/bouncer, and drafts: chathistory, message-redaction,
read-marker, typing, react, reply, channel-rename.

Commands live: CAP, AUTHENTICATE, NICK/USER, METADATA, MONITOR, TAGMSG, REGISTER,
VERIFY, SETNAME, REDACT, MARKREAD, CHATHISTORY, account family.

## IRCv3 — gaps (priority order)

1. **WHOX** (extended WHO, `RPL_WHOSPCRPL` 354) — ABSENT. Widely used by modern
   clients/bots for field-selective WHO (`%tcuihsnfdlaor`). High value, self-
   contained (parser + formatter + WHO wiring). **← starting here.**
2. **cap-notify + CAP NEW/DEL** — ABSENT. Runtime cap advertisement; many clients
   assume it. Foundational for later dynamic caps. Small.
3. **labeled-response** (+ `label` tag echo, batch wrapping) — ABSENT. Lets clients
   correlate responses to requests; pairs with the present `batch` cap.
4. **draft/account-registration cap** — commands (REGISTER/VERIFY) exist but the
   cap isn't advertised, so compliant clients don't surface registration. Cheap.
5. **draft/metadata-2 cap** — METADATA command exists but the cap/notify surface
   isn't advertised. Cheap-ish.
6. **STS** (strict transport security policy cap) — modern TLS posture; advertise
   policy so clients pin TLS. Fits the implicit-TLS stance.
7. **draft/multiline** — multiline messages via batch. Lower priority.
8. **standard-replies cap advertise** — FAIL/WARN/NOTE are emitted; advertising the
   cap is informational. Trivial.

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
Work top-down on the IRCv3 list (highest client value), then the IRCX PROP-provider
completeness. Each item ships as its own green + tested increment. Starting with
WHOX now.
