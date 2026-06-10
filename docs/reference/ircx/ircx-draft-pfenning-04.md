# IRCX — draft-pfenning-irc-extensions-04 (canonical reference)

> Source: IETF Internet-Draft "Extensions to the Internet Relay Chat Protocol
> (IRCX)", Pfenning/Abraham (Microsoft), July 1998.
> https://www.ietf.org/archive/id/draft-pfenning-irc-extensions-04.txt
> Captured 2026-06-05 as Orochi's authoritative IRCX reference. This is the
> normative extraction; the ophion implementation notes are in the sibling
> `ircx-protocol-ophion.md` + `m_ircx_*.md` files.

## Protocol discovery
- `MODE ISIRCX` (or `ISIRCX` / `IRCX`) → reply **800 IRCRPL_IRCX**:
  `<state> <version> <package-list> <maxmsg> <option-list>`
  - state 0=disabled / 1=enabled; version starts at 0; package-list =
    comma-separated SASL mechs; maxmsg standard 512; option-list `*` if none.
- Non-IRCX servers return an error → lets unregistered clients probe support.
- `IRCX` enables IRCX mode for the session.

## AUTH (predates CAP/SASL)
```
AUTH <name> <seq> [:<parameter>]      ; seq = I (initial) | S (subsequent) | * (abort)
AUTH <name> S [:<parameter>]          ; server: continue
AUTH <name> * <ident> <oid>           ; server: success (ident=userid@domain)
```
Ordering: if the server advertises IRCX SASL mechs, the client's FIRST message
must be AUTH (when authenticating), **before USER and NICK**.

## ACCESS
```
ACCESS <object> LIST
ACCESS <object> ADD|DELETE <level> <mask> [<timeout> [:<reason>]]
ACCESS <object> CLEAR [<level>]
```
- Levels: **DENY, GRANT, HOST, OWNER, VOICE**.
- Evaluation order: **OWNER → HOST → VOICE → GRANT → DENY**.
- Objects: channel, nickname, `$` (server), `*` (network).

## PROP (entity properties)
```
PROP <object> <prop>[,<prop>]      ; query
PROP <object> <prop> :<data>       ; set
PROP <object> <prop> :             ; delete
```
Channel properties (R/O or string/numeric, with per-visibility read/write rules):
OID(R/O), NAME(R/O,63), CREATION(R/O), LANGUAGE(31), OWNERKEY/HOSTKEY/MEMBERKEY(31,
**never readable**), PICS(255), TOPIC(160), SUBJECT(31), CLIENT(255), ONJOIN(255),
ONPART(255), LAG(0–2s), ACCOUNT(31), CLIENTGUID, SERVICEPATH.

## EVENT
```
EVENT [ADD|DELETE] <event> [<mask>]
EVENT LIST [<event>]
```
- Event types: **CHANNEL, MEMBER, SERVER, CONNECTION, SOCKET, USER**.
- Only sysops / sysop-managers may receive events.

## LISTX (extended LIST)
`LISTX [<channel list>]` or `LISTX <query list> [<query limit>]`. Query terms:
`<#`, `>#` (member count), `C<#`/`C>#` (creation age min), `L=`/`N=`/`S=`/`T=`
(language/name/subject/topic mask), `R=0`/`R=1` (un/registered), `T<#`/`T>#`
(topic-change age).

## CREATE / WHISPER / DATA
- `CREATE <channel> [<modes> [<modeargs>]]` → returns OID; modes t/n/m/l/k/c/e.
- `WHISPER <channel> <nick-list> :<message>` — sender + all recipients must be on
  the channel.
- `DATA <target> <tag> :<message>` — tag `[A-z][A-z0-9.]{0,14}`; reserved prefixes
  SYS/ADM/OWN/HST gated by privilege.

## Channel modes
Visibility (mutually exclusive): PUBLIC(default), PRIVATE +p, HIDDEN +h, SECRET +s.
Others: MODERATED +m, NOEXTERN +n, TOPICOP +t, INVITE +i, KNOCK +u, NOFORMAT +f,
NOWHISPER +w, AUDITORIUM +x, REGISTERED +r, SERVICE +z, AUTHONLY +a, CLONEABLE +d,
CLONE +e. User modes: OWNER +q (`.` prefix), GAG +z (sysop-only).

## Numerics
Replies: **800** IRCX; **801–805** ACCESS ADD/DELETE/START/LIST/END; **806–810**
EVENT ADD/DEL/START/LIST/END; **811–817** LISTX START/LIST/PICS/…/TRUNC/END;
**818** PROPLIST, **819** PROPEND.
Errors: **900** BADCOMMAND, 901 TOOMANYARGUMENTS, 902 BADFUNCTION, 903 BADLEVEL,
904 BADTAG, 905 BADPROPERTY, 906 BADVALUE, 907 RESOURCE, **908 SECURITY**,
909 ALREADYAUTHENTICATED, 910 AUTHENTICATIONFAILED, 911 AUTHENTICATIONSUSPENDED,
912 UNKNOWNPACKAGE, **913 NOACCESS**, 914 DUPACCESS, 915 MISACCESS,
916 TOOMANYACCESSES, **918 EVENTDUP**, 919 EVENTMIS, 920 NOSUCHEVENT,
921 TOOMANYEVENTS, **923 NOWHISPER**, 924 NOSUCHOBJECT, 925 NOTSUPPORTED,
926 CHANNELEXIST, 927 ALREADYONCHANNEL, 999 UNKNOWNERROR.

## Object prefixes
`#`/`&` RFC1459 global/local; `%#`/`%&` UTF8 global/local; `'` UTF8 IRCX nick;
`^` UTF8→hex display nick; `0` internal OID (8 hex); `$` server.

## Clone takeover protection
Creating a clone channel removes any same-named channel (prevents clone takeover).
