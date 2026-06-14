# IRCX draft conformance — Orochi implementation status

> Heavy gap analysis of draft-pfenning-irc-extensions-04 vs Orochi's live
> daemon. Clean-room ("our design"): we implement the draft's *semantics*, using
> Orochi's identity/mode model where it deliberately improves on the draft
> (founder +Q, WALLOPS→Event-Spine, node_id identity, conformant numerics).
> Status: ✅ done · 🟡 partial · ❌ missing. Goal: drive ❌/🟡 → ✅.

## Progress (2026-06-05 conformance pass)
Now ✅ live: IRCX/ISIRCX/MODE-ISIRCX gateway + RPL_IRCX 800 (pre- & post-reg);
LISTX (811/812/817); DATA/REQUEST/REPLY tag messaging (904 + SYS/ADM/OWN/HST
gating); AUTHONLY +a JOIN block (477); +z GAG (oper-set, silent drop);
MEMBERKEY↔+k & MEMBERLIMIT↔+l PROP built-ins (+ NAME/MEMBERCOUNT computed);
numerics fixed (PROP 913, MODEX 820/821). **Remaining**: CLONEABLE/CLONE
auto-clone + takeover protection; OID; UTF8 IRCX prefixes; EVENT numeric/type
alignment decision; fill residual 9xx error set.

## Discovery & session
| Feature | Status | Notes |
| --- | --- | --- |
| `IRCX` (enable) → 800 RPL_IRCX | ✅ | live gateway and reply path |
| `ISIRCX` / `MODE ISIRCX` (query) → 800 | ✅ | live discovery path |
| 800 `<state> <version> <pkgs> <maxmsg> <opts>` | ✅ | live `RPL_IRCX` builder/emitter |
| session IRCX opt-in bit | ✅ | live per-session IRCX state gates IRCX behavior |

## Commands
| Cmd | Status | Notes |
| --- | --- | --- |
| AUTH (IRCX legacy SASL) | 🟡 | Orochi uses IRCv3 SASL (CAP/AUTHENTICATE); ircx_auth lib exists. Deliberate: CAP path primary. |
| ACCESS (801–805, OWNER/HOST/VOICE/GRANT/DENY) | ✅ | live, channel-op gated; OWNER needs owner/founder |
| PROP (818/819) | ✅ | live; secret-key read filter; denial 913 |
| EVENT (806–810, types CHANNEL/MEMBER/…) | 🟡 | Deliberate divergence: ADD/DEL/LIST run over the native Event-Spine taxonomy (richer than the draft's CHANNEL/MEMBER types), matching the locked WALLOPS/snomask→Event-Spine design. Draft 806–810 numerics are intentionally not emitted; this is a settled design choice, not an open gap. |
| LISTX (811–817 + query terms) | ✅ | live dispatch + filters match real channel data (name/topic/subject/language masks, `C`/`T` ages, `R=`), 816 truncation cap |
| CREATE (returns OID) | 🟡 | Deliberate: create-or-join founder semantics; the channel OID is a computed built-in queryable via `PROP <#chan> OID`, not echoed on CREATE (no Orochi numeric for it). Settled design choice. |
| WHISPER (+w/923) | ✅ | live, member-gated |
| DATA / REQUEST / REPLY (tag messaging) | ✅ | live tag messaging with SYS/ADM/OWN/HST prefix gating |
| KNOCK | ✅ | live (713/711) |

## Channel modes (stored vs enforced)
| Mode | Stored | Enforced | Notes |
| --- | --- | --- | --- |
| PUBLIC/PRIVATE +p / HIDDEN +h / SECRET +s | ✅ | 🟡 | +s/+p affect NAMES/LIST visibility; verify PRIVATE/HIDDEN query rules |
| MODERATED +m / NOEXTERN +n / TOPICOP +t / INVITE +i | ✅ | ✅ | base enforcement live |
| KNOCK +u | ✅ | ✅ | KNOCK accepted when `+i` or `+u`; otherwise open-channel rejection applies |
| NOFORMAT +f | ✅ | ✅ | settable/rendered; channel delivery strips formatting |
| NOWHISPER +w | ✅ | ✅ | enforced in WHISPER |
| AUDITORIUM +x | ✅ | ✅ | enforced NAMES/JOIN/PART |
| AUTHONLY +a | ✅ | ✅ | blocks unauthenticated JOIN with numeric 477 |
| CLONEABLE +d / CLONE +E | ✅ | ❌ | auto-clone-on-full + clone-takeover protection — implement |
| REGISTERED +r / SERVICE +z | ✅ | ❌ | oper/services-set; semantics TBD |

## Objects / identity
| Feature | Status | Notes |
| --- | --- | --- |
| OID (8-hex object ids; `0` prefix) | ❌ | CREATE/PROP OID; decide if Orochi adopts OIDs or uses node-scoped ids |
| UTF8 chan/nick (`%#`, `'`, `^` prefixes) | ❌ | UTF8ONLY cap exists; full IRCX UTF8 prefixing not done |
| Object types for ACCESS (`$` server, `*` net) | 🟡 | channel/nick yes; server/network scope TBD |

## User modes (umodes)
| Draft umode | Orochi | Notes |
| --- | --- | --- |
| +q OWNER (`.` prefix) | ✅ (as member mode) | Orochi models owner as a *channel member* mode (+q owner `.`), plus founder +Q `~` above it — cleaner than a umode. Deliberate divergence. |
| +z GAG (sysop-only; server drops user's msgs) | ✅ | oper-set; silently drops gagged user's PRIVMSG/NOTICE |
| (Orochi-native) +o oper | ✅ | RPL_UMODEIS reflects +o (item 90) |
| (Orochi-native) +i invisible / +B bot / +r registered / +Z secure-tls / +D deaf / +g callerid / +T no-ctcp / +x cloaked | ✅ | richer than the draft; our design |

## Behaviors
| Behavior | Status | Notes |
| --- | --- | --- |
| AUDITORIUM +x visibility/relay | ✅ | NAMES + JOIN + PART relay gating |
| Clone takeover protection (CREATE clone removes same-name) | ❌ | with CLONEABLE/CLONE |
| AUTHONLY +a blocks unauth JOIN | ✅ | live JOIN gate returns 477 |
| KNOCK notify owner/host on +i reject | 🟡 | KNOCK cmd live; tie to +i/+u |
| NOFORMAT +f raw display | ❌ | largely client-side; mark relay tag |
| Backward compat (RFC1459 clients unaffected) | ✅ | IRCX is opt-in; base IRC always works |
| UTF8 escape sequences in IRCX strings | 🟡 | UTF8ONLY cap; full escape handling TBD |

## Numerics (errors 900–927)
🟡 — Orochi maps a subset to its own enum. Conformant where it matters
(NOWHISPER 923, NOACCESS 913). Audit/add: 900 BADCOMMAND, 903 BADLEVEL,
905 BADPROPERTY, 906 BADVALUE, 907 RESOURCE, 908 SECURITY, 912 UNKNOWNPACKAGE,
914 DUPACCESS, 915 MISACCESS, 916 TOOMANYACCESSES, 918–921 EVENT*, 924 NOSUCHOBJECT,
925 NOTSUPPORTED, 926 CHANNELEXIST, 927 ALREADYONCHANNEL.

## Implementation order (this conformance pass)
1. **IRCX/ISIRCX gateway + 800 RPL_IRCX** — DONE.
2. **LISTX** dispatch — DONE.
3. **AUTHONLY +a** JOIN enforcement; **KNOCK +u** gating — DONE.
4. **DATA/REQUEST/REPLY** tag messaging + reserved-prefix gating — DONE.
5. **CLONEABLE/CLONE** auto-clone + takeover protection.
6. EVENT numeric/type alignment decision; OID decision; UTF8 IRCX prefixes.
7. Fill the IRCX error-numeric set.

## Locked decisions (task #20, 2026-06-05) and status

These resolve the six open questions from `docs/planning/14-ircx-remainder.md`.

| # | Decision | Status |
|---|----------|--------|
| 6a KNOCK gating | **Additive** — KNOCK accepted when `+i` OR `+u`; neither ⇒ 713 open. | ✅ DONE (`handleKnock`) |
| 5 9xx numerics | **Adopt** the IRCX error taxonomy in the live `Numeric` enum (inert until emitted). | ✅ DONE (900/903/905/907/908/912/914/915/916/924/925/926/927) |
| 6b NOFORMAT `+f` | **Advertise-only (path A)** — `+f` is settable and rendered in MODE; clients strip formatting. No relay/tag change. | ✅ satisfied by existing ext-MODE rendering |
| 4 EVENT | **Document the Event-Spine divergence (path B)** — Orochi keeps the richer native event taxonomy (matches WALLOPS→Event-Spine); does not force-map 806–810/918–921. | 🟡 documented; native taxonomy stands |
| 2 OID | **Adopt** real per-channel OIDs (8-hex, `0` prefix) + `World.next_oid`; CREATION timestamp follows. | ⬜ remaining (centralized in `world.ensureChannel`; clock threading for CREATION) |
| 1 CLONEABLE/CLONE | **Adopt**, takeover **oper-only**; clone copies limit/key/modes into a `+E` `#chan<n>`. | ⬜ remaining (hot JOIN path `joinOne`; 926/927 now available) |
| 3 UTF8 prefixes | **Do `%#`/`%&`/`&`/`'` first; DEFER `^`→hex** display (needs a transliteration layer) to a separate task. | ⬜ remaining (broad: `world.isChannelName` + ~8 callers) |
