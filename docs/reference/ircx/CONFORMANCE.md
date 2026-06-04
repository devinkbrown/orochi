# IRCX draft conformance — Mizuchi implementation status

> Heavy gap analysis of draft-pfenning-irc-extensions-04 vs Mizuchi's live
> daemon. Clean-room ("our design"): we implement the draft's *semantics*, using
> Mizuchi's identity/mode model where it deliberately improves on the draft
> (founder +Q, WALLOPS→Event-Spine, node_id identity, conformant numerics).
> Status: ✅ done · 🟡 partial · ❌ missing. Goal: drive ❌/🟡 → ✅.

## Discovery & session
| Feature | Status | Notes |
| --- | --- | --- |
| `IRCX` (enable) → 800 RPL_IRCX | ❌ | gateway missing; implement first |
| `ISIRCX` / `MODE ISIRCX` (query) → 800 | ❌ | discovery; implement first |
| 800 `<state> <version> <pkgs> <maxmsg> <opts>` | ❌ | no 800 builder yet |
| session IRCX opt-in bit | ❌ | add `ircx` to ConnState; gate via ircx_gate |

## Commands
| Cmd | Status | Notes |
| --- | --- | --- |
| AUTH (IRCX legacy SASL) | 🟡 | Mizuchi uses IRCv3 SASL (CAP/AUTHENTICATE); ircx_auth lib exists. Deliberate: CAP path primary. |
| ACCESS (801–805, OWNER/HOST/VOICE/GRANT/DENY) | ✅ | live, channel-op gated; OWNER needs owner/founder |
| PROP (818/819) | ✅ | live; secret-key read filter; denial 913 |
| EVENT (806–810, types CHANNEL/MEMBER/…) | 🟡 | wired ADD/DEL/LIST over Event-Spine categories; numerics+types not draft-aligned (decide: conform vs document divergence) |
| LISTX (811–817 + query terms) | ❌ | listx.zig builder exists but NOT dispatched — wire it |
| CREATE (returns OID) | 🟡 | live as create-or-join founder; no OID returned |
| WHISPER (+w/923) | ✅ | live, member-gated |
| DATA / REQUEST / REPLY (tag messaging) | ❌ | not implemented; SYS/ADM/OWN/HST prefix gating |
| KNOCK | ✅ | live (713/711) |

## Channel modes (stored vs enforced)
| Mode | Stored | Enforced | Notes |
| --- | --- | --- | --- |
| PUBLIC/PRIVATE +p / HIDDEN +h / SECRET +s | ✅ | 🟡 | +s/+p affect NAMES/LIST visibility; verify PRIVATE/HIDDEN query rules |
| MODERATED +m / NOEXTERN +n / TOPICOP +t / INVITE +i | ✅ | ✅ | base enforcement live |
| KNOCK +u | 🟡 | ❌ | flag stored (chanmode_ext); KNOCK cmd live but +u gating? |
| NOFORMAT +f | ✅ | ❌ | stored; no display-format effect (client-side mostly) |
| NOWHISPER +w | ✅ | ✅ | enforced in WHISPER |
| AUDITORIUM +x | ✅ | ✅ | enforced NAMES/JOIN/PART |
| AUTHONLY +a | ✅ | ❌ | **must block unauthenticated JOIN** — implement |
| CLONEABLE +d / CLONE +E | ✅ | ❌ | auto-clone-on-full + clone-takeover protection — implement |
| REGISTERED +r / SERVICE +z | ✅ | ❌ | oper/services-set; semantics TBD |

## Objects / identity
| Feature | Status | Notes |
| --- | --- | --- |
| OID (8-hex object ids; `0` prefix) | ❌ | CREATE/PROP OID; decide if Mizuchi adopts OIDs or uses node-scoped ids |
| UTF8 chan/nick (`%#`, `'`, `^` prefixes) | ❌ | UTF8ONLY cap exists; full IRCX UTF8 prefixing not done |
| Object types for ACCESS (`$` server, `*` net) | 🟡 | channel/nick yes; server/network scope TBD |

## User modes (umodes)
| Draft umode | Mizuchi | Notes |
| --- | --- | --- |
| +q OWNER (`.` prefix) | ✅ (as member mode) | Mizuchi models owner as a *channel member* mode (+q owner `.`), plus founder +Q `~` above it — cleaner than a umode. Deliberate divergence. |
| +z GAG (sysop-only; server drops user's msgs) | ❌ | add as an oper tool (silently drop a user's PRIVMSG/NOTICE) |
| (Mizuchi-native) +o oper | ✅ | RPL_UMODEIS reflects +o (item 90) |
| (Mizuchi-native) +i invisible / +B bot / +r registered / +Z secure-tls / +D deaf / +g callerid / +T no-ctcp / +x cloaked | ✅ | richer than the draft; our design |

## Behaviors
| Behavior | Status | Notes |
| --- | --- | --- |
| AUDITORIUM +x visibility/relay | ✅ | NAMES + JOIN + PART relay gating |
| Clone takeover protection (CREATE clone removes same-name) | ❌ | with CLONEABLE/CLONE |
| AUTHONLY +a blocks unauth JOIN | ❌ | implement |
| KNOCK notify owner/host on +i reject | 🟡 | KNOCK cmd live; tie to +i/+u |
| NOFORMAT +f raw display | ❌ | largely client-side; mark relay tag |
| Backward compat (RFC1459 clients unaffected) | ✅ | IRCX is opt-in; base IRC always works |
| UTF8 escape sequences in IRCX strings | 🟡 | UTF8ONLY cap; full escape handling TBD |

## Numerics (errors 900–927)
🟡 — Mizuchi maps a subset to its own enum. Conformant where it matters
(NOWHISPER 923, NOACCESS 913). Audit/add: 900 BADCOMMAND, 903 BADLEVEL,
905 BADPROPERTY, 906 BADVALUE, 907 RESOURCE, 908 SECURITY, 912 UNKNOWNPACKAGE,
914 DUPACCESS, 915 MISACCESS, 916 TOOMANYACCESSES, 918–921 EVENT*, 924 NOSUCHOBJECT,
925 NOTSUPPORTED, 926 CHANNELEXIST, 927 ALREADYONCHANNEL.

## Implementation order (this conformance pass)
1. **IRCX/ISIRCX gateway + 800 RPL_IRCX** (the entry point). ← starting now
2. **LISTX** dispatch (builder exists).
3. **AUTHONLY +a** JOIN enforcement; **KNOCK +u** gating.
4. **DATA/REQUEST/REPLY** tag messaging + reserved-prefix gating.
5. **CLONEABLE/CLONE** auto-clone + takeover protection.
6. EVENT numeric/type alignment decision; OID decision; UTF8 IRCX prefixes.
7. Fill the IRCX error-numeric set.
