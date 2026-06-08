# 23 — IRCv3 upstream research (current spec set vs Mizuchi)

Sourced from the live IRCv3 spec index + recent spec PRs (June 2026). Maps every
upstream capability to Mizuchi's status. This complements the in-tree gap sweep
(`22-irc-gap-sweep.md`) with the *authoritative upstream list*, including the
newest additions the user flagged.

## Newest upstream additions (2024–2026) — the "new things"
- **account-extban** (ratified Jul 2024) — ISUPPORT token to build an EXTBAN
  targeting an account. Mizuchi already has extban `a`; verify it matches the
  ratified `account-extban` ISUPPORT token + semantics (ban/exempt/invex).
- **pre-away** (draft) — allow `AWAY` during registration / mark a connection as
  not user-initiated (auto-away systems). MISSING.
- **extended-isupport** (draft, Apr 2025) — fetch ISUPPORT *before* registration;
  new command + a batch type delimiting ISUPPORT bursts. MISSING.
- **network-icon** (draft, Nov 2025) — ISUPPORT token advertising a network icon.
  MISSING (trivial token; pairs well with Ocean).
- **SCRAM-SHA-256** SASL mechanism + **EXTERNAL** — Mizuchi has the server modules
  (sasl_scram_server, sasl_scram512_server, sasl_external) but advertises only
  `sasl=PLAIN`. PARTIAL — just advertise the mechs in the cap value.
- **msgid** — unique message-id tag. MISSING.
- **WebSocket transport** — ratified transport; relevant to the browser/Ocean path.

## Ratified/stable — Mizuchi status
| Cap | Status |
|---|---|
| cap-notify | **MISSING** |
| message-tags | present |
| sasl (PLAIN/EXTERNAL/SCRAM-SHA-256) | **PARTIAL** — only PLAIN advertised |
| account-extban | PARTIAL — extban `a` exists; verify token conformance |
| account-notify / account-tag / extended-join | present |
| away-notify | present |
| batch (+ netsplit/netjoin/chathistory types) | present |
| bot | present |
| chghost / setname | present |
| echo-message | present |
| invite-notify | present |
| **labeled-response** (`label`) | **MISSING** (high value) |
| multi-prefix / userhost-in-names | present |
| **WHOX** | present (completed this session) |
| no-implicit-names | present |
| **msgid** | **MISSING** |
| MONITOR | present |
| server-time | present |
| **sts** | **MISSING** |
| UTF8ONLY | present (ISUPPORT) |
| WEBIRC | **excluded by project decision** |
| WebSocket transport | MISSING (browser/Ocean path) |

## Work-in-progress / draft — Mizuchi status
| Cap | Status |
|---|---|
| account-registration | PARTIAL — REGISTER/VERIFY exist, **cap unadvertised** |
| channel-rename | present (draft/channel-rename) |
| chathistory | present (draft/chathistory) |
| message-redaction | present |
| read-marker | present |
| **pre-away** | MISSING (new) |
| **extended-isupport** | MISSING (new) |
| **network-icon** | MISSING (new) |
| client-batch | MISSING |
| **metadata-2** | PARTIAL — METADATA exists, **cap unadvertised** |
| multiline | MISSING |
| SNI | MISSING (modern TLS; review vs implicit-TLS stance) |

## Client-only tags — Mizuchi status
reply ✅ · react ✅ · typing ✅ · **channel-context** ❌ (MISSING)

## Deprecated (do NOT implement)
STARTTLS — superseded by STS; already out by project decision (modern-only).

## Cheapest complete wins (commands already exist — just advertise/conform)
1. Advertise `sasl=PLAIN,EXTERNAL,SCRAM-SHA-256` (modules exist).
2. Advertise `draft/account-registration` (REGISTER/VERIFY live).
3. Advertise `draft/metadata-2` (METADATA live).
4. `network-icon` ISUPPORT token (trivial; Ocean uses it).

## High-value new builds (wave candidates)
labeled-response (+msgid), cap-notify (+CAP NEW/DEL), sts, pre-away,
extended-isupport, multiline, client-batch, channel-context tag, WebSocket
transport (browser).

## Sources
- IRCv3 spec index: https://ircv3.net/irc/
- account-extban: https://ircv3.net/specs/extensions/account-extban (PR #464)
- pre-away: https://github.com/ircv3/ircv3-specifications/pull/514
- account-registration: https://ircv3.net/specs/extensions/account-registration (PR #435)
- IRCv3 registry: https://ircv3.net/registry
- spec repo: https://github.com/ircv3/ircv3-specifications
