# IRCX reference and Orochi conformance cross-check

_Index of the IRCX reference set, plus a conformance check of Orochi's live IRCX surface against the canonical draft._

## Authoritative material

| Document | Role |
| --- | --- |
| `ircx-draft-pfenning-04.md` | Canonical IETF draft. Source of truth for numerics, commands, modes, and properties. |
| `ircx-protocol-ophion.md` and `m_ircx_*.md` | Ophion implementation notes (behavioral blueprint). Not authoritative on identity/SID — Orochi is SID-free. |
| `../ircv3.md` and `../ircv3-ophion.md` | Orochi IRCv3 capabilities, plus the richer ophion IRCv3 capability list. |

## Cross-check: live IRCX versus the draft

Orochi implements live: CREATE, ACCESS (801–805), PROP (818/819), EVENT
(ADD/DEL/LIST), MODEX, WHISPER (+w/923), AUDITORIUM (+x), the visibility and
extended channel modes (a/x/w/u/f/d/E/r/z/Y), and AUTH (lib). Comparing this
surface against the draft surfaces numeric conflicts to fix:

| Orochi now | Draft says | Action |
| --- | --- | --- |
| `ERR_PROPDENIED = 918` (PROP set/delete denial) | `918 = IRCERR_EVENTDUP` | Bug. PROP permission denial should be `908 IRCERR_SECURITY` (or 913 NOACCESS). Move it and free 918 for EVENT-dup. |
| `RPL_MODEXLIST/END = 826/827` | `806/807 = IRCRPL_EVENTADD/DEL` | Resolved. EVENT now uses the draft `806–810` (ADD/DEL/START/LIST/END); MODEX (a non-draft Orochi extension) moved to `826/827`, clear of ACCESS/EVENT/LISTX/PROP. |
| `ERR_NOWHISPER = 923` | `923 IRCERR_NOWHISPER` | Correct. |
| ACCESS 801–805 | `801–805 ACCESS*` | Correct. |
| PROP 818/819 | `818/819 PROPLIST/END` | Correct. |
| `ERR_KEYNOPERMISSION = 769` (METADATA) | n/a (IRCv3 metadata-2, not IRCX) | Correct domain. |

## Open conformance items

Honor these as EVENT and IRCX-mode are wired fully:

- **800 IRCRPL_IRCX discovery** (`MODE ISIRCX` / `IRCX`). Orochi has the `ircx_gate`
  builder; wire the 800 reply and the `IRCX`/`ISIRCX` mode switch (parity item 51).
- **EVENT numerics 806–810** plus event types CHANNEL/MEMBER/SERVER/CONNECTION/
  SOCKET/USER. Orochi's EVENT currently rides the daemon Event-Spine categories;
  reconcile names and numerics with the draft, or document the deliberate
  divergence (WALLOPS-as-Event-Spine is an intentional Orochi change).
- **AUTH ordering** (AUTH before USER/NICK). Orochi uses IRCv3 SASL via CAP; IRCX
  AUTH is the legacy path (the lib exists but is not the primary).
- **Clone takeover protection** (CREATE clone removes a same-named channel). Note
  for CLONEABLE/CLONE (+d/+e) if and when implemented.

## Decision

Treat the draft numerics as authoritative for IRCX-namespaced replies. Orochi
extensions (MODEX) must not squat draft-reserved codes. Fix the `ERR_PROPDENIED`
and `MODEX` numerics in a dedicated conformance pass (tracked).
