# IRCX reference + Orochi conformance cross-check

Authoritative IRCX material for Orochi:
- `ircx-draft-pfenning-04.md` — the canonical IETF draft (normative numerics,
  commands, modes, properties). Source of truth.
- `ircx-protocol-ophion.md` + `m_ircx_*.md` — ophion's implementation notes
  (behavioral blueprint; NOT authoritative on identity/SID — Orochi is SID-free).
- `../ircv3.md` (Orochi) + `../ircv3-ophion.md` (richer ophion IRCv3 cap list).

## Cross-check: Orochi live IRCX vs the draft (findings)

Orochi already implements live: CREATE, ACCESS (801–805), PROP (818/819), EVENT
(ADD/DEL/LIST), MODEX, WHISPER (+w/923), AUDITORIUM (+x), the visibility/extended
channel modes (a/x/w/u/f/d/E/r/z/Y), and AUTH (lib). Studying the draft surfaced
**numeric conflicts to fix** (the kind of "bad decision" a redesign should catch):

| Orochi now | Draft says | Action |
| --- | --- | --- |
| `ERR_PROPDENIED = 918` (PROP set/delete denial) | **918 = IRCERR_EVENTDUP** | **BUG.** PROP permission denial should be **908 IRCERR_SECURITY** (or 913 NOACCESS). Move it; free 918 for EVENT-dup. |
| `RPL_MODEXLIST/END = 826/827` | 806/807 = IRCRPL_EVENTADD/DEL | ✅ resolved. EVENT now uses the draft `806–810` (ADD/DEL/START/LIST/END); MODEX (a non-draft Orochi extension) moved to `826/827`, clear of ACCESS/EVENT/LISTX/PROP. |
| `ERR_NOWHISPER = 923` | 923 IRCERR_NOWHISPER | ✅ correct |
| ACCESS 801–805 | 801–805 ACCESS* | ✅ correct |
| PROP 818/819 | 818/819 PROPLIST/END | ✅ correct |
| `ERR_KEYNOPERMISSION = 769` (METADATA) | n/a (IRCv3 metadata-2, not IRCX) | ✅ correct domain |

Other draft conformance to honor as we wire EVENT/IRCX-mode fully:
- **800 IRCRPL_IRCX** discovery (`MODE ISIRCX` / `IRCX`): Orochi has `ircx_gate`
  builder; wire the 800 reply + the `IRCX`/`ISIRCX` mode switch (parity item 51).
- **EVENT** numerics 806–810 + event types CHANNEL/MEMBER/SERVER/CONNECTION/
  SOCKET/USER. Orochi's EVENT currently rides the daemon Event-Spine categories;
  reconcile names/numerics with the draft (or document the deliberate divergence —
  WALLOPS-as-Event-Spine is an intentional Orochi change).
- **AUTH ordering** (AUTH before USER/NICK) — Orochi uses IRCv3 SASL via CAP;
  IRCX AUTH is the legacy path (lib exists, not the primary).
- **Clone takeover protection** (CREATE clone removes same-named channel) — note
  for CLONEABLE/CLONE (+d/+e) if/when implemented.

## Decision

Treat the draft numerics as authoritative for IRCX-namespaced replies; Orochi
extensions (MODEX) must NOT squat draft-reserved codes. Fix `ERR_PROPDENIED` and
`MODEX` numerics in a dedicated conformance pass (tracked).
