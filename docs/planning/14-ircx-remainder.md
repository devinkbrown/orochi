# IRCX draft conformance — remaining items (task #20)

Read-only plan. Live `Numeric` enum is `server.zig:473-556` (NOT commands.zig/
proto/numeric.zig — those are test scaffold / SASL). IRCX flags in
`proto/chanmode_ext.zig`. `world.isChannelName` (`world.zig:599`) accepts only `#`.
`Channel` (`world.zig:48-99`) has no created-at/OID field.

## Execution order (dependency + risk; smallest/safest first)
1. **Item 5 — residual 9xx numerics** (zero risk, unblocks others): add to the
   `Numeric` enum at server.zig:473-556: 900 BADCOMMAND, 903 BADLEVEL, 905
   BADPROPERTY, 907 RESOURCE, 908 SECURITY, 912 UNKNOWNPACKAGE, 914 DUPACCESS,
   915 MISACCESS, 916 TOOMANYACCESSES, 924 NOSUCHOBJECT, 925 NOTSUPPORTED,
   926 CHANNELEXIST, 927 ALREADYONCHANNEL (+ 918-921 EVENT* if Item 4 path A).
   No 9xx collision in this enum (SASL 9xx live in proto/numeric.zig). Adding
   variants is inert until callers use them.
2. **Item 6a — KNOCK +u gating**: `handleKnock` server.zig:2369-2403, gate at 2385.
   Allow KNOCK when `+i` OR `+u` (`channelHasExtFlag(.knock)`); else 713. Decision:
   additive (recommended) vs `+u`-required.
3. **Item 6b — NOFORMAT +f**: `messageOne` 4015 / broadcastChannelTagged. Recommend
   path A (advertise via MODE, client-enforced; no relay change) vs B (vendor tag).
4. **Item 4 — EVENT numeric/type**: `handleEvent` server.zig:2987-3025. Decision:
   (A) conform to 806-810 + 918-921 + 6 draft types, or (B, recommended) document
   Event-Spine divergence (richer native taxonomy; matches WALLOPS→Event-Spine).
5. **Item 2 — OID** (8-hex, `0` prefix): `handleCreate` 3434-3440; `channelBuiltinGet`
   3148-3159 (OID/CREATION unpopulated; prop store recognizes keys at
   ircx_prop_store.zig:89-115). Needs `oid:u32`+`created_unix:i64` on `Channel` +
   a `World.next_oid` counter (none today). Decision: (A, recommended) adopt vs
   (B) derive deterministic OID from node_id+channel and document divergence.
6. **Item 1 — CLONEABLE +d / CLONE +E** (hot JOIN path): auto-clone-on-full in
   `joinOne` server.zig:1505-1532 (intercept the `+l`-full 471 when `+d`: find next
   free `#chan<n>`, create `+E` clone copying limit/key/modes, JOIN there);
   clone-takeover protection in the `creating` branch 1521-1525 / `handleCreate`
   (oper-gated removal of a same-name squatter, reuse the prop/access purge). Flags
   exist (`chanmode_ext` .cloneable `d`, .clone `E`). Likely needs a small public
   `world.zig` cloneChannel helper (`ensureChannel` is private at world.zig:579).
   Uses 926/927 (Item 5). Decisions: template-copy scope; takeover authorization
   (oper-only recommended).
7. **Item 3 — UTF8 prefixes** (broadest blast radius; do last): `world.isChannelName`
   world.zig:599 + ~8 callers (joinOne 1506, MODE 1633, DATA 3349, metadata 3448,
   routing 4043, WHO 2017/2074). Accept `&` local + `%#`/`%&` UTF8; nicks `'`/`^`
   gated behind UTF8 cap (handleNickChange 3649). Recommend DEFER `^` UTF8→hex
   display (needs transliteration layer) to a separate task; do `%#`/`%&`/`&`/`'` first.

## Decisions needing the user (do not guess)
- 6a `+u` additive (rec) vs required · 6b advertise-only (rec) vs vendor tag ·
  4 conform 806-810 vs document divergence (rec) · 2 adopt OIDs (rec) vs document ·
  1 clone copy-scope + takeover auth (oper-only rec) · 3 implement `^` now vs defer (rec).

Files: server.zig, world.zig, proto/chanmode_ext.zig, proto/ircx_prop_store.zig,
docs/reference/ircx/CONFORMANCE.md.
