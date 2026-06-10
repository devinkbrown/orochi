# Mode Re-architecture: Legacy Channel & User Modes

Decision document for the Orochi IRC daemon.

Status: design decision record. Scope: deciding, for each channel/user mode found in
the legacy ircds (charybdis / UnrealIRCd / InspIRCd lineage) that Orochi does **not**
yet implement, whether to **KEEP** (reimplement Orochi-native), **DROP** (obsolete,
legacy, or redundant), or mark **ALREADY-COVERED** (Orochi achieves the effect by
another mechanism).

---

## 1. Philosophy

Orochi is a clean-room daemon, not a port. We are not obligated to carry forward the
accreted single-letter mode flags that legacy ircds accumulated over twenty years. The
guiding principles for this review:

1. **A mode letter is a bad API.** A cryptic one-byte flag is justified only when the
   effect is (a) per-channel or per-user state, (b) frequently toggled by ordinary
   channel operators, and (c) cheap to represent on the wire. Anything that is really an
   account property, a network policy, or a broadcast event belongs in the account
   system, configuration, or the **Event Spine**, not in a `MODE` letter.

2. **Account integration over flags.** Orochi has first-class accounts (operators are
   SASL-only; there is no password `OPER`). Effects that key off "is this user
   authenticated / registered" are expressed against the account identity directly,
   and where a channel-level toggle is still wanted it is exposed through the named
   **IRCX MODEX** layer rather than inventing new ad-hoc letters.

3. **Modern transport only.** TLS is implicit-on-connect; there is **no STARTTLS**.
   Every connected session is either TLS or it is not, decided at accept time. Any
   "secure-only" semantics are defined in terms of that connection fact, never in terms
   of an in-band upgrade.

4. **The Event Spine replaces server-broadcast modes.** WALLOPS, snomasks, and operwall
   are Event-Spine events, not a `+w` user mode or `+s` snomask user mode. Server-to-user
   broadcast is a subscription concern, not a mode bit.

5. **Cloaking is automatic.** Hostnames are cloaked at connect time for every user. There
   is no user-toggled cloak.

6. **Don't duplicate what IRCX already names.** Orochi ships an IRCX-style named-mode
   layer (`MODEX`, `PROP`, `ACCESS`, `OWNER`). Several legacy letter-modes map directly
   onto existing IRCX named flags; those are ALREADY-COVERED and should not get a second,
   redundant letter.

### Already-shipped surface (baseline for this review)

- **Core channel modes** (`chanmode.zig`): `b e I k l i m n t s`, plus member tiers
  founder `~` (+Q) > owner `.` (+q) > op `@` (+o) > voice `+` (+v),
  ISUPPORT `PREFIX=(Qqov)~.@+`.
- **IRCX extended channel flags** (`chanmode_ext.zig` / `ircx_modex.zig`, named via
  `MODEX`): `PRIVATE(p)`, `HIDDEN(h)`, `SECRET(s)`, `AUTHONLY(a)`, `NOFORMAT(f)`,
  `KNOCK(u)`, `AUDITORIUM(x)`, `NOWHISPER(w)`, `REGISTERED(r)`, `SERVICE(z)`,
  `CLONEABLE(d)`, `CLONE(E)`, `NOCOMICDATA(Y)`.
- **User modes** (`usermode.zig`): `invisible(i)`, `bot(B)`, `registered(r)`,
  `secure-tls(z)`, `deaf(D)`, `callerid(g)`, `no-ctcp(C)`, `cloaked(x)`.

Note: several modes the request lists as "not yet implemented" are in fact already
present in one of the layers above; those are recorded as ALREADY-COVERED with a pointer
to the implementing module.

---

## 2. Channel Modes

| Legacy | Meaning | Decision | Rationale & Orochi-native design |
|--------|---------|----------|-----------------------------------|
| `p` | private | **ALREADY-COVERED** | IRCX `PRIVATE(p)` exists in `chanmode_ext.zig`. The legacy `+p`/`+s` split is collapsed: `SECRET(s)` hides from `LIST`/`WHOIS`, `PRIVATE(p)` suppresses membership disclosure. No new letter. |
| `c` | strip mIRC color/formatting | **ALREADY-COVERED** | IRCX `NOFORMAT(f)` already strips formatting/color. Keep the named form; do not add a second `c`. |
| `C` | block CTCP to channel | **KEEP** | Distinct from NOFORMAT (CTCP is a message class, not formatting). Orochi-native: channel flag `NOCTCP`, MODE letter **`C`**. Drops CTCP (except ACTION) addressed to the channel; ops bypass. Mirrors the user-mode `no-ctcp(C)` already shipped. |
| `g` | free invite (anyone may `/invite`) | **KEEP** | Useful with `+i`. Orochi-native: flag `FREEINVITE`, MODE letter **`g`** — lets any member (not only ops) invite while `+i` is set. Cheap flag, frequently toggled, belongs as a letter. |
| `z` | reduced/op moderation (blocked msgs redirected to ops) | **KEEP** | Complements `+m`/`+b`: messages that *would* be blocked are instead delivered to ops as an Event-Spine `chan.moderation.held` signal. Orochi-native: flag `OPMODERATE`, MODE letter **`U`** (legacy `z` collides with our IRCX `SERVICE(z)`; pick a free letter). Held messages surface to ops via the Event Spine, not as raw NOTICEs. |
| `T` | block channel NOTICEs | **KEEP** | Anti-spam staple. Orochi-native: flag `NONOTICE`, MODE letter **`T`**. Blocks `NOTICE` to the channel from non-ops. |
| `N` | block nick changes while in channel | **KEEP** | Useful for moderated/event channels. Orochi-native: flag `NONICK`, MODE letter **`N`**. While set, members below op cannot change nick while joined. |
| `S` | TLS-only channel | **KEEP** | Redefined for implicit-TLS: join is permitted only if the joining session was accepted over TLS (connection fact, no STARTTLS). Orochi-native: flag `TLSONLY`, MODE letter **`S`**. Non-TLS join → `ERR_SECUREONLYCHAN`. |
| `O` | oper-only channel | **DROP / fold into IRCX** | The IRCX `ACCESS` list with a `DENY`/`GRANT` entry keyed on operator identity expresses this precisely and auditable-y. A blunt "opers only" bit is too coarse; use `ACCESS #chan ADD DENY *` + grant for opers. No new letter. |
| `A` | admin-only channel | **DROP** | Same reasoning as `O`, and Orochi has no separate "admin" oper class to gate on. Express via `ACCESS`. |
| `r` | registered-account-only join | **KEEP** | Common, distinct from registered-*channel*. Reuse the IRCX named flag **`AUTHONLY(a)`** which already gates join on an authenticated account — so this is effectively ALREADY-COVERED by `AUTHONLY`. No new `r` channel letter (our `r` already means REGISTERED-channel). |
| `M` | mute unauthenticated users (may join, can't speak) | **KEEP** | Softer than `AUTHONLY`. Orochi-native: flag `MODREG` (moderate-unregistered), MODE letter **`M`**. Unauthenticated members are treated as un-voiced under `+m`-like rules; authenticated speak freely. Account-integrated. |
| `P` | permanent channel (survives empty) | **KEEP** | Real operational need. But it is config/operator policy, not a casual toggle. Orochi-native: a **persistent-channel** property set via `PROP #chan PERSIST :1` (IRCX PROP), oper-gated, with the underlying CRDT channel object retained by the substrate. Surfaced read-only as MODE letter **`P`** for client display. |
| `F` / `f` | forward / free forward-target | **DROP** | Channel forwarding (bounce a blocked joiner to another channel) is rarely understood, frequently abused for ad-channels, and interacts badly with a mesh/CRDT membership model. Provide nothing; rejected joins get a clear numeric, not a silent redirect. |
| `Q` | block forwarding *into* this channel | **DROP** | Only exists to defend against `F`/`f`; with forwarding dropped it is meaningless. |
| `L` | limit-redirect (overflow → other channel) | **DROP** | Same family as `F`; overflow on `+l` returns `ERR_CHANNELISFULL`, no silent redirect. Predictable failure beats hidden routing. |
| `D` / `d` | delayed / cloaked join (hide joins until speak) | **KEEP** | Strong anti-spam / large-channel UX win. Orochi-native: flag `DELAYJOIN`, MODE letter **`D`**. Joins are withheld from the channel until the member sends a message or is op'd; revealed via a normal `JOIN` at that point. Integrates with the Event Spine for the deferred reveal. (Subsumes both legacy `+D` and `+d`.) |
| `j` | join throttle `n:t` | **KEEP** | Effective flood control. Orochi-native: param flag `THROTTLE`, MODE letter **`j`**, parameter `joins:seconds`. Enforced per-channel with a token-bucket; excess joins get `ERR_TOOMANYJOINS`. Type-C-style (param on set, bare on unset). |
| `q` (quiet list) | quiet ban (mute without ban) | **KEEP (renamed)** | The letter `q` is the Orochi **owner** member tier (+q `.`), so a quiet *cannot* reuse `q`. Orochi-native: a type-A list mode `MUTE`, MODE letter **`Z`** (`+Z mask`), matched like `+b` but only suppressing speech, not join. Equivalent expressiveness to legacy `~q:`/extban quiets without the letter collision. |

---

## 3. User Modes

| Legacy | Meaning | Decision | Rationale & Orochi-native design |
|--------|---------|----------|-----------------------------------|
| `i` | invisible (hidden from `WHO`/no-shared-channel `WHOIS`) | **ALREADY-COVERED** | Shipped as `invisible(i)` in `usermode.zig`. |
| `B` | bot flag | **ALREADY-COVERED** | Shipped as `bot(B)` with IRCv3 `bot` tag in `usermode.zig`. |
| `D` | deaf (drop channel messages) | **ALREADY-COVERED** | Shipped as `deaf(D)` in `usermode.zig`. |
| `g` | caller-id / server-side ignore (accept-list gating of PMs) | **ALREADY-COVERED** | Shipped as `callerid(g)` in `usermode.zig`. Pairs with an `ACCEPT` command for the allow-list. |
| `o` | operator | **KEEP (server-managed)** | Operators exist but are **SASL-only** — there is no password `OPER`. Orochi-native: user mode `oper`, letter **`o`**, `policy = server_managed` (set by the daemon on successful operator-class SASL auth, never client-writable; clients may only `-o` to deopper themselves). |
| `R` | reg-only PMs / block messages from unauthenticated users | **KEEP** | Anti-spam staple, account-integrated. Orochi-native: user mode `regonly-pm`, letter **`R`**, `client_writable`. PMs/notices from unauthenticated senders are rejected with `ERR_NONONREG` while set. |
| `p` | hide channel list in own `WHOIS` | **KEEP** | Genuine privacy control distinct from `+i`. Orochi-native: user mode `hide-chans`, letter **`p`**, `client_writable`. Suppresses the `RPL_WHOISCHANNELS` line for this user (opers still see it). |
| `Z` | connected via TLS | **ALREADY-COVERED** | Shipped as `secure-tls(z)` in `usermode.zig`, `policy = server_managed`, set at accept time from the implicit-TLS connection fact (no STARTTLS path). We use lowercase `z`; that is the canonical Orochi letter. |
| `x` | host cloak toggle | **DROP** | Cloaking is automatic on connect for everyone. There is nothing to toggle. (Note: `usermode.zig` carries a server-managed `cloaked(x)` purely as a *read-only indicator* that the auto-cloak is applied; it is not user-settable.) |
| `w` | receive WALLOPS | **DROP** | WALLOPS is an Event-Spine event with a subscription, not a user mode. Already-covered by Event Spine. |
| `s` | snomask / server notices | **DROP** | Snomasks are Event-Spine event subscriptions, not a `+s` user mode. Already-covered by Event Spine. |

---

## 4. Recommended Implementation Order (KEEP items only)

Grouped by implementation effort. ALREADY-COVERED and DROP items are excluded.

### Tier 1 — trivial boolean channel flags (a flag bit + a join/speak/notice gate)
- `C` NOCTCP — block channel CTCP.
- `T` NONOTICE — block channel notices.
- `N` NONICK — block nick changes while joined.
- `g` FREEINVITE — any member may invite under `+i`.
- `S` TLSONLY — gate join on the connection's TLS fact.

### Tier 2 — account-integrated user/channel toggles
- user `R` regonly-pm — reject PMs from unauthenticated senders.
- user `p` hide-chans — suppress own WHOIS channel list.
- channel `M` MODREG — mute unauthenticated members (`+m`-like for non-accounts).
- user `o` oper — server-managed, set on operator-class SASL only.
- (channel `AUTHONLY(a)` already covers reg-only join — no new work beyond confirming the gate.)

### Tier 3 — parameterized / list modes (need storage + matching)
- `Z` MUTE — type-A quiet list (mute-only ban analog; letter chosen to avoid the owner `q` collision).
- `j` THROTTLE — `joins:seconds` token-bucket on join.

### Tier 4 — stateful / cross-subsystem features
- `U` OPMODERATE — held-message moderation, surfaced to ops via the Event Spine.
- `D` DELAYJOIN — deferred join reveal, integrates with the Event Spine and membership state.
- `P` PERSIST — persistent channel via IRCX `PROP`, oper-gated, backed by the CRDT channel object in the substrate (read-only `P` display letter).

---

## 5. Better as Account-Integrated Features or Event-Spine Signals

Several KEEP items are explicitly **not** best modeled as cryptic letters and should lean
on existing subsystems rather than expanding the letter namespace:

- **`P` PERSIST → IRCX PROP (account/config), not a writable letter.** Persistence is an
  operator policy on a channel's lifecycle, set with `PROP #chan PERSIST`. The `P` MODE
  letter is only a *read-only mirror* for clients that display channel modes; the source
  of truth is the channel property and the substrate's retained CRDT object.

- **`U` OPMODERATE → Event-Spine signal.** Held messages must reach ops as a structured
  `chan.moderation.held` event (with sender, target, payload, reason) so tooling and bots
  can act on them — far more useful than re-flinging raw NOTICEs. The MODE letter only
  arms the behavior.

- **`D` DELAYJOIN → Event-Spine reveal.** The deferred "now reveal this member" step is an
  Event-Spine transition, keeping membership visibility logic in one place rather than
  scattered through the JOIN path.

- **`R` regonly-pm, `M` MODREG, channel `AUTHONLY` → account identity, not host masks.**
  These all key on "is the principal an authenticated account?" — answered directly from
  the SASL-established account, never from `b`/`e` host-mask heuristics. This is more
  precise and resistant to spoofing than the legacy mask-based equivalents.

- **`o` oper → SASL, not a mode set by clients.** The "operator" state is a consequence of
  operator-class SASL authentication; the `+o` letter is a server-managed reflection of
  account state, not an independently togglable flag. There is no password `OPER`.

### What we deliberately did *not* bring forward

Channel forwarding (`F`/`f`/`Q`/`L`), oper/admin-only channel bits (`O`/`A`), the
host-cloak toggle (`x`), and the WALLOPS/snomask user bits (`w`/`s`) are all DROPPED:
forwarding is replaced by predictable failure numerics, coarse oper-only gating is
replaced by the auditable IRCX `ACCESS` list, cloaking is automatic, and server-broadcast
subscriptions live on the Event Spine. Each removal eliminates a cryptic letter in favor
of a clearer, account- or event-integrated mechanism.
