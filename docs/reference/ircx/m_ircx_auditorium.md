# IRCX AUDITORIUM (+x) and HIDDEN (+h)

_Two IRCX channel visibility modes: `+x AUDITORIUM` hides ordinary members from each other, and `+h HIDDEN` hides the channel itself from listings._

These are named channel modes, not commands. They live in Orochi's Zig channel
model, not a C module. The mode letters and MODEX names are declared in
[`src/proto/chanmode_ext.zig`](../../../src/proto/chanmode_ext.zig); the
auditorium visibility predicates are in
[`src/proto/auditorium.zig`](../../../src/proto/auditorium.zig); enforcement is
in [`src/daemon/server.zig`](../../../src/daemon/server.zig). Set them with
either `MODE` or the IRCX [`MODEX`](README.md) named-mode form.

## Syntax

```text
MODE  <channel> +x | -x        # AUDITORIUM
MODE  <channel> +h | -h        # HIDDEN
MODEX <channel> +AUDITORIUM    # named-mode equivalent
MODEX <channel> +HIDDEN
```

## Behavior

### `+x` AUDITORIUM (`auditorium.zig`, letter `x`)

Regular members are hidden from one another; only operators and voiced members
see the full roster. Visibility is by rank (`auditorium.Rank`):

- An **op** member is visible to everyone.
- A **viewer** who is op or voice sees everyone.
- A plain **regular** member sees only ops (and always their own record).

This filter is applied wherever the roster is projected — `NAMES`/`WHO`
(`renderNames`, ~`server.zig:26014`), and `JOIN`/`PART` relays
(`server.zig:9551` / `:10201`): a regular member's join/part is relayed only to
ops and voiced members (`auditorium.shouldRelayJoinPart`). It applies across the
mesh — remote members are rank-filtered the same way when merged into `NAMES`.

### `+h` HIDDEN (`chanmode_ext` letter `h`)

`HIDDEN` marks the channel as unlisted: it is skipped from `LIST`/`LISTX`, the
busiest-channels directory, and the home-view pulse unless the requester is a
member (mirroring `+s SECRET`, but a distinct flag). It is stored on the channel
record (`world.isHidden` / `setHidden`) and rendered as the state-flag diff `h`
in `MODE` output.

## Examples

```irc
MODE #townhall +x            ; audience can't see each other, only the panel
MODE #townhall +h            ; keep it out of channel listings
MODEX #townhall +AUDITORIUM  ; same as +x, by name
```
