# IRCX built-in channel properties

_The channel properties Orochi knows by name — computed built-ins, mode-linked keys, the secret key ladder, and the new `EPHEMERAL` and `PINS` properties._

Channel properties are served by `LinuxServer.handleProp` in
[`src/daemon/server.zig`](../../../src/daemon/server.zig) over the store in
[`src/proto/ircx_prop_store.zig`](../../../src/proto/ircx_prop_store.zig). The
known-key table is `ircx_prop_store.ChannelPropKey` / `channelPropInfo`;
computed reads are `channelBuiltinGet`; validated writes are
`channelBuiltinSet`. All of these are addressed through the
[`PROP`](m_ircx_prop.md) command and require IRCX mode (else `421`).

## Known channel property keys

`OID`, `NAME`, `CREATION`, `MEMBERCOUNT`, `MEMBERLIMIT`, `LANGUAGE`,
`FOUNDERKEY`, `OWNERKEY`, `HOSTKEY`, `VOICEKEY`, `MEMBERKEY`, `PICS`, `TOPIC`,
`SUBJECT`, `CLIENT`, `ONJOIN`, `ONPART`, `LAG`, `ACCOUNT`, `CLIENTGUID`,
`SERVICEPATH`.

### Computed / linked (answered ahead of the generic store)

| Key | Source | Notes |
| --- | --- | --- |
| `NAME` | the channel name | read-only |
| `OID` | `world.channelOid` | `0` + 8 hex digits; read-only |
| `CREATION` | `world.channelCreatedUnix` | unix seconds; read-only |
| `MEMBERCOUNT` | `world.memberCount` | live; read-only |
| `MEMBERLIMIT` | channel `+l` | host-settable; write links to `MODE +l` |
| `MEMBERKEY` | channel `+k` | secret; write links to `MODE +k` |

Setting `MEMBERKEY`/`MEMBERLIMIT` writes through to live channel state and
broadcasts the equivalent `MODE` so every member's mode view stays in sync.

### Secret key ladder (per-tier read gate)

`FOUNDERKEY`, `OWNERKEY`, `HOSTKEY`, `VOICEKEY`, `MEMBERKEY` are marked
`secret`. They are visible only to members at or above their tier (founder >
owner > op/host > voice > member), or to operators. Non-authorized requesters do
not see these rows at all.

## New channel properties

### `EPHEMERAL <secs>` — message TTL (commit `201e5f3`)

```text
PROP <#channel> EPHEMERAL :<seconds>     # 60 … 2592000 (30 days)
PROP <#channel> EPHEMERAL :0             # disable (non-ephemeral)
PROP <#channel> EPHEMERAL :              # delete the property
```

Sets a per-channel message time-to-live in whole seconds. `channelBuiltinSet`
validates the bound (at least `60`, at most `30 days`; `0` disables) and returns
`906 ERR_BADVALUE` for anything out of range or non-numeric. It is **not** a
mode-linked built-in: the value is persisted and mesh-propagated as an ordinary
signed channel property, and it is enforced on **read** at the single
history-replay funnel `renderHistoryReplay` — which serves CHATHISTORY, bouncer
rewind, **and** SEARCH. Every replay drops messages older than the TTL
(`channelEphemeralTtlMs` → `ephemeralFloorMs`), so expired content is simply
never re-served. The history ring still bounds memory; this makes the expiry
policy authoritative on read. Only `#`/`&` channels are ephemeral (DMs never
expire on this path).

### `PINS` — pinned messages (commit `dc2c351`)

```text
PROP <#channel> PINS :<msgid>[,<msgid>…]   # up to 50 msgids
PROP <#channel> PINS :                     # clear all pins
```

A comma-separated list of pinned message-id tokens. `channelBuiltinSet` calls
`validPinsValue`: each token must be non-empty, ≤ 64 chars, printable, and
contain no whitespace or comma; at most 50 tokens; an empty value means "no
pins". Invalid values return `906 ERR_BADVALUE`. Like `EPHEMERAL`, it is stored
and mesh-propagated as a plain signed channel property (not mode-linked), and —
like all channel-property writes — it is channel-operator gated. Clients render
a pins drawer, resolving each msgid against their own history.

## Mesh note

Channel properties (built-in, `EPHEMERAL`, and `PINS` alike) are signed at the
local origin and replicated as last-writer-wins CRDT facts. Commit `c2eee68`
fixed cross-mesh PROP propagation so channel and entity properties now reach
peers; the origin is stamped with the node's `shortId`.

## Examples

```irc
IRCX
PROP #vault EPHEMERAL :3600        ; drop anything older than an hour on replay
PROP #vault EPHEMERAL :0           ; turn expiry off again
PROP #news PINS :01H…ABC,01H…XYZ   ; pin two messages by id
PROP #news PINS :                  ; unpin everything
```
