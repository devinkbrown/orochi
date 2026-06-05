# #6 live wiring — channel-scoped nick propagation for remote NAMES/WHO

The projection engine (`world_projection.mergeMembers`, commit 7983299) and the
secured S2S link (`secure_s2s_link.SecureLink`, commit d4a32cd) are done. What is
still missing to make remote members appear in NAMES/WHO is the *data*: the mesh
must propagate, per channel, *which remote nicks are present and with what status*.
This doc fixes that wire-format decision and the implementation order.

## Why the data isn't there yet

- The channel CRDT (`channel_crdt.zig`) keys members by an opaque `u64` MemberId
  and stores **only** mode/status bits — no nick/user/host. (Confirmed; this is
  the decision recorded in `world_projection.zig`.)
- `route_table.zig` tracks `nick → node` and `channel → nodes`, but **not**
  `channel → nicks`, and nothing populates remote nicks today: the only
  `setNickLocation` call is each peer registering *its own server name*.
- So there is no path from "remote peer has alice on #chat" to this server's
  `sendNames`.

## Decision: a typed MEMBERSHIP delta on the existing S2S frame stream

Carry membership as a small, convergent, signed event rather than overloading the
channel CRDT with identity (keeps the CRDT identity-light and the mode-convergence
clean). Reuse the machinery already in place:

- New `s2s_frame` type `MEMBERSHIP` (additive to the frame enum; no change to
  existing HANDSHAKE/BURST/DELTA/GOSSIP/PING/PONG/QUIT semantics).
- Payload (CoilPack-encoded, so it is canonical + signable): `{ op: join|part|
  status, channel: []u8, nick: []u8, status_bits: u4, origin_node: u64, hlc: u64 }`.
  `status_bits` reuses `MemberStatus` (founder/owner/op/voice) so prefixes render.
- `hlc` + `origin_node` give last-writer-wins convergence per `(channel, nick)`,
  consistent with the rest of Goryu-Sync; a part with a newer hlc beats a stale
  join. Signing reuses `signed_delta`/`coilpack_value` (already built).

Rationale for a separate event vs. embedding nicks in the channel CRDT: identity
is membership-scoped and high-churn (nick changes, joins/parts) and must not bloat
the mode CRDT's delta/anti-entropy traffic; a dedicated family lets the relay
filter and the store evict independently.

## Storage: extend `route_table` with channel → members

Add a parallel `channel_members: StringHashMap(MemberMap)` where
`MemberMap = StringHashMap(Member)` and `Member = { node: NodeId, status: u4,
hlc: u64 }`. API:

- `applyMembership(op, chan, nick, node, status, hlc)` — LWW by hlc; allocates/
  frees owned nick keys; bounded by `cfg.max_nicks` per channel.
- `channelMembers(chan) -> iterator` of `{ nick, node, status }`.
- `clearChannel(chan)` / eviction on `removeNode` (peer split) — drop all members
  homed on a departed node so a netsplit cleans up remote ghosts.

Ownership mirrors the existing `nick_to_node` pattern (dupe on insert, free on
remove/clear/deinit). Add the same in `clear`/`deinit`.

## Producer (each daemon → its peers)

In `server.zig`, on local membership transitions already handled by the world
(`joinOne`/`partOne`/`broadcastQuit`/nick change/`setMemberMode`), emit a
`MEMBERSHIP` event to every established `conn.s2s` link via a new
`s2s_link.sendMembership(op, chan, nick, status)` → `s2s_peer` → frame. Gate on
`link.established()`. Use the daemon clock for `hlc`.

## Consumer (peer frame → route table → NAMES)

- `s2s_peer.dispatch` handles `.MEMBERSHIP` → `route_table.applyMembership(...)`.
- `s2s_link` exposes `channelMembers(chan)`.
- `server.zig sendNames` / `handleWho`: after the local members, iterate each
  established link's `channelMembers(channel)`, build `world_projection.RemoteMember`
  `{ nick, prefixes = renderStatus(status), server_name = link.remoteName() }`,
  and call `world_projection.mergeMembers(local, remote)`. Apply the auditorium
  (+x) filter to remote members too (already done for local).

## Implementation order (smallest/safest first)

1. `route_table` channel→members storage + `applyMembership`/`channelMembers`/
   eviction + unit tests (LWW, part-after-join, node eviction, bounds). *Pure,
   isolated, no protocol change yet.*
2. `s2s_frame` `MEMBERSHIP` type + CoilPack payload codec + round-trip tests.
3. `s2s_peer` produce/consume + `s2s_link.sendMembership`/`channelMembers`.
4. `server.zig` producer hooks (join/part/quit/nick/status) + `sendNames`/`WHO`
   consumer using `mergeMembers`.
5. DST test in `s2s_dst`: alice on A + bob on B → after convergence, NAMES #chat
   on both peers shows both (the end-to-end #6 acceptance test).

## Risk notes

- Hot paths touched: `sendNames`/`handleWho` (read side) and join/part (emit
  side). Keep emit best-effort (a full link buffer must not fail a local JOIN).
- Netsplit hygiene: `removeNode` eviction (step 1) is mandatory or remote ghosts
  linger in NAMES after a peer drops.
- Nick collisions across the mesh are already handled by LADON rename-to-UID
  (see memory `feedback_nick_collision_rename`); MEMBERSHIP carries the post-rename
  nick, so projection shows the winner.
