# World projection: converged mesh state → IRC surface (task #6)

Blueprint from a read-only pass over server.zig + suimyaku. Goal: surface remote
channel members (from the converged suimyaku channel CRDT) into NAMES/WHO/WHOIS
and PRIVMSG routing.

## Where local state is read today
- `sendNames` (server.zig ~4206): iterates `self.world.memberIterator(channel)`;
  builds `names_reply.Member{prefixes,nick,user,host}`; user via `usernameOf`,
  host = `default_host`. Auditorium (+x) filtering at ~4215-4231.
- `handleWho`/`handleWhox` (~2012-2122), `handleWhois` (~2178-2228): also read
  `self.world`.
- PRIVMSG routing `messageOne` (~4093-4106): `self.world.findNick(target)` →
  local only; no remote routing today. `routeNickNode` exists on the link.

## Core edits (HIGH priority, ~each 20-50 lines)
1. `channel_crdt.zig`: add `pub fn members()` iterator over live members.
2. `route_table.zig`: add reverse lookup `nicksForNode(NodeId) -> []nick`.
3. `s2s_link.zig`: helper bridging route table → CRDT member nicks.
4. `server.zig sendNames`: merge remote members into NAMES (dedupe local+remote,
   apply prefixes from `MemberStatus`, apply auditorium filter to remote too).
5. `server.zig handleWho`: same merge for WHO.

Deferred: WHOIS remote (Edit 6), PRIVMSG S2S routing via `routeNickNode` (Edit 7).

## BLOCKER to resolve first (read channel_crdt.zig)
- **MemberId semantics for remote members.** Hypothesis A: `MemberId == NodeId`
  (remote server identity); map MemberId→nicks via route table `nicksForNode`.
  Hypothesis B: MemberId is a stable remote client/slot id and the nick mapping
  must be carried in burst/gossip. **Verify before coding.**
- **CRDT stores no nick/user@host/realname** — only MemberId + MemberStatus
  (op/voice bits). Short-term: render remote as `nick@remote_server_name`
  (user@host placeholder); proper fix = carry identity in the burst/gossip
  payload (ties into Tsumugi pubkey exchange, task #2).
- **One ChannelCrdt per link** (`s2s_link.state`) — treat the converged CRDT as
  the authoritative remote view; merge with `self.world` for the channel.

## Tests to add
- `channel_crdt.members()` iteration (incl. removed member tombstone vs containsMember).
- `route_table.nicksForNode()`.
- sendNames/handleWho with a mock remote CRDT member (prefixes + auditorium filter).
- e2e (two linked daemons): alice on A + bob on B → NAMES #chat shows both on both.
