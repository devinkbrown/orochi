# 12 — World projection from converged mesh state to IRC surface

*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

Defines task #6: surface remote channel members from the converged suimyaku channel CRDT into NAMES/WHO/WHOIS and PRIVMSG routing.

Blueprint from a read-only pass over server.zig + suimyaku.

## Where local state is read today

| Surface | Current read path |
|---|---|
| `sendNames` | `sendNames` (server.zig ~4206) iterates `self.world.memberIterator(channel)`; builds `names_reply.Member{prefixes,nick,user,host}`; user via `usernameOf`, host = `default_host`. Auditorium (+x) filtering at ~4215-4231. |
| WHO/WHOIS | `handleWho`/`handleWhox` (~2012-2122), `handleWhois` (~2178-2228): also read `self.world`. |
| PRIVMSG routing | `messageOne` (~4093-4106): `self.world.findNick(target)` → local only; no remote routing today. `routeNickNode` exists on the link. |

## Core edits (HIGH priority, ~each 20-50 lines)

| Order | Edit |
|---|---|
| 1 | `channel_crdt.zig`: add `pub fn members()` iterator over live members. |
| 2 | `route_table.zig`: add reverse lookup `nicksForNode(NodeId) -> []nick`. |
| 3 | `s2s_link.zig`: helper bridging route table → CRDT member nicks. |
| 4 | `server.zig sendNames`: merge remote members into NAMES (dedupe local+remote, apply prefixes from `MemberStatus`, apply auditorium filter to remote too). |
| 5 | `server.zig handleWho`: same merge for WHO. |

Deferred: WHOIS remote (Edit 6), PRIVMSG S2S routing via `routeNickNode` (Edit 7).

## Blockers to resolve first (read channel_crdt.zig)

| Blocker | Planning note |
|---|---|
| **MemberId semantics for remote members.** | Hypothesis A: `MemberId == NodeId` (remote server identity); map MemberId→nicks via route table `nicksForNode`. Hypothesis B: MemberId is a stable remote client/slot id and the nick mapping must be carried in burst/gossip. **Verify before coding.** |
| **CRDT stores no nick/user@host/realname** | It stores only MemberId + MemberStatus (op/voice bits). Short-term: render remote as `nick@remote_server_name` (user@host placeholder); proper fix = carry identity in the burst/gossip payload (ties into Tsumugi pubkey exchange, task #2). |
| **One ChannelCrdt per link** (`s2s_link.state`) | Treat the converged CRDT as the authoritative remote view; merge with `self.world` for the channel. |

## Tests to add

| Area | Test |
|---|---|
| CRDT iteration | `channel_crdt.members()` iteration (incl. removed member tombstone vs containsMember). |
| Route lookup | `route_table.nicksForNode()`. |
| IRC projection | sendNames/handleWho with a mock remote CRDT member (prefixes + auditorium filter). |
| End-to-end | e2e (two linked daemons): alice on A + bob on B → NAMES #chat shows both on both. |
