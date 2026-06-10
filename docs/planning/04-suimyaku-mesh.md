Using `source-command-plan`; no files were modified.

**04 — Protocol (Suimyaku mesh)**

> NAMING: Orochi's invented names supersede ophion's. **Suimyaku** = S2S CRDT
> mesh (was LADON), **Tsumugi** = PQ ratchet (was VEIL), **Sazanami** = gossip
> (was SWIM), **Goryu** = CRDT lib. Below, old names appear ONLY in citations to
> ophion's superseded specs (overview.md / wire-protocol.md / veil-security.md);
> Orochi's own systems use the new names.

Orochi is a clean break: IRC-compatible client line protocol on the front, native **Suimyaku/Tsumugi** mesh on S2S, no TS6 bridge by default. The brief explicitly requires Zig-native rewrite, feature parity, no TS6, Suimyaku+Tsumugi-only mesh, Goryu-CRDT/Sazanami-gossip/Merkle state, nick collision rename-to-UID, and constant-time crypto paths (`/home/kain/orochi/docs/BRIEF.md:3`, `:10`, `:14`, `:21`, `:32`, `:45`).

**Part A: Client Line**
Existing Ophion parses mutable IRC lines into `MsgBuf` with fixed `MAXPARA=15`, tag array, origin, command, params, and cap-gated outbound tags (`include/msgbuf.h:30`, `:37`, `:50`, `:105`). `msgbuf_parse.c` is folded into `ircd/msgbuf.c`; `ircd/numeric.c` is absent, with numerics in `include/numeric.h`.

Design: `LineView` is zero-copy over one read slab. SIMD scans CR/LF, first space, `@tags`, `:prefix`, and param separators; it stores slices, never NUL-mutates. Tag values are lazily unescaped into a small arena only when a handler asks. Ophion already uses SIMD delimiter scans and in-place tag splitting (`ircd/msgbuf.c:130`, `:162`, `:198`, `:215`); Orochi keeps SIMD but removes mutation and fixed tag count. Numerics become a comptime enum table generated from `numeric.zig`, retaining IRC ranges such as local replies 001-099 and errors 400-599 (`include/numeric.h:33`, `:218`).

```zig
const LineView = struct {
    raw: []const u8,
    tags: []TagView,
    prefix: ?[]const u8,
    cmd: CommandId,
    params: BoundedSlice([]const u8, 15),
    trailing: ?[]const u8,
};
const TagView = struct { key: []const u8, value_raw: ?[]const u8, gate: CapSet = .client_supplied };
```

CAP is a typed state machine: `LS`, `REQ`, `ACK`, `NAK`, `LIST`, `END`, with CAP 302 data. Ophion’s module lists visible caps, chunks LS output, mutates local cap bits, and rejects whole overlong ACKs (`modules/m_cap.c:173`, `:300`, `:320`, `:393`). Orochi models this as `CapRegistry(comptime caps)` plus per-client `CapSet`; outbound tags declare `required_caps`, and the encoder selects tags by intersection, matching Ophion’s capmask intent (`include/msgbuf.h:37`, `ircd/msgbuf.c:280`).

Send path: one per-shard writer owns each socket. Workers enqueue immutable `EncodedLine` references into an MPSC ring; writer batches by `writev`/`sendmsg` under io_uring. Backpressure is three-tier: soft throttle, hard disconnect for clients, negotiated credit for S2S. Ophion’s current lessons are sendq caps, one-writer shard routing, max flush bytes per tick, corking, and per-capability linebuf cache (`ircd/send.c:212`, `:314`, `:467`, `:527`, `:967`). Orochi makes those first-class: `SendBatch` groups recipients by `CapSet` and message template, so one render fans out to many clients without `printf` chains.

**Faithful LADON/VEIL Summary**
LADON today is not TS6 text: it is an 8-byte native frame header, MessagePack payloads, SWIM membership, CRDT anti-entropy, and VEIL wrapping post-auth traffic (`docs/protocols/ladon/overview.md:6`, `:8`, `:14`). Existing burst order is users, channels, CRDT, SWIM, cap state, then VEIL ratchet (`overview.md:12`). Frame header fields are `type`, `ctrl`, `uint16 length`, 24-bit `stream_id`, `hop_count` (`wire-protocol.md:10`). Frame bands include control, SWIM/CRDT, IRC app, caps, VEIL, and media (`wire-protocol.md:36`). HELLO is MessagePack with version, server, caps, time, Ed25519 key, compression, checksum, SID, replica key (`wire-protocol.md:47`). AUTH is Ed25519-signed X25519 plus nonce; AUTH_OK confirms HKDF output (`wire-protocol.md:65`). Existing text-link MessagePack is a separate TS6 optimization and rejects NUL/CR/LF strings (`wire-protocol.md:74`, `:95`).

VEIL currently wraps non-control LADON frames after AUTH using X25519, HKDF-SHA256, ChaCha20-Poly1305 (`docs/protocols/veil-security.md:4`). It has `VEIL_HANDSHAKE`, response, ratchet data, and optional group key frames (`veil-security.md:10`). Ratchet frame plaintext is the full inner LADON header plus payload (`veil-security.md:70`, `:83`). Replay/reorder handling uses counters, skipped keys, max skip 256, and commits receive state only after AEAD success (`veil-security.md:85`, `:96`, `:98`). Flow control starts at 4 MiB and VEIL credit must account for the full inner LADON frame size (`transport-state.md:28`).

**Beyond The Specs**
1. Replace MessagePack with **CoilPack**: a compact self-describing Zig-generated binary format. Header: varint schema id, varint field bitmap, canonical field order, typed atoms. Unknown fields are skipped; canonical encoding makes signatures stable. Use MessagePack only in transitional tooling, never on S2S.
2. Replace legacy SID-centered identity with `NodeId = BLAKE3-160(Ed25519 pubkey)`, display name as metadata, and `replica_id = first 64 bits` only as a compression alias. Existing libop uses first 8 Ed25519 bytes for replicas (`op_crdt.h:35`, `op_vclock.h:5`), but Orochi carries full NodeId on admission and abbreviates on hot paths.
3. Add **MeshPass** admission: an Ed25519-signed capability token containing node key, realm, roles, expiry, allowed frame families, max fanout, media rights, and revocation epoch. Admission requires configured trust root or quorum-signed invite from existing operators.
4. Add **Witnessed Gossip**: SWIM gossip entries include signer, HLC, suspicion evidence, and compact witness set. Byzantine or flaky nodes cannot force DEAD alone.

**S2S Protocol**
State machine: `TcpConnected -> HelloSent/Recv -> AuthProved -> VeilInit -> MeshEstablished -> Rekeying -> Draining -> Closed`. Before `MeshEstablished`, accept only HELLO/AUTH/AUTH_OK/VEIL/PING/CREDIT/ERROR, matching existing established-frame gating (`transport-state.md:10`, `:21`). Every frame has outer transport header, stream id, priority, credit cost, HLC, source NodeId, causal summary, and optional route hint.

VEIL protocol: AUTH derives `session_secret`; VEIL_INIT derives `root_key`, directional send/recv chains, nonce base, generation, and replay window. Each encrypted frame uses AD = outer header + peer NodeIds + generation + stream id + plaintext length. Payload is encrypted `InnerFrame{type, flags, stream, seq, body}`. Rekey every time interval, byte budget, or message count; old generation remains in drain window for reordered frames. Replay state is a gap-aware bitmap plus skipped-key cache; AEAD failure never advances counters, preserving the current VEIL invariant (`veil-security.md:91`, `:98`).

Transport: one io_uring peer actor owns socket, crypto state, credit windows, and stream schedulers. Streams: `0 control`, `1 gossip`, `2 anti_entropy`, `3 irc_events`, `4 services`, `5 media_control`, `>=64 media/data`. Priority scheduler is weighted deficit round-robin: control > repair > IRC > media retransmit > bulk media. Credit is charged on encrypted inner-frame length, not user payload.

**Membership**
SWIM: direct ping every randomized interval, indirect `PING_REQ` to k witnesses, suspicion before dead, explicit leave tombstones, incarnation counters. Existing LADON already names direct probes, indirect probes, and ALIVE/SUSPECT/DEAD (`overview.md:14`); Orochi adds signed membership deltas and per-node health CRDT. Large mesh scaling: partial views using HyParView-style active/passive sets; gossip fanout `O(log n)`; anti-entropy pull pairs selected by graph distance and failure domains. Routing uses a Zig-native weighted graph, matching libop’s graph reference for BFS/Dijkstra (`op_graph.h:11`, `:166`).

**CRDT State**
Use delta-state CRDTs because libop already frames OR-set deltas, causal contexts, HLC LWW, vector clocks, and Merkle sync as the substrate (`op_crdt.h:5`, `:159`, `:226`; `op_vclock.h:10`; `op_hlc.h:3`; `op_merkle.h:1`).

| Entity | CRDT | Resolution |
| --- | --- | --- |
| Users/UIDs | OR-Map `uid -> LWW profile + presence lease` | UID is immutable; disconnect is lease expiry plus tombstone. |
| Nicks | MV-register claim set `nick -> {uid,node,hlc,authority}` | Winner by authority, then HLC, then NodeId. Losers are renamed to UID, never killed, satisfying brief (`BRIEF.md:50`). |
| Channels | OR-Map `channel -> ChannelRoot` | Root has Min-HLC birth register for TS; ownership is signed grant set, not implicit from split side. |
| Memberships | OR-Set `(channel,uid,session)` | Part/kick removes observed dots; rejoin creates new dot. |
| Prefix modes | OR-Map `(channel,uid,mode) -> AuthToggle` | Higher authority can remove lower grants; concurrent same-authority add wins for voice/halfop/op. |
| Boolean modes | Causal toggle register | Policy per mode: restrictive modes add-wins, permissive modes remove-wins. |
| Param modes | LWW register with authority | Keyed by mode char; same HLC ties by writer (`op_crdt.h:229`). |
| Bans/exempts/invites | OR-Set normalized mask + metadata LWW | Concurrent add/remove uses observed-remove; unobserved concurrent add survives. |
| Topics | LWW register plus optional alternates | Display newest HLC; expose conflicts to opers through a cap-gated tag. |
| Accounts | Authority-signed OR-Map from services realm | Servers cannot invent account state; they relay signed assertions. |
| History/media presence | Bounded OR-Log with HLC | Pruned by retention watermarks and Merkle roots. |

Anti-entropy: every delta carries dot, HLC, vector summary, and entity bucket. Peers gossip hot deltas; pull repair compares Merkle roots per entity family, descends differing buckets, then requests missing dots. Vector clocks give causal coverage and concurrency (`op_vclock.h:96`); HLC gives near-wall ordering (`op_hlc.h:11`); Merkle diff bounds repair to differing leaves (`op_merkle.h:109`). Bloom filters are only prefilters for “do you probably have dot X?”, never authority, because false positives are possible (`op_bloom.h:48`).

**Partitions**
A mesh does not netsplit like a tree. Local partitions continue accepting local actions under degraded trust labels. Users see cap-gated tags such as `orochi.net/partition=regional`, `orochi.net/conflict=topic`, and oper numerics for suspect/dead nodes. On heal, CRDTs converge; no mass kills, nick losers rename to UID, channel state merges, bans union by observed-remove semantics, and services-signed account state overrides unauthenticated local claims.

**Media**
Existing LADON media exposes `ophion/ladon-media`, `MEDIAFRAME`, `MEDIA`, policy modes/properties, and frame families for voice/video/stats/negotiation/simulcast/ABR (`ladon/media.md:10`, `:27`, `:68`, `:105`). Orochi keeps client-facing IRC commands for compatibility but moves S2S media to streams: media control is reliable VEIL; media data is optionally unreliable QUIC-like datagrams over LADON streams with FEC/NACK. Server role is SFU/relay by default, mixer optional; E2E media keys are client group keys relayed as signed envelopes, matching the current E2E/key-management module intent (`m_ladon_e2e.md:1`).

**Migration**
Recommend clean break. A bridge is useful only as a separate gateway process that terminates TS6/Ophion and republishes sanitized events into Orochi with lower authority. Do not embed TS6 in the daemon; it violates the brief’s “No TS6” constraint and would contaminate CRDT conflict semantics (`BRIEF.md:50`).

**Novel Technologies**
1. **CoilPack**: canonical Zig-generated wire codec with schema ids, skip-safe fields, and signature-stable encoding.
2. **MeshPass**: Ed25519 admission/capability token with expiry, roles, frame-family rights, and revocation epoch.
3. **NickClaim MV-Reg**: deterministic nick uniqueness where collisions converge by rename-to-UID, not kill.
4. **Witnessed SWIM**: signed suspicion/dead evidence with witness quorum thresholds.
5. **CausalTags**: client-visible, cap-gated IRCv3 tags for partition, conflict, repair, and delayed-order context.
6. **Merkle Lanes**: per-entity anti-entropy lanes with adaptive bucket depth and bandwidth budgets.

**Threats/Risks**
Byzantine nodes: admission tokens, signed deltas, witnessed gossip, and services authority reduce damage but do not make arbitrary trusted nodes harmless. Replay: VEIL counters, generation, AD, skipped-key single use. CRDT metadata growth: causal-context compaction, tombstone TTL after vector-watermark stability, Merkle bucket pruning. Convergence latency: bounded by gossip fanout plus anti-entropy interval, but partitions can delay truth. User-visible ordering anomalies remain possible; expose HLC/order tags under caps rather than pretending total order exists.

