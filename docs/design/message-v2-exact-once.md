# MESSAGE_V2 durable exact-once integration contract

Status: canonical signed codec, secured exact-wire transport, Lotus exact-once
ingestion, durable RVG2 replay authority, and mandatory Helix relation are
implemented. The daemon integration must follow the transaction below.

## Immutable transport object

`message_relay_v2.RelayMessage` signs every routing, rendering, logical-session,
origin, and HLC field. `verifyAndRelayId` validates semantics, constructs one
canonical transcript, verifies its Ed25519 proof, and derives one 16-byte
`RelayId` from those same authenticated bytes.

`InboundMessageV2` retains three views of one received object:

- `wire`: the exact canonical inner MESSAGE_V2 bytes;
- `owned.msg`: the decoded immutable fields used for policy and delivery; and
- `via_peer`: the authenticated immediate transport hop.

The CoilPack decoder rejects non-canonical maps, duplicate/unknown/missing keys,
overlong encodings, and trailing data. After daemon-global acceptance, forward
only `wire` through `forwardMessageV2`; never re-encode `owned.msg` in transit.
The forward API wraps the unchanged inner image in the next hop's signed,
encrypted envelope and returns `false` without writing on the ingress leg.

The per-link SeenSet is outbound-only reflection suppression. Verified inbound
duplicates are intentionally queued again: a prior drained copy might have met
a recoverable daemon rejection such as OOM or incomplete restore/registry
convergence. Only the durable global guard decides duplicate delivery.

## One accepted identity

Call `relay_v2_replay_guard.Guard.admitMessage(msg)`. It verifies the origin and
returns:

- `accepted: RelayId`;
- `duplicate`, `equivocation`, `retired`, or `origin_capacity`; or
- `origin_mismatch`, `bad_signature`, or `invalid_semantic`.

Only `accepted` carries an identity. That exact payload is the message identity
for Lotus, rendered msgid/server-time state, audit correlation, and forwarding.
Do not call `relayId` again after admission.

## Transactional guard and Lotus publication

Serialize this lane under one daemon-owned replay/history mutation lock.

1. Decode the retained canonical wire and prevalidate every daemon-owned bound
   and policy input: scope, target/history key, command, sender prefix, client
   tags, text, timestamp conversion, and the final RelayId-to-msgid encoding.
   A value this build cannot preserve exactly is rejected before any authority
   moves.
2. Stage a complete replay-guard candidate from the live RVG2 checkpoint and a
   complete Lotus candidate from the live Lotus checkpoint. No live object has
   changed yet.
3. Call `guard_candidate.admitMessage(msg)` exactly once.
4. On `accepted => relay_id`, build `lotus.ExactInputMessage` using the exact
   accepted id and signed message fields, then call
   `lotus_candidate.ingestExactOnce(history_target, input)`.
5. Only the pair `accepted` plus Lotus `.inserted` may publish. While still
   holding the mutation lock, swap both candidates into the live guard and
   Lotus store as one unobservable critical section. All reservations and
   fallible work must finish before the first swap.
6. After that publication, update SearchIndex/metrics and perform local delivery
   and exact-wire mesh forwarding. Projection failure may be audited and
   repaired, but it must not roll back or duplicate the accepted authorities.

Every other combination is side-effect-free:

- replay `duplicate`/`retired`: no Lotus, delivery, search, stats, or forwarding;
- replay `equivocation` or proof/semantic/capacity rejection: audit and drop;
- replay `accepted` with Lotus `.exact_duplicate` or `.equivocation`: the staged
  authorities disagree, so publish neither candidate, audit the invariant
  failure, and request repair;
- OOM anywhere before both swaps: deinitialize candidates and leave both live
  checkpoints byte-identical.

A locally authored v2 message uses the same path before its first local delivery
or peer send. Encode the accepted signed object once and give every eligible
secured link that same canonical wire image.

## Mesh-wide authoring barrier

Bridge binaries default to `relay_v2_authoring = "compat"`: they receive, ACK,
retain, replay, and forward MESSAGE_V2 while authoring only legacy events. An
active node instead durably admits each V2-eligible local event and sends only
the accepted V2 object. `relayLegacyToPeers(..., v2_admitted=true)` is a hard
no-op; emitting a legacy twin would make a rolling-old peer deliver the event
once immediately and again when its retained V2 copy replays after upgrade.

Activation therefore uses an external full-inventory barrier: deploy bridge
code everywhere; stage one exact non-zero epoch and full public-key roster on
every node while compatible; Helix-reload every node; verify identical live
epoch/digest/count plus the local bridge implementation marker; then change only mode to active and
reload sequentially. The full roster is canonicalized independently of order
or hex/base64 representation. It must contain the configured local identity
and every direct trust root, but it is not by itself a signed READY certificate
and does not prove graph-wide readiness. The deployment system owns that proof.

Staged epochs are monotonic and immutable: they cannot be removed, decreased,
or rebound to another roster; replacement by a strictly higher epoch is allowed
only while the predecessor remains compatible.
Activation requires the predecessor's exact staged tuple. Once active, mode and
tuple are immutable across current Helix handoff. Cold boot has no durable
previous-active floor, so operational rollback must preserve the exact active
tuple and must never boot compatibility or older code after activation.
Roster change after activation is not implemented and requires a future
protocol/release.

## Hot-upgrade authority

RVG2 and Lotus must be captured under the same replay/history mutation lock so
the handoff cannot describe different acceptance cuts. Restore stages and
validates every dependent object before publishing any of them.

The current Helix relation requires exactly one RVG2 capsule alongside exactly
one ESG2 capsule and one current MHLC v3 activation authority:

- capsule kind `.mesh_checkpoint`;
- current mesh-checkpoint schema/version/max and exactly ordinal-1 payload;
- `min_supported = 2`;
- inner magic `RVG2`, inner version 1, canonical checksum/order/watermarks; and
- encoded `{window_size, max_origins}` exactly equal to the operator-owned live
  guard config during `Guard.decodeCheckpoint`.

MHLC v3 carries the HLC high-water mark, migration-offer epoch, and exact
MESSAGE_V2 `{mode, activation_epoch, roster_digest}`. Current handoff requires
`min_supported = 2`, rejects v1/v2, duplicates, malformed semantics, and illegal
predecessor-to-successor transitions before publishing any inherited state.

`isCheckpoint` is only a magic-family selector. `validateCheckpoint` is the
allocation-free strict whole-image validator used by the relation pass;
`decodeCheckpoint` performs the config-bound staged restore. Missing, duplicate,
corrupt, non-canonical, downgraded, config-mismatched, or OOM-failed authorities
abort adoption without changing the predecessor or successor live state.

Legacy MESSAGE remains a separate direct compatibility path. It cannot enter or
weaken this v2 exact-once authority.

## Cold-restart durability contract

"Durable" throughout this file — including the title and every "Bounded
durable" module doc-comment — means **retransmit-until-ACK obligation that
survives a Helix (SIGUSR2) checkpoint restore**, not crash- or power-loss
durable. There is no disk write-ahead log behind this custody plane.

The four custody authorities are in-memory only:

- RVL2 accepted-event authority (`src/daemon/relay_v2_event_log.zig:4`), which
  retires a retained wire once every required node confirms
  (`relay_v2_event_log.zig:16-17`);
- RVO2 per-hop retransmission authority (`src/daemon/relay_v2_outbox.zig:4-9`),
  which retains the exact wire "until that peer authenticates an ACK";
- RVG2 replay/equivocation authority (`src/daemon/relay_v2_replay_guard.zig:4-6`);
  and
- ADS1 rendered-record authority (`src/daemon/attachment_delivery_spool.zig:4-11`),
  which is deliberately lock-free with no disk backing.

Each exposes `encodeCheckpoint`/`decodeCheckpoint`
(`relay_v2_event_log.zig:761`, `relay_v2_outbox.zig:390`,
`relay_v2_replay_guard.zig:285`, `attachment_delivery_spool.zig:648`), but those
checkpoints are sealed **only into the Helix in-memory upgrade capsule at
re-exec** — `OROCHI_HELIX_UPGRADE_CAPS` advertises `relay-v2-event-log-v1`,
`relay-v2-outbox-v2`, `attachment-delivery-spool-v1`, and the `mesh-checkpoint-v2`
capsule that carries RVG2 (`src/daemon/helix/live.zig:268`), and adoption
requires exactly one of each (`src/daemon/helix/handoff_relations.zig:319-321`).
The re-exec seals `relay_replay_bytes` and `event_replay_bytes` as mandatory
capsule state passed across `execve` (`src/daemon/server.zig:23725`). No path
writes them to storage: the OroStore disk WAL has families only for
`accounts, nicks, chanregs, bans, memos, vhosts, props, history`
(`src/daemon/store.zig:55-64`) — none for relay, custody, spool, or message_v2 —
and the four custody modules contain no file I/O.

**Consequence — last-copy loss on cold restart.** Consider an intermediate node
B relaying an origin-signed message from upstream A toward downstream C. B admits
the message, records A among the confirmed nodes, and returns a durable ACK to A.
Once B's ACK completes A's required-node set, A may retire its own retained wire
(`relay_v2_event_log.zig:16-17`), so B becomes the last custodian of the
still-unconfirmed retransmission obligation to C (held in RVO2,
`relay_v2_outbox.zig:4-9`). If B now suffers a power loss or a systemd **cold**
restart (`systemctl restart`, not `reload`) before that obligation to C is
ACKed, no checkpoint was ever captured — capture happens only at the USR2 re-exec
boundary — and B's in-memory RVL2/RVO2/RVG2/ADS1 state is gone. The last custody
copy of that message is lost, and exact-once delivery to C is not recovered. This
plane is therefore **not crash-durable**.

**Supported contract.** The only custody-preserving transition is a
connection-preserving Helix migration (`systemctl reload orochi`), where the
checkpoints above ride the in-memory capsule across `execve`. A hard restart is
supported only from a **drained, clean boundary** — a node with no unconfirmed
custody obligations outstanding (no un-ACKed RVO2 rows, no unretired RVL2 wire).
Cold-restarting a node that still holds custody obligations can silently drop the
last copy of an in-flight message. A disk-backed custody WAL that would make this
plane crash-durable is future work and is not implemented in this build.
