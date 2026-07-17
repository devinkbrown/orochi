# Event Spine full-mesh v2 wiring contract

Status: protocol, replay substrate, and negotiated secured S2S transport
implemented; live daemon delivery/flood wiring pending.

The v1 `OPER_EVENT` payload is a direct-peer compatibility format. It carries no
stable identity or end-to-end proof, so an inbound v1 event may be delivered
locally but must never be forwarded. Decode it only on the legacy
`FrameType.OPER_EVENT` path via `oper_event.decodeLegacyV1`.

The full-mesh path uses `oper_event.SignedOperEventV2` and the strict
`encodeV2`/`decodeV2` APIs. Its author creates one immutable event with:

- the local self-certified `origin_node`;
- one `MeshClock` HLC, whose physical component is the shared Unix-ms event time;
- category, severity, origin server, the bounded filtering subject, and message;
  the subject is signed independently of the displayed message so every node
  applies the same per-category glob decision; and
- the original node public key and `stampOrigin` signature.

The author must stamp once. Relays forward the original v2 payload bytes without
rewriting the origin, HLC, subject, displayed fields, public key, or signature.

The canonical inner wire image is:

`"OEVT" | version=2 | flags=0 | category:u8 | severity:u8 |
origin_node:u64be | hlc:u64be | origin_len:u16be | subject_len:u16be |
message_len:u16be | origin_pubkey:32 | origin_signature:64 |
origin_server | subject | message`

`subject` is bounded to 256 bytes, is included in both the Ed25519 transcript
and stable event id, and is forwarded byte-for-byte. A local author sets it to
the exact `publishOperEventSubject` argument; an inbound receiver filters only
on the signed `event.subject`, never on a subject re-derived from the message.

## S2S transport contract

Event Spine v2 uses the distinct `FrameType.OPER_EVENT_V2` (`0x23`) and the
`event-spine-v2` capability (`0x80`). The capability occupies bit 7 of the
existing one-byte handshake and Helix S2S snapshot field, so it requires no
handshake-width or capsule-schema change. The frame is `secured_signed`: the
outer `signed_frame` authenticates the immediate peer while the inner OEVT
signature remains attributable to the original author across transit.

Only `SecuredLink` enables `event_spine_v2_transport_enabled`. Both it and the
remote capability must be present for `supportsEventSpineV2()` to return true.
The transport exposes three intentionally separate egress operations:

- `sendOperEventV2Authored`: stamp a canonical event with the local node key;
- `sendOperEventV2`: verify and canonically encode an already-stamped object;
- `forwardOperEventV2`: verify and forward the exact supplied inner wire bytes.

Inbound `takeOperEventsV2` items own the exact inner wire image and carry
`via_peer`, the authenticated immediate node. The bounded per-link cache only
suppresses reflection after signature verification and successful queueing.
Queue overflow, invalid input, and unnegotiated input do not mutate it. Legacy
`sendLegacyOperEvent`/`takeOperEvents` remain terminal local-delivery APIs and
have no forwarding operation.

The cache never suppresses verified inbound retries. A prior queued copy may
have been drained and rejected recoverably before daemon-global admission, so
the same leg must be allowed to queue it again. The cache is consulted only by
outbound send/forward operations to prevent reflection.

Hot resume must capture and restore both
`peer_supports_secure_relay_v2` and `peer_supports_event_spine_v2`; the latter
maps to `s2s_snapshot.cap_event_spine_v2`.

## Local publish order

1. Allocate one HLC before local delivery or peer fan-out.
2. Build and `stampOrigin` one v2 event with the node identity key.
3. Encode it once and retain that exact byte slice for every peer send.
4. Admit it through the daemon-global `event_spine_replay_guard.Guard`, passing
   current Unix ms and the configured future-skew bound.
5. Only `.accepted` may enter local delivery, EventHistory, EventStats, and peer
   forwarding. Use `event.originTimeMs()` for history and `server-time`; use the
   stable `(origin_node, hlc)` msgid derivation for client-visible identity.
6. Send the unchanged v2 payload to every established v2-capable direct peer.

Admitting the local event before sending is mandatory: a reflected copy then
lands as `.duplicate` rather than being delivered twice.

## Inbound v2 order

1. Require the negotiated OPER_EVENT v2 capability and the authenticated S2S
   envelope; never downgrade a malformed v2 payload into the v1 decoder.
2. Run `decodeV2` on the retained payload. It rejects unknown versions, reserved
   flags, non-canonical lengths, trailing/concatenated documents, and malformed
   identities.
3. Call the single daemon-global Event Spine replay guard. It authenticates the
   self-contained origin signature before touching replay state, rejects future
   HLCs without mutation, and keys authority by the full Ed25519 public key.
4. Handle the decision exactly:
   - `accepted`: deliver/history/stats once, causally observe the authenticated
     HLC, then forward the exact original bytes to every eligible peer except the
     ingress link;
   - `duplicate` or `retired`: drop without delivery, history, stats, or forwarding;
   - `equivocation`: drop and audit the origin (same origin/HLC, different signed
     event);
   - `origin_capacity`, `future_skew`, `origin_mismatch`, `bad_signature`, or
     `invalid_semantic`: fail closed and audit/rate-limit as appropriate.

Do not use a per-link SeenSet as the delivery boundary. It may suppress immediate
reflections, but only the global durable guard authorizes delivery.

## Checkpoint lifecycle

`event_spine_replay_guard.Guard.encodeCheckpoint` produces a canonical,
checksummed `ESG2` checkpoint whose inner greatest-W state permanently retires
evicted HLCs. Store it in a dedicated Helix capsule, distinct from MESSAGE_V2
replay state.

- Restore the guard before accepting OPER_EVENT v2 traffic.
- Replace from a checkpoint transactionally through `replaceFromCheckpoint`.
- Include the latest checkpoint in hot-upgrade capture/adoption.
- Persist after accepted admissions according to the daemon durability policy;
  a restart from an older checkpoint widens the replay window and is therefore
  not an exact-once boundary.

## Rolling compatibility

Capability negotiation selects one wire version per link. V2-capable nodes send
signed v2 and participate in multi-hop forwarding. A v1-only edge receives a
legacy direct notification as a terminal leaf; it cannot safely bridge that
event farther. The transitional `oper_event.encode`/`decode` aliases exist only
so the current v1 daemon compiles while its link APIs migrate; new code must use
the explicitly named versioned functions.
