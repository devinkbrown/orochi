# 08 — The Orochi Vision (design brief)

> Synthesized 2026-06-04 from a codex design consultation + the owner's directive
> to "make the IRC vision amazing." This is the north star the parity work
> (`07-parity-100.md`) is substrate FOR — parity is not the product, the mesh is.

## The five differentiators

1. **Partition-Proof Rooms.** No netsplit drama, no split-side takeovers, no mass
   kills. Channels (members, modes, bans, topic, history) are delta-CRDTs with
   HLC + dotted causality + Merkle repair + Sazanami membership. Channel
   authority is *signed grants*, not "which server won the split." Risk: users
   see causality artifacts unless partition/conflict tags are exposed honestly.

2. **Sovereign Identity, not platform identity.** An account multi-homes across
   nodes, survives server loss, carries certfp/PQ credentials with no single
   central service. Server + account assertions are signed objects; **nicks are
   claims in an MV-register — losers rename to UID, never die.** Risk: services
   authority must be crisp, or it's "Discord with worse consistency."

3. **Secure Federation by default.** S2S is harvest-now-decrypt-later resistant,
   forward-secret, replay-aware, auditable — never bolted on. Suimyaku peer auth
   → hybrid X25519+ML-KEM root; Tsumugi per-frame ratchet + scheduled hybrid
   rekeys; MeshPass gates admission. Risk: clean-room crypto/TLS is the highest
   bet — narrow TLS 1.3 scope, mandatory test vectors, audit before open fed.

4. **IRC speed with a Discord-grade product surface.** Text-protocol compat +
   IRC latency, plus history, edit/redact, read markers, media signaling, IRCX
   access/props, durable services. Lotus content-addressed history + Event Spine
   + comptime SerpentRegistry. Risk: feature sprawl burying the mesh.

5. **Deterministic operations.** Replay seeds, causal traces, zero-disconnect
   upgrades. Deterministic Ocean + Fault Loom + typed Helix upgrade capsules +
   share-nothing Ringlane shards. Risk: simulator drift — prod and sim MUST link
   the same protocol/state code.

## Where the CRDT genuinely changes IRC semantics

- Channels become **add-wins, repairable state**, not burst text.
- History becomes **eventually consistent with retention watermarks**, not
  "whatever server you happened to hit."
- **Nicks become claims, not identities.** Accounts become signed authority facts.
- Netsplit/netjoin batches become **compatibility views** over partition metadata.

### Invariants that must hold

- UID immutable; every mutation carries `{origin, dot/HLC, authority}`.
- Observed-remove only removes observed dots; tombstone GC waits for causal
  stability across live peers.
- Services assertions are signed; restrictive modes converge safely.
- **No peer may declare another DEAD alone** (witnessed SWIM).

## Contrarian bet

**Drop nickname primacy entirely.** The stable identity is account/key/UID; the
nick is a human-readable, conflict-prone *display claim*. This single change
unlocks sane mesh healing — and it's already half-encoded in the
collision→rename-to-UID rule.

## Ranked next build moves (vision-weighted)

1. Finish channel-mode truth: +e/+I, mode queries (params to members), multi-mode
   batching, **nick collision rename-to-UID**. ← current parity track
2. Wire IRCv3 message-tags / batch / labeled-response (CausalTags need this surface).
3. Account / certfp / SASL EXTERNAL / SCRAM + **signed account assertions**.
4. Lotus minimal CHATHISTORY with msgid + edit + redact + read-marker.
5. Extend the `Reactor` seam beyond time into accept/recv/send/timer; SimReactor E2E.
6. Promote the Suimyaku peer handshake into a real TCP peer actor with credit/backpressure.
7. CRDT world model for users/channels/modes — first in a deterministic 3-node sim.
8. Merkle anti-entropy repair + partition/heal simulator campaigns.
9. Integrate Tsumugi around established Suimyaku frames (restart/reorder vectors).
10. Event Spine + operator causal-trace view before media.

> The through-line: every parity command we wire now should be designed so its
> state is **CRDT-portable** later — modes, bans, topic, membership, account.
> Build the single-node truth so the mesh can replicate it without a rewrite.
