---
name: orochi-message-spine
description: Implement and falsify Orochi Event Spine and MESSAGE_V2 exact-once delivery. Use for local authorship, signed relay, replay guards, ACK or retention, deferred authority, mixed-version peers, stable msgid/time, or mesh-wide event convergence.
---

# Build exact-once message delivery

Read `AGENTS.md`, `docs/architecture/event-spine.md`, `docs/design/event-spine-mesh-v2.md`, and `docs/design/message-v2-exact-once.md`. Trace local authorship, Lotus/history commit, Guard admission, recipient routing, secured S2S framing, replay, and Helix checkpointing as one transaction.

Enforce these properties:

- Author every supported local channel, notice, direct, whisper, and sender-session path as V2. A partial V1/V2 split is not release-ready.
- Use one immutable signed origin wire and one `RelayId` as relay identity, msgid, history identity, and replay key. Forward the accepted bytes unchanged.
- Verify origin registry, signature, clock bounds, authorization, target policy, and local authority before consuming the global replay guard.
- Build one deduplicated recipient set before delivery. Sender mirrors and channel membership must not create duplicate local delivery.
- A successful socket write is not receipt. Retain outbound accepted events until explicit acknowledgement or an equivalent durable anti-entropy proof; retry link loss, absence, OOM, queue pressure, and receiver deferral.
- Bound deferred and retained queues, include required state in Helix, and never advance a cursor until the recoverable handoff is durable.
- Prevent legacy replay from re-injecting a V1 copy into a V2 path. Mixed-capability convergence must preserve one logical event.

Required tests include a real A-B-C secured mesh, multiple clients sharing a session, link loss after write, absent receiver, queue saturation, unknown origin followed by convergence, future-clock recovery, OOM sweeps, equivocation, duplicate replay, sequential upgrades, and exact one-delivery assertions on every client.

Use `$orochi-server-integration` for live daemon wiring and `$orochi-zig-verification` for gates.
