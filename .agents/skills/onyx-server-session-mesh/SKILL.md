---
name: onyx-server-session-mesh
description: Implement and verify Onyx Server reusable sessions across the secured mesh. Use for session tokens, resume, multi-attachment, migration, reclaim, replica convergence, sequential Helix upgrades, or any requirement that every client stay connected and participate from any mesh node.
---

# Build exact mesh-wide sessions

Read `AGENTS.md` and `docs/design/session-resume-anywhere-blueprint.md`, then trace the live paths in `src/daemon/server.zig`, `src/daemon/sessions.zig`, `src/daemon/world.zig`, `src/daemon/helix/session_*`, `src/daemon/helix/migration_*`, `src/daemon/helix/session_replica.zig`, `src/proto/session_reclaim_mesh.zig`, `src/proto/session_replica_frame.zig`, and the secured S2S stack.

Preserve these invariants:

- A reusable local session token is stable across sequential upgrades. Validate each signed credential against its own canonical schema and replay domain. Do not add a per-peer audience to a forwardable multi-hop replica, and do not assume legacy relay, reclaim, replica, and local resume objects carry the same fields.
- One logical session may have many physical client attachments. Never collapse per-connection membership, modes, invites, parser/TLS state, delivery state, or participation by nick, account, or token.
- Resolve authority route-first through the session store and authenticated origin. Nick lookup is not session authority.
- Current Helix restore is strict, mandatory, staged, and atomic. Checkpoint counters, nonces, replay cursors, deferred work, capability state, and epochs whose reset could change behavior after exec.
- Treat allocation failure and send-queue pressure as retryable without partial publication, burned tokens, advanced cursors, duplicated plaintext, or lost retained state.
- Distinguish a capability-old current process from an arbitrary pre-checkpoint binary. Test mixed capability with current checkpoint schemas. A genuinely incompatible binary requires an explicit accepted-loss cold boundary and cannot satisfy session-preserving acceptance.

Required acceptance topology:

1. Build a three-node non-clique line A-B-C and prove origin state crosses B unchanged, then disconnect and reconnect a link to exercise retained anti-entropy.
2. Attach at least four clients to one shared token across the secured mesh and prove all existing transports remain alive and independently participatory.
3. Upgrade node A, then node B, preserving the same local token and exact per-client state.
4. Resume a fifth client on the opposite edge node.
5. Send channel and direct traffic from every attachment and assert every eligible client sees each accepted event exactly once with stable identity.
6. Sweep allocation failures across decode, staging, checkpoint publish, replay, and send-queue boundaries in Debug and ReleaseSafe.

Never edit `src/daemon/server.zig`. Report the exact seam and hand it to the permanently named `onyx-server-integrator` role.
