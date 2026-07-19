---
name: onyx-server-integration
description: Integrate completed Onyx Server modules into daemon lifecycle and server.zig transactionally. Use when wiring session, Helix, mesh, Event Spine, delivery, persistence, capability, reconnect, or shutdown behavior into the live server.
---

# Integrate the live daemon

The `onyx-server-integrator` role holds a permanent named-role reservation on `src/daemon/server.zig` across all assignments. No other role may receive that file. Do not absorb leaf-module work that another agent owns.

Before editing, write down the full lifecycle: initialization, local authorship, inbound admission, routing, persistence, outbound queueing, disconnect, reconnect, RESYNC, Helix seal/adopt, and shutdown. Identify every state owner and lock.

Implement in this order:

1. Validate immutable input and authenticated authority.
2. Allocate and encode every fallible candidate before mutating live state.
3. Stage all related stores under the same logical cut. Use a fixed lock order and keep shared snapshot pairs under one cut.
4. Commit with no-fail swaps only after all validation and staging succeeds.
5. Publish delivery or outbound work after commit, or retain it durably before acknowledging success.
6. On retryable failure, leave live state byte-equivalent and keep cursors, guards, epochs, and plaintext queues retry-safe.

Prefer route-first session authority over nick lookup. Build recipient sets once and deduplicate before writes. Do not treat `send` success as peer receipt. Negotiate one capability decision per link and prevent current peers from receiving both legacy and current representations.

Add live-path tests, not only helper tests. Exercise real command parsing, SessionStore selection, World projection, secured links, reconnect/RESYNC, and Helix adoption. Run the focused module tests before `test-server`, affected mesh/Helix/services gates, `zig build check`, and `git diff --check`.
