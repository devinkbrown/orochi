---
name: orochi-zig-verification
description: Select and run evidence-driven Orochi Zig verification. Use for focused gates, Debug and ReleaseSafe checks, allocation-failure sweeps, deterministic distributed fault tests, topology validation, full release gates, or judging whether an Orochi feature is actually done.
---

# Verify Orochi

Use project build steps. Direct tests of daemon files can fail because their imports escape the standalone module root.

1. Run `scripts/select-gates.py` with the changed paths to get the minimum gate set.
2. While iterating, run the narrowest filtered module or executable test and `zig build check`.
3. Run every affected named gate in Debug. Run critical session, Helix, mesh, crypto, persistence, and exact-once gates again with `-Doptimize=ReleaseSafe`.
4. Sweep every allocation index until one normal success occurs after the final injected failure. Assert byte-exact rollback, no leaks, no consumed replay identity, and successful retry.
5. Use deterministic seeds for scheduling, shard, reconnect, upgrade, queue-pressure, and partition faults. Print failing seeds and replay them before fixing.
6. Prove the topology is non-vacuous: distinct nodes, established secured links, intended capability bits, real client transports, nonzero deliveries, exact counts, and participation from every client.
7. Before release, run the full deterministic gate, reproducible release/package verification, and an independent review. Capture commands, exit codes, pass counts, elapsed time, and artifact commit hash.

A test name is not evidence. Inspect its assertions, transport, capability negotiation, failure injection, and cleanup before citing it.

After changing gate selection, run `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_select_gates.py`. A critical gate must always be a selected gate, and auth/session/Helix/mesh/event/live-server changes must retain ReleaseSafe coverage.
