---
name: orochi-roadmap-execution
description: Audit and execute Orochi roadmap work from current source truth. Use when continuing the Orochi roadmap, resuming an interrupted Orochi implementation, selecting the next server-side slice, or coordinating parallel agents without losing existing work.
---

# Execute the Orochi roadmap

1. Read `AGENTS.md`, inspect `git status`, and identify active file owners before changing anything.
2. Read `/home/kain/OROCHI_ONYX_MASTER_ROADMAP.md` when it exists, but treat current source and tests as authoritative. Audit the relevant implementation read-only before selecting a slice.
3. Recover unfinished work instead of restarting it. Preserve current changes, pass/fail evidence, unresolved invariants, and deployment state.
4. Prefer server, protocol, mesh, Helix, persistence, and daemon acceptance work unless a server contract forces a client-facing change.
5. Fill available agent slots only with concrete, independent tasks. Give every writer an explicit non-overlapping file set; assign integration files such as `src/daemon/server.zig` to one owner.
6. Choose the smallest coherent slice that closes a user-visible contract end to end. Do not mark roadmap prose complete from a codec or helper test alone.
7. Use `$orochi-zig-verification` for evidence and a fresh reviewer for release-critical work. Commit a coherent green slice locally; do not publish or deploy unless the release workflow is explicitly active.

For reusable sessions or mesh migration, load `$orochi-session-mesh`. For Event Spine or message relay, load `$orochi-message-spine`. For `server.zig` wiring, load `$orochi-server-integration`.
