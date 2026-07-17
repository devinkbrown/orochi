# Orochi agent operating contract

## Scope and source of truth

- Work only in the Orochi repository unless the task explicitly names a deployment host.
- Treat the current source and tests as authoritative. Roadmaps and prose may lag implementation.
- Orochi is a pure-Zig IRC/IRCX daemon with a secured Suimyaku mesh. Do not introduce C interop or replace the native mesh with a tree protocol.
- The production contract is mesh-wide: every attached client in a reusable session remains connected, can participate independently, and observes the same accepted events after migration or Helix upgrade on any node.

## Parallel work

- Give each writing agent an explicit, non-overlapping file set. One agent owns integration files such as `src/daemon/server.zig` at a time.
- Use parallel agents primarily for bounded modules, read-only audits, test execution, and log analysis.
- Before editing a file, check whether another active agent owns it. Route integration requests to that owner instead of racing edits.
- Return concise evidence: files changed, invariants covered, exact commands, pass counts, and unresolved risks.

## Helix and session invariants

- Current-version Helix state is strict and fail-closed. Missing, malformed, duplicated, trailing, or semantically inconsistent mandatory state must abort adoption transactionally.
- Legacy decoding belongs only in explicit cold-migration paths. Never let a current Helix restore silently fall back to a legacy decoder.
- Preserve every live attachment by physical connection identity. Shared account/session identity must not collapse per-client channel membership, modes, invites, participation, or delivery.
- Reusable local session tokens remain stable across sequential upgrades. Renewable mesh migration tokens may rotate, but must reopen to the same account and session and remain valid under their envelope rules.
- Mesh relays require stable origin identity, exact-once acceptance, deterministic replay/equivocation handling, and byte-identical forwarding of signed origin frames.
- Checkpoint decode and adoption must be allocation-failure atomic: validate and stage completely before publishing replacement state.

## Verification

- Format touched Zig files with `zig fmt`.
- Use project-harness commands rather than direct daemon-file tests that import outside the module root.
- Run the narrowest relevant tests while iterating, then the affected build filters, `zig build check`, and `git diff --check`.
- Release readiness requires the full project gates, Debug and ReleaseSafe coverage for critical modules, deterministic multi-node/multi-client upgrade acceptance, and a clean reproducible release build.
- A green test is evidence only for the behavior it actually exercises. Identify vacuous topology, shard-count, transport, timing, and parser assertions.
- A fresh reviewer must try to refute release-critical changes. Authors do not grade their own work.

## Git and deployment safety

- Preserve unrelated user changes and untracked files. Never use destructive reset or checkout commands.
- Do not publish a dirty or unverified tree.
- For a release deployment: first reach a verified release commit; then update both servers and their configs; then hard-restart both `orochi.service` units; then run live two-node acceptance; then update documentation heavily; push GitHub last.
- Never signal or replace a live daemon with an artifact that has not passed the current release gates.

## Context preservation

- When compacting or handing off, preserve the active owners, modified files, exact failing/passing commands, deployment state, release order, and unresolved invariants.
