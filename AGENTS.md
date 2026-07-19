# Onyx Server agent operating contract

## Product naming

- **Product / engine name:** **Onyx Server** (formerly Onyx Server). Binary and packaging names use `onyx-server`. Do not call the product "Onyx" in new prose.
- **Network / client brand:** **Onyx** (consumer-facing). IRCXNet is retired public identity only.
- **English subsystem codenames** (use these in docs and comments; Japanese forms are etymology only): **Undertow** (mesh CRDT state), **Ripple**, **Concord**, **Mooring** (S2S secure channel), **Armor** (TLS/crypto), **Helix** (USR2 hot-upgrade), **Ringlane**, **CadenceVox** / **CadenceVis**. Authoritative map: `docs/reference/glossary.md`.
- **Keep as-is (not product renames):** `onyx-*` Codex agent and skill IDs (real roster names under `.codex/agents/` and `.agents/skills/`); wire/config literals (`onyx/*` caps/tags, `onyx-server-node.key`, crypto domain labels, `ONYX_*` env vars, internal `@import("onyx_server")`); live runtime paths under `/home/kain/onyx-server-run` until a deploy-gated migration.
- **Repository path:** `/home/kain/onyx-server` (there is no `/home/kain/onyx-server` source tree).

## Scope and source of truth

- Work only in the Onyx Server repository unless the task explicitly names a deployment host.
- Treat the current source and tests as authoritative. Roadmaps and prose may lag implementation.
- Onyx Server is a pure-Zig IRC/IRCX daemon with a secured Undertow mesh. Do not introduce C interop or replace the native mesh with a tree protocol.
- The production contract is mesh-wide: every attached client in a reusable session remains connected, can participate independently, and observes the same accepted events after migration or Helix upgrade on any node.

## Parallel work

- Give each writing agent an explicit, non-overlapping file set. The named `onyx-server-integrator` is always the sole `src/daemon/server.zig` writer; the parent never transfers that file to another role, even temporarily.
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

## Claude review routing

- Invoke Claude through `tools/claude-review.sh`; direct ad hoc review output is not release evidence.
- Pass an explicit repository-relative file scope. The launcher gives Claude only exact-path `Read` access to an immutable private snapshot and rejects output unless every scoped file has a valid source anchor and every finding stays inside that scope.
- Use `fast` (Haiku/low) for codecs and mechanical consistency, `integration` (Sonnet/medium) for ownership and lifecycle seams, and `security` (Sonnet/high) for Helix, mesh, replay, token, and adversarial boundaries.
- Use `onyx-reviewer` when a domain-specific lens must be supplied in the prompt. Writer agents do not enter the structured-review launcher; use a fresh reviewer instead.
- Treat Claude findings as hypotheses. Codex reproduces each counterexample against the current tree, routes confirmed fixes to the single file owner, and sends the fixed scope through a fresh review.

## Codex specialist routing

- Project-scoped native roles live in `.codex/agents/` and inherit the active Codex model. Use `zig-coder` for bounded leaf-module implementation, `onyx-session` for session/migration/Helix leaf state, and `onyx-server-integrator` as the sole `server.zig` writer.
- Use `onyx-server-dst` for deterministic fault campaigns and `onyx-reviewer` as a fresh read-only adversarial gate. Rotate `onyx-release-gate`, `onyx-server-deploy`, and `onyx-docs` only at their explicit handoff points.
- A specialist role does not override the one-writer-per-file rule. The parent assigns disjoint files, retains integration authority, validates returned evidence, and decides what is committed.
- Use `onyx-agent-architect` only to audit or evolve the roster itself. It is read-only and should reduce overlap, not create agents reflexively.

## Skills and deterministic tooling

- Canonical project skills live under `.agents/skills`; `.claude/skills` exposes the same tree so Codex and Claude use one source of truth.
- Use `onyx-server-roadmap-execution` to resume or select roadmap slices, `onyx-server-session-mesh` for reusable sessions, `onyx-server-message-spine` for exact-once events, and `onyx-server-integration` for live daemon wiring.
- Use `onyx-server-zig-verification` for gate selection and fault evidence, `onyx-server-cross-model-review` for grounded Claude review, and `onyx-server-release-deploy` for the ordered release workflow.
- Use `onyx-server-agent-toolkit` only when changing the workflow itself. After agent, skill, or review-launcher changes, run its validator, Python authority tests, and snapshot-isolation shell regression.

## Git and deployment safety

- Preserve unrelated user changes and untracked files. Never use destructive reset or checkout commands.
- Do not publish a dirty or unverified tree.
- For a release deployment: first reach a verified release commit; then update both servers and their configs; then hard-restart both nodes' systemd units (packaging unit name `onyx-server.service`; live units may still be `onyx-server.service` until the deploy-gated rename); then run live two-node acceptance; then update documentation heavily; push GitHub last.
- Never signal or replace a live daemon with an artifact that has not passed the current release gates.

## Context preservation

- When compacting or handing off, preserve the active owners, modified files, exact failing/passing commands, deployment state, release order, and unresolved invariants.
