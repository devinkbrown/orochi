---
name: onyx-server-agent-toolkit
description: Audit, evolve, and validate Onyx Server's Codex and Claude engineering toolkit. Use when adding or updating project agents, skills, model or effort routing, delegation rules, review launchers, worktree strategy, roster validation, or cross-model workflows.
---

# Maintain the Onyx Server agent toolkit

Research current official Codex and Claude documentation before changing platform-specific fields. Keep project knowledge in skills, isolation and authority in agents, universal constraints in `AGENTS.md`, and deterministic checks in scripts.

Design rules:

- Keep one writer per file. Use the integration agent as the sole `server.zig` owner while leaf agents work on disjoint modules.
- Fill the runtime's available agent slots with concrete independent work, but do not invent tasks to satisfy a number. Rotate test, review, release, and docs roles at handoffs.
- Keep Codex agents on the active configured model unless a task has a measured reason to override it. Use high or xhigh reasoning for integration and adversarial work.
- Route Claude mechanical review to Haiku/low, integration review to Sonnet/medium, and security/protocol review to Sonnet/high. Keep structured review read-only.
- Use worktrees only from a coherent commit when a worker does not need the current dirty tree. Do not use experimental agent teams for overlapping writes or sequential integration.
- Separate implementer, fresh reviewer, gate runner, deployer, and docs authority. Deployment never implies source-edit authority.
- Prefer a small reusable roster plus task skills over a permanent agent for every directory.

Use `.agents/skills` as the canonical project skill tree and expose it to Claude through `.claude/skills`. Run `scripts/validate_toolkit.py`, `scripts/test_validate_toolkit.py`, `scripts/test_claude_review_stub.py`, and `scripts/test_claude_review.sh` after every authority or launcher change. Validate every skill with the skill-creator validator, then run a grounded integration review of `AGENTS.md` and the changed definitions. The structured Claude launcher must expose only exact-file `Read` plus schema-return permissions over a private immutable snapshot; live checkout hashes are a relevance check, not the reviewer's source view.
