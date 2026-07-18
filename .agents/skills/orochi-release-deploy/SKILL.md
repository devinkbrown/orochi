---
name: orochi-release-deploy
description: "Execute Orochi's authorized two-node release in its mandatory order. Use only when release or deployment is explicitly requested: verify a release commit, update both server artifacts and configs, hard-restart systemd, run live mesh acceptance, update docs, then push GitHub last."
disable-model-invocation: true
---

# Release and deploy Orochi

Do not enter this workflow until the user has explicitly authorized deployment. Read `AGENTS.md`, `docs/RUNBOOK.md`, `packaging/release.sh`, `packaging/verify-release.sh`, and `etc/systemd/orochi.service`.

Follow this order without reordering:

1. Reach one verified release commit. Build from a fresh clean worktree at that exact commit so unrelated files in the active workspace are preserved and cannot taint provenance. Require full gates, critical ReleaseSafe gates, a reproducible package, verified provenance, and an artifact whose embedded revision matches the commit.
2. Preserve rollback artifacts and capture the pre-deploy revisions and service state on both nodes.
3. Update the local runtime under `/home/kain/orochi-run` and the remote runtime under `/home/trev/orochi-run` on `trev@ircx.us`. Do not print private keys or secrets.
4. Reconcile and validate `/home/kain/orochi-run/orochi.local.toml` and `/home/trev/orochi-run/orochi.ircxus.toml` against the new reference config before touching either service. Run `--check-config` on each file before the restart and never run the binary bare against a live runtime dir: a config `ParseError` does not stop boot, it silently falls back to the built-in DEFAULT identity (wrong server name and keys), so an unvalidated config can bring a live node up as the wrong server and needs a full restart to recover.
5. Hard-restart both `orochi.service` units with systemd. A signal-based Helix reload is not a hard restart.
6. Verify both units are active, running the expected artifact/config, mutually connected over the secured mesh, and free of startup or protocol errors.
7. Run live multi-node, multi-client acceptance: shared token, participation from every client, exact event delivery, cross-node resume, and reconnect after each restart. A hard restart necessarily replaces that node's TCP transports; record the expected disconnect and prove token-based recovery rather than calling it zero-drop.
8. Update documentation heavily from the deployed truth, including config, protocol, upgrade, operations, rollback, and acceptance evidence.
9. Commit the documentation/final release state and push GitHub last.

Stop and roll back on artifact mismatch, config validation failure, service failure, mesh divergence, lost client, duplicate/missing event, or token/resume failure. Do not push a failed deployment state.
