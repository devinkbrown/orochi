---
name: orochi-cross-model-review
description: Run bounded, grounded, independent Claude review of Orochi changes. Use for fresh mechanical, integration, security, Helix, mesh, crypto, token, replay, or release-critical review without granting Claude write access.
---

# Run grounded cross-model review

Invoke Claude only through `tools/claude-review.sh` for release evidence.

1. Wait until the scoped writer has stopped changing the files.
2. Select `fast` for small mechanical codecs, `integration` for ownership/lifecycle seams, or `security` for tokens, Helix, mesh, replay, crypto, and adversarial boundaries.
3. Pass only repository-relative regular files. Split broad reviews into seams rather than raising scope caps.
4. Use a review-only agent. The launcher supplies exact hashes, line counts, a nonce, a strict JSON schema, no MCP, no browser, and read-only tools.
5. Accept output only when the launcher validates the exact file set and current source anchors.
6. Treat every finding as a hypothesis. Reproduce the counterexample in the current tree, route confirmed fixes to the single file owner, and discard ungrounded claims.
7. Run a fresh review after fixes. An author or the same context does not grade its own work.

Do not use direct ad hoc Claude prose as release evidence. Preserve rejected raw output for diagnosis, then remove temporary review artifacts after the issue is understood.
