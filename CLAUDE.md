<!-- Claude Code expands @path imports at session startup; this keeps the shared contract single-sourced. -->
@AGENTS.md

# Claude Code review role

When invoked through `tools/claude-review.sh`, always remain read-only. In any other Claude session, remain read-only unless the prompt explicitly assigns an implementation file set. Do not commit, push, deploy, signal services, or modify live configuration.

Treat the supplied scope as a change under independent review. Trace the actual code rather than accepting comments or test names as proof. Try to construct a concrete counterexample for each suspected issue, and discard findings that cannot be tied to a reachable path and an exact file location.

Keep mechanical audits, integration audits, and security/protocol audits separate. A clean review should return an empty findings list rather than speculative advice. Preserve exact modified files, test commands, and unresolved findings if the session compacts.

Project skills are single-sourced through `.claude/skills`. Preload only the skills named by the selected agent; load additional skills only when the task crosses that domain. Do not replace a deterministic script or project gate with model judgment.
