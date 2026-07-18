#!/usr/bin/env python3
"""Regression tests for authority-sensitive toolkit validation."""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path


VALIDATOR = Path(__file__).with_name("validate_toolkit.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("validate_toolkit", VALIDATOR)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class AuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        validator.ROOT = self.root
        validator.CODEX = self.root / ".codex" / "agents"
        validator.CLAUDE = self.root / ".claude" / "agents"
        validator.SKILLS = self.root / ".agents" / "skills"
        validator.CODEX.mkdir(parents=True)
        validator.CLAUDE.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_codex_architect(self, sandbox: str) -> None:
        (validator.CODEX / "orochi-agent-architect.toml").write_text(
            'name = "orochi-agent-architect"\n'
            'description = "Audit only"\n'
            'model_reasoning_effort = "xhigh"\n'
            f'sandbox_mode = "{sandbox}"\n'
            'developer_instructions = "Remain read-only."\n',
            encoding="utf-8",
        )

    def write_claude_architect(self, tools: str) -> None:
        (validator.CLAUDE / "orochi-agent-architect.md").write_text(
            "---\n"
            "name: orochi-agent-architect\n"
            "description: Audit only\n"
            f"tools: {tools}\n"
            "model: claude-sonnet-5\n"
            "effort: high\n"
            "---\n\nRemain read-only.\n",
            encoding="utf-8",
        )

    def write_codex_zig_coder(self, instructions: str) -> None:
        (validator.CODEX / "zig-coder.toml").write_text(
            'name = "zig-coder"\n'
            'description = "Leaf writer"\n'
            'model_reasoning_effort = "high"\n'
            'sandbox_mode = "workspace-write"\n'
            f'developer_instructions = "{instructions}"\n',
            encoding="utf-8",
        )

    def write_claude_zig_coder(self, instructions: str) -> None:
        (validator.CLAUDE / "zig-coder-leaf.md").write_text(
            "---\n"
            "name: zig-coder-leaf\n"
            "description: Leaf writer\n"
            "tools: Read, Grep, Glob, Bash, Write, Edit, Skill\n"
            "model: claude-sonnet-5\n"
            "effort: high\n"
            "---\n\n"
            f"{instructions}\n",
            encoding="utf-8",
        )

    def write_codex_server_integrator(self, instructions: str) -> None:
        (validator.CODEX / "orochi-server-integrator.toml").write_text(
            'name = "orochi-server-integrator"\n'
            'description = "Sole server writer"\n'
            'model_reasoning_effort = "xhigh"\n'
            'sandbox_mode = "workspace-write"\n'
            f'developer_instructions = "{instructions}"\n',
            encoding="utf-8",
        )

    def write_claude_server_integrator(self, instructions: str) -> None:
        (validator.CLAUDE / "orochi-server-integrator.md").write_text(
            "---\n"
            "name: orochi-server-integrator\n"
            "description: Sole server writer\n"
            "tools: Read, Grep, Glob, Bash, Write, Edit, Skill\n"
            "model: claude-sonnet-5\n"
            "effort: high\n"
            "---\n\n"
            f"{instructions}\n",
            encoding="utf-8",
        )

    def write_claude_only_writer(
        self,
        name: str,
        instructions: str,
        tools: str = "Read, Write, Edit",
    ) -> None:
        (validator.CLAUDE / f"{name}.md").write_text(
            "---\n"
            f"name: {name}\n"
            "description: Claude-only writer\n"
            f"tools: {tools}\n"
            "model: claude-sonnet-5\n"
            "effort: high\n"
            "---\n\n"
            f"{instructions}\n",
            encoding="utf-8",
        )

    def write_codex_docs(self, instructions: str) -> None:
        (validator.CODEX / "orochi-docs.toml").write_text(
            'name = "orochi-docs"\n'
            'description = "Docs writer"\n'
            'model_reasoning_effort = "high"\n'
            'sandbox_mode = "workspace-write"\n'
            f'developer_instructions = "{instructions}"\n',
            encoding="utf-8",
        )

    def write_codex_release_gate(self, sandbox: str) -> None:
        (validator.CODEX / "orochi-release-gate.toml").write_text(
            'name = "orochi-release-gate"\n'
            'description = "Runs release evidence without editing source."\n'
            'model_reasoning_effort = "high"\n'
            f'sandbox_mode = "{sandbox}"\n'
            'developer_instructions = "Do not edit source, docs, or configs."\n',
            encoding="utf-8",
        )

    def write_claude_docs(self, instructions: str) -> None:
        (validator.CLAUDE / "orochi-docs.md").write_text(
            "---\n"
            "name: orochi-docs\n"
            "description: Docs writer\n"
            "tools: Read, Grep, Glob, Bash, Write, Edit, Skill\n"
            "model: claude-sonnet-5\n"
            "effort: medium\n"
            "---\n\n"
            f"{instructions}\n",
            encoding="utf-8",
        )

    def test_codex_architect_rejects_workspace_write(self) -> None:
        self.write_codex_architect("workspace-write")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_codex()
        self.write_codex_architect("read-only")
        self.assertEqual({"orochi-agent-architect"}, validator.validate_codex())

    def test_codex_release_gate_enforces_no_edit_contract(self) -> None:
        self.write_codex_release_gate("workspace-write")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_codex()
        self.write_codex_release_gate("read-only")
        self.assertEqual({"orochi-release-gate"}, validator.validate_codex())

    def test_claude_architect_rejects_unexpected_tools(self) -> None:
        self.write_claude_architect("Read, Grep, Glob, Skill, WebFetch")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_claude(set())
        self.write_claude_architect("Read, Grep, Glob, Skill")
        self.assertEqual({"orochi-agent-architect"}, validator.validate_claude(set()))

    def test_non_integrator_writers_cannot_claim_server(self) -> None:
        self.write_codex_zig_coder(
            "It is false that we would never edit src/daemon/server.zig."
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_codex()
        self.write_codex_zig_coder(
            "SERVER_ZIG_ROLE: excluded\\nNever edit src/daemon/server.zig."
        )
        self.assertEqual({"zig-coder"}, validator.validate_codex())
        self.write_codex_zig_coder(
            "SERVER_ZIG_ROLE: excluded\\nNever edit src/daemon/server.zig. "
            "You may edit src/daemon/server.zig if the integrator is unavailable."
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_codex()

        self.write_claude_zig_coder(
            "It is false that we would never edit `src/daemon/server.zig`."
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_claude(set())
        self.write_claude_zig_coder(
            "SERVER_ZIG_ROLE: excluded\nNever edit `src/daemon/server.zig`."
        )
        self.assertEqual({"zig-coder-leaf"}, validator.validate_claude(set()))
        self.write_claude_zig_coder(
            "SERVER_ZIG_ROLE: excluded\nNever edit `src/daemon/server.zig`. "
            "You may edit `src/daemon/server.zig` if the integrator is unavailable."
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_claude(set())

    def test_server_integrator_requires_owner_authority(self) -> None:
        self.write_codex_server_integrator(
            "This role does NOT hold the permanent named-role reservation on src/daemon/server.zig."
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_codex()
        self.write_codex_server_integrator(
            "SERVER_ZIG_ROLE: owner\\n"
            "Hold the permanent named-role reservation on src/daemon/server.zig."
        )
        self.assertEqual({"orochi-server-integrator"}, validator.validate_codex())

        self.write_claude_server_integrator(
            "This role does NOT hold the permanent named-role reservation on `src/daemon/server.zig`."
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_claude(set())
        self.write_claude_server_integrator(
            "SERVER_ZIG_ROLE: owner\n"
            "Hold the permanent named-role reservation on `src/daemon/server.zig`."
        )
        self.assertEqual({"orochi-server-integrator"}, validator.validate_claude(set()))

    def test_claude_only_writer_requires_excluded_authority(self) -> None:
        name = "claude-only-writer"
        validator.CLAUDE_TOOLS[name] = {"Read", "Write", "Edit"}
        try:
            self.write_claude_only_writer(name, "Own arbitrary files.")
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    validator.validate_claude(set())
            self.write_claude_only_writer(
                name,
                "SERVER_ZIG_ROLE: excluded\nNever edit `src/daemon/server.zig`.",
            )
            self.assertEqual({name}, validator.validate_claude(set()))
            self.write_claude_only_writer(
                name,
                "SERVER_ZIG_ROLE: excluded\nNever edit `src/daemon/server.zig`. "
                "You may patch `src/daemon/server.zig` if the integrator is unavailable.",
            )
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    validator.validate_claude(set())
        finally:
            validator.CLAUDE_TOOLS.pop(name, None)

    def test_claude_bash_role_requires_excluded_authority(self) -> None:
        name = "claude-bash-role"
        validator.CLAUDE_TOOLS[name] = {"Read", "Bash"}
        try:
            self.write_claude_only_writer(name, "Run bounded evidence.", "Read, Bash")
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    validator.validate_claude(set())
            self.write_claude_only_writer(
                name,
                "SERVER_ZIG_ROLE: excluded\nNever edit `src/daemon/server.zig`.",
                "Read, Bash",
            )
            self.assertEqual({name}, validator.validate_claude(set()))
        finally:
            validator.CLAUDE_TOOLS.pop(name, None)

    def test_docs_writer_must_exclude_server(self) -> None:
        self.write_codex_docs("Edit documentation only.")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_codex()
        self.write_codex_docs(
            "SERVER_ZIG_ROLE: excluded\\nNever edit src/daemon/server.zig."
        )
        self.assertEqual({"orochi-docs"}, validator.validate_codex())

        self.write_claude_docs("Edit documentation only.")
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                validator.validate_claude(set())
        self.write_claude_docs(
            "SERVER_ZIG_ROLE: excluded\nNever edit `src/daemon/server.zig`."
        )
        self.assertEqual({"orochi-docs"}, validator.validate_claude(set()))


if __name__ == "__main__":
    unittest.main()
