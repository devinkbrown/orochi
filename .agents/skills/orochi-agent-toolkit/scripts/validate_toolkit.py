#!/usr/bin/env python3
"""Validate Orochi's project-scoped Codex agents, Claude agents, and skills."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import TypeAlias


ROOT = Path(__file__).resolve().parents[4]
CODEX = ROOT / ".codex" / "agents"
CLAUDE = ROOT / ".claude" / "agents"
SKILLS = ROOT / ".agents" / "skills"
NAME = re.compile(r"^[a-z0-9-]+$")
REQUIRED_SHARED = {
    "zig-coder",
    "orochi-session",
    "orochi-server-integrator",
    "orochi-dst",
    "orochi-reviewer",
    "orochi-release-gate",
    "orochi-deploy",
    "orochi-docs",
    "orochi-agent-architect",
}
CODEX_SANDBOX = {
    "orochi-agent-architect": "read-only",
    "orochi-reviewer": "read-only",
    "orochi-deploy": "danger-full-access",
    "orochi-docs": "workspace-write",
    "orochi-dst": "workspace-write",
    "orochi-release-gate": "read-only",
    "orochi-server-integrator": "workspace-write",
    "orochi-session": "workspace-write",
    "zig-coder": "workspace-write",
}
CODEX_EFFORT = {
    "zig-coder": "high",
    "orochi-release-gate": "high",
    "orochi-docs": "high",
    "orochi-session": "xhigh",
    "orochi-server-integrator": "xhigh",
    "orochi-dst": "xhigh",
    "orochi-reviewer": "xhigh",
    "orochi-deploy": "xhigh",
    "orochi-agent-architect": "xhigh",
}
CLAUDE_TOOLS = {
    "orochi-agent-architect": {"Read", "Grep", "Glob", "Skill"},
    "orochi-reviewer": {"Read"},
    "orochi-fast-auditor": {"Read"},
    "orochi-integration-reviewer": {"Read"},
    "orochi-security-reviewer": {"Read"},
    "orochi-release-gate": {"Read", "Grep", "Glob", "Bash", "Skill"},
    "orochi-deploy-authorized": {"Read", "Grep", "Glob", "Bash", "Skill"},
    "orochi-docs": {"Read", "Grep", "Glob", "Bash", "Write", "Edit", "Skill"},
    "orochi-dst-leaf": {"Read", "Grep", "Glob", "Bash", "Write", "Edit", "Skill"},
    "orochi-server-integrator": {"Read", "Grep", "Glob", "Bash", "Write", "Edit", "Skill"},
    "orochi-session": {"Read", "Grep", "Glob", "Bash", "Write", "Edit", "Skill"},
    "zig-coder-leaf": {"Read", "Grep", "Glob", "Bash", "Write", "Edit", "Skill"},
}
CODEX_SERVER_EXCLUDED_WRITERS = {
    name
    for name, sandbox in CODEX_SANDBOX.items()
    if sandbox != "read-only" and name != "orochi-server-integrator"
}
CLAUDE_MODEL_EFFORT = {
    "orochi-fast-auditor": ("claude-sonnet-5", "low"),
    "orochi-integration-reviewer": ("claude-sonnet-5", "medium"),
    "orochi-security-reviewer": ("claude-sonnet-5", "high"),
    "orochi-release-gate": ("claude-sonnet-5", "medium"),
    "orochi-docs": ("claude-sonnet-5", "medium"),
}


def server_zig_role(text: str) -> str:
    """Return the one exact machine-readable server.zig authority marker."""
    markers = {
        line.strip().lower()
        for line in text.replace("`", "").splitlines()
        if line.strip().lower().startswith("server_zig_role:")
    }
    if len(markers) != 1:
        return ""
    marker = markers.pop()
    if marker == "server_zig_role: owner":
        return "owner"
    if marker == "server_zig_role: excluded":
        return "excluded"
    return ""


def server_exclusion_consistent(text: str) -> bool:
    normalized = text.replace("`", "").lower()
    required = "never edit src/daemon/server.zig"
    return required in normalized and normalized.count("server.zig") == 1


def server_owner_consistent(text: str) -> bool:
    normalized = text.replace("`", "").lower()
    required = "hold the permanent named-role reservation on src/daemon/server.zig"
    return normalized.count("server.zig") == 1 and any(
        clause.strip().startswith(required)
        for clause in re.split(r";|\n|(?<=\.)\s+", normalized)
    )


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


MetaValue: TypeAlias = str | list[str]


def frontmatter(path: Path) -> dict[str, MetaValue]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        fail(f"{path.relative_to(ROOT)} has no YAML frontmatter")
    parts = text.split("---\n", 2)
    if len(parts) != 3:
        fail(f"{path.relative_to(ROOT)} has unterminated YAML frontmatter")
    raw = parts[1]
    values: dict[str, MetaValue] = {}
    current_list: str | None = None
    for line in raw.splitlines():
        if line.startswith("  - ") and current_list is not None:
            value = values[current_list]
            assert isinstance(value, list)
            value.append(line[4:].strip().strip('"'))
            continue
        current_list = None
        if not line or line[0].isspace() or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"')
        if value:
            values[key] = value
        else:
            values[key] = []
            current_list = key
    return values


def scalar(meta: dict[str, MetaValue], key: str) -> str:
    value = meta.get(key, "")
    return value if isinstance(value, str) else ""


def csv(meta: dict[str, MetaValue], key: str) -> set[str]:
    value = meta.get(key, "")
    if isinstance(value, list):
        return set(value)
    return {item.strip() for item in value.split(",") if item.strip()}


def validate_skills() -> set[str]:
    names: set[str] = set()
    for skill_file in sorted(SKILLS.glob("*/SKILL.md")):
        meta = frontmatter(skill_file)
        name = scalar(meta, "name")
        if not NAME.fullmatch(name) or name != skill_file.parent.name:
            fail(f"invalid skill name in {skill_file.relative_to(ROOT)}")
        if not scalar(meta, "description"):
            fail(f"missing skill description in {skill_file.relative_to(ROOT)}")
        if name in names:
            fail(f"duplicate skill name {name}")
        normalized = skill_file.read_text(encoding="utf-8").replace("`", "").lower()
        if name == "orochi-server-integration" and (
            "permanent named-role reservation on src/daemon/server.zig" not in normalized
            or "orochi-server-integrator" not in normalized
        ):
            fail("server integration skill does not enforce permanent named-role ownership")
        if name == "orochi-session-mesh" and (
            "never edit src/daemon/server.zig" not in normalized
            or "orochi-server-integrator" not in normalized
        ):
            fail("session mesh skill does not enforce server.zig handoff")
        names.add(name)
        ui = skill_file.parent / "agents" / "openai.yaml"
        if not ui.is_file() or f"${name}" not in ui.read_text(encoding="utf-8"):
            fail(f"missing or stale UI metadata for {name}")
    if not names:
        fail("no project skills found")
    return names


def validate_codex() -> set[str]:
    names: set[str] = set()
    for path in sorted(CODEX.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        name = data.get("name", "")
        if name != path.stem or not NAME.fullmatch(name):
            fail(f"invalid Codex agent name in {path.relative_to(ROOT)}")
        if not data.get("description") or not data.get("developer_instructions"):
            fail(f"incomplete Codex agent {name}")
        if name in names:
            fail(f"duplicate Codex agent {name}")
        names.add(name)
        expected_sandbox = CODEX_SANDBOX.get(name)
        if expected_sandbox is not None and data.get("sandbox_mode") != expected_sandbox:
            fail(f"Codex agent {name} sandbox must be {expected_sandbox}")
        no_edit_contract = "without editing source" in data["description"].lower() or any(
            phrase in data["developer_instructions"].lower()
            for phrase in ("remain read-only",)
        )
        if no_edit_contract and data.get("sandbox_mode") != "read-only":
            fail(f"Codex agent {name} has a no-edit contract but a write-capable sandbox")
        expected_effort = CODEX_EFFORT.get(name)
        if expected_effort is not None and data.get("model_reasoning_effort") != expected_effort:
            fail(f"Codex agent {name} reasoning effort must be {expected_effort}")
        if "model" in data:
            fail(f"Codex agent {name} must inherit the active configured model")
        role = server_zig_role(data["developer_instructions"])
        if name in CODEX_SERVER_EXCLUDED_WRITERS and (
            role != "excluded" or not server_exclusion_consistent(data["developer_instructions"])
        ):
            fail(f"Codex agent {name} does not declare excluded server.zig authority")
        if name == "orochi-server-integrator" and (
            role != "owner" or not server_owner_consistent(data["developer_instructions"])
        ):
            fail("Codex server integrator does not declare owner authority")
        if name != "orochi-server-integrator" and role == "owner":
            fail(f"Codex agent {name} cannot declare owner server.zig authority")
        for skill in re.findall(r"\$(orochi-[a-z0-9-]+)", data["developer_instructions"]):
            if not (SKILLS / skill / "SKILL.md").is_file():
                fail(f"Codex agent {name} references missing skill {skill}")
    return names


def validate_claude(skill_names: set[str]) -> set[str]:
    names: set[str] = set()
    for path in sorted(CLAUDE.glob("*.md")):
        meta = frontmatter(path)
        name = scalar(meta, "name")
        if name != path.stem or not NAME.fullmatch(name):
            fail(f"invalid Claude agent name in {path.relative_to(ROOT)}")
        if not scalar(meta, "description"):
            fail(f"missing Claude agent description for {name}")
        tools = csv(meta, "tools")
        expected_tools = CLAUDE_TOOLS.get(name)
        if expected_tools is None or tools != expected_tools:
            fail(
                f"Claude agent {name} tools mismatch: "
                f"expected={sorted(expected_tools or set())} actual={sorted(tools)}"
            )
        raw_agent_text = path.read_text(encoding="utf-8")
        agent_text = raw_agent_text.replace("`", "").lower()
        agent_body = raw_agent_text.split("---\n", 2)[2]
        role = server_zig_role(agent_body)
        is_claude_writer = bool(tools & {"Write", "Edit", "Bash"})
        if name != "orochi-server-integrator" and is_claude_writer and (
            role != "excluded" or not server_exclusion_consistent(agent_body)
        ):
            fail(f"Claude agent {name} does not declare excluded server.zig authority")
        if name == "orochi-server-integrator" and (
            role != "owner" or not server_owner_consistent(agent_body)
        ):
            fail("Claude server integrator does not declare owner authority")
        if name != "orochi-server-integrator" and role == "owner":
            fail(f"Claude agent {name} cannot declare owner server.zig authority")
        expected_model, expected_effort = CLAUDE_MODEL_EFFORT.get(
            name, ("claude-sonnet-5", "high")
        )
        if scalar(meta, "model") != expected_model or scalar(meta, "effort") != expected_effort:
            fail(f"Claude agent {name} must use {expected_model} at {expected_effort} effort")
        for skill in csv(meta, "skills"):
            if skill not in skill_names:
                fail(f"Claude agent {name} references missing skill {skill}")
        if name in names:
            fail(f"duplicate Claude agent {name}")
        names.add(name)
    return names


def main() -> int:
    skills = validate_skills()
    codex = validate_codex()
    claude = validate_claude(skills)
    claude_skills = ROOT / ".claude" / "skills"
    if not claude_skills.exists() or claude_skills.resolve() != SKILLS.resolve():
        fail(".claude/skills must expose the canonical .agents/skills tree")
    if codex != REQUIRED_SHARED:
        fail(f"Codex roster mismatch: missing={sorted(REQUIRED_SHARED - codex)} extra={sorted(codex - REQUIRED_SHARED)}")
    expected_claude = set(CLAUDE_TOOLS)
    if claude != expected_claude:
        fail(
            f"Claude roster mismatch: missing={sorted(expected_claude - claude)} "
            f"extra={sorted(claude - expected_claude)}"
        )
    print(f"validated {len(skills)} skills, {len(codex)} Codex agents, {len(claude)} Claude agents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
