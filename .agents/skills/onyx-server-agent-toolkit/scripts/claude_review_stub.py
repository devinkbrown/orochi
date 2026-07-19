#!/usr/bin/env python3
"""Deterministic Claude CLI stub for the snapshot-isolation regression test."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

REQUIRED_SWITCHES = {
    "--strict-mcp-config",
    "--disable-slash-commands",
    "--no-chrome",
    "--no-session-persistence",
}
EXPECTED_OPTIONS = {
    "--agent": "onyx-fast-auditor",
    "--model": "claude-haiku-4-5-20251001",
    "--effort": "low",
    "--max-budget-usd": "0.75",
    "--setting-sources": "project,local",
    "--output-format": "json",
}
REQUIRED_SCHEMA_KEYS = {
    "review_nonce",
    "verdict",
    "summary",
    "reviewed_files",
    "findings",
}


def option_value(args: list[str], option: str) -> str:
    prefix = option + "="
    for index, argument in enumerate(args):
        if argument == option:
            return args[index + 1]
        if argument.startswith(prefix):
            return argument[len(prefix) :]
    raise ValueError(f"missing option {option}")


def validate_launcher_args(args: list[str]) -> None:
    if option_value(args, "--permission-mode") != "dontAsk":
        raise SystemExit("launcher did not select dontAsk")
    tool_start = args.index("--tools") + 1
    if set(args[tool_start:]) != {"Read", "StructuredOutput"}:
        raise SystemExit("launcher exposed tools other than Read and StructuredOutput")
    if not REQUIRED_SWITCHES.issubset(args):
        raise SystemExit("launcher omitted a safety-critical switch")
    for option, expected_value in EXPECTED_OPTIONS.items():
        if option_value(args, option) != expected_value:
            raise SystemExit(f"unexpected {option} value")
    if json.loads(option_value(args, "--mcp-config")) != {"mcpServers": {}}:
        raise SystemExit("launcher did not disable MCP servers")
    schema = json.loads(option_value(args, "--json-schema"))
    if schema.get("additionalProperties") is not False or set(
        schema.get("required", [])
    ) != REQUIRED_SCHEMA_KEYS:
        raise SystemExit("launcher JSON schema is missing mandatory structure")


def main() -> int:
    args = sys.argv[1:]
    validate_launcher_args(args)
    prompt = option_value(args, "-p")

    nonce_match = re.search(r"Review nonce: ([0-9a-f]{64})", prompt)
    if nonce_match is None:
        raise SystemExit("review nonce missing")
    marker = "Exact review scope (path, snapshot line count, snapshot SHA-256):\n"
    manifest = prompt.split(marker, 1)[1].split("\n\n", 1)[0]
    manifest_lines = manifest.splitlines()
    files = [line.split("\t", 1)[0] for line in manifest_lines]
    for line, file in zip(manifest_lines, files, strict=True):
        fields = dict(field.split("=", 1) for field in line.split("\t")[1:])
        if fields.get("read_path") != str(Path.cwd() / file):
            raise SystemExit("manifest read_path does not name the snapshot file")

    settings = json.loads(option_value(args, "--settings"))
    if settings.get("permissions", {}).get("defaultMode") != "dontAsk":
        raise SystemExit("settings did not lock the default permission mode")
    allowed = set(settings.get("permissions", {}).get("allow", []))
    expected = {
        "StructuredOutput",
        *(f"Read(/{file})" for file in files),
        *(f"Read(/{Path.cwd()}/{file})" for file in files),
    }
    if allowed != expected:
        raise SystemExit(f"unexpected Read rules: {sorted(allowed)}")

    ready = Path(os.environ["CLAUDE_STUB_READY"])
    hold = Path(os.environ["CLAUDE_STUB_HOLD"])
    observed = Path(os.environ["CLAUDE_STUB_OBSERVED"])
    ready.write_text("ready\n", encoding="utf-8")
    deadline = time.monotonic() + 10
    while hold.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if hold.exists():
        raise SystemExit("test did not release stub")

    reviewed_files: list[dict[str, object]] = []
    observed_lines = [f"cwd={Path.cwd()}"]
    for agent_file in sorted(Path(".claude/agents").glob("*.md")):
        observed_lines.append(
            f"agent={agent_file.read_text(encoding='utf-8').replace(chr(10), '|')}"
        )
    for file in files:
        lines = Path(file).read_text(encoding="utf-8").splitlines()
        for line_number, source_line in enumerate(lines, 1):
            if source_line.strip():
                anchor = source_line.strip()[:160]
                reviewed_files.append(
                    {"file": file, "line": line_number, "anchor": anchor}
                )
                observed_lines.append(f"{file}={source_line}")
                break
        else:
            raise SystemExit(f"scoped file has no anchor: {file}")
    observed.write_text("\n".join(observed_lines) + "\n", encoding="utf-8")

    structured = {
        "review_nonce": nonce_match.group(1),
        "verdict": "pass",
        "summary": "Snapshot-isolated stub review completed successfully.",
        "reviewed_files": reviewed_files,
        "findings": [],
    }
    if os.environ.get("CLAUDE_STUB_RESULT_MODE") == "fenced":
        print(
            json.dumps(
                {
                    "is_error": False,
                    "structured_output": None,
                    "result": f"```json\n{json.dumps(structured)}\n```",
                }
            )
        )
    else:
        print(json.dumps({"is_error": False, "structured_output": structured}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
