#!/usr/bin/env python3
"""Negative tests for safety-critical Claude launcher arguments."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


STUB = Path(__file__).with_name("claude_review_stub.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("claude_review_stub", STUB)
assert SPEC is not None and SPEC.loader is not None
stub = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stub)


class StubArgumentTests(unittest.TestCase):
    def launcher_args(self) -> list[str]:
        schema = {
            "additionalProperties": False,
            "required": sorted(stub.REQUIRED_SCHEMA_KEYS),
        }
        return [
            "-p",
            "ignored",
            "--permission-mode",
            "dontAsk",
            "--agent",
            "onyx-fast-auditor",
            "--model",
            "claude-haiku-4-5-20251001",
            "--effort",
            "low",
            "--max-budget-usd",
            "0.75",
            "--setting-sources",
            "project,local",
            "--output-format",
            "json",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--json-schema",
            json.dumps(schema),
            *sorted(stub.REQUIRED_SWITCHES),
            "--tools",
            "Read",
            "StructuredOutput",
        ]

    def test_complete_safety_arguments_are_accepted(self) -> None:
        stub.validate_launcher_args(self.launcher_args())

    def test_each_missing_isolation_switch_is_rejected(self) -> None:
        for missing in sorted(stub.REQUIRED_SWITCHES):
            with self.subTest(missing=missing):
                argv = [arg for arg in self.launcher_args() if arg != missing]
                with self.assertRaisesRegex(SystemExit, "safety-critical switch"):
                    stub.validate_launcher_args(argv)


if __name__ == "__main__":
    unittest.main()
