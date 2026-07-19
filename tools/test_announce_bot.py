#!/usr/bin/env python3
"""Focused tests for the announce bot's non-blocking stats inventory."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "announce_bot", pathlib.Path(__file__).with_name("announce_bot.py")
)
assert SPEC and SPEC.loader
bot = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bot
SPEC.loader.exec_module(bot)


PROJECT = bot.Project(
    key="fixture",
    name="Fixture",
    emoji="x",
    accent="",
    repo="/fixture",
    module_label="modules",
    module_cmd="modules",
    loc_cmd="loc",
    test_cmd="tests",
    test_label="test blocks",
    stats_suffix="fixture",
    topic_label="Fixture",
    user_realname="fixture",
    project_lines=(),
    roadmap=(),
    progress_text="",
)


class InventoryTests(unittest.TestCase):
    def test_inventory_commands_exclude_nested_worktrees_and_need_no_ripgrep(self) -> None:
        for command in (
            bot._quoted_find_tsx("/fixture"),
            bot._quoted_loc_ts("/fixture"),
            bot._quoted_test_files_ts("/fixture"),
        ):
            self.assertIn("-name .claude", command)
            self.assertIn("-prune", command)
        zig = bot._quoted_test_blocks_zig("/fixture")
        self.assertIn("grep -hE", zig)
        self.assertNotIn("rg ", zig)

    def test_collect_inventory_labels_static_counts_without_claiming_a_run(self) -> None:
        def fake_shell(command: str, timeout: float = 0) -> str:
            self.assertEqual(8.0, timeout)
            return {"modules": "8", "tests": "42", "loc": "12345"}[command]

        def fake_git(_project: bot.Project, *args: str) -> str:
            if args == ("rev-list", "--count", "HEAD"):
                return "99"
            if args == ("rev-parse", "HEAD"):
                return "deadbeef"
            if args == ("status", "--porcelain=v1"):
                return ""
            self.fail(f"unexpected git args: {args}")

        with mock.patch.object(bot, "_shell_count", side_effect=fake_shell), mock.patch.object(
            bot, "git", side_effect=fake_git
        ):
            item = bot.collect_inventory(PROJECT)

        self.assertEqual("8", item.modules)
        self.assertEqual("42", item.test_blocks)
        self.assertEqual("12.3k", item.loc)
        self.assertEqual("99", item.commits)
        self.assertEqual("deadbeef", item.head)

    def test_stats_rendering_never_claims_test_blocks_are_passing(self) -> None:
        item = bot.BuildInventory(
            modules="8",
            test_blocks="42",
            loc="12.3k",
            commits="99",
            head="deadbeef",
            measured_at=1.0,
        )
        with bot.INVENTORY._lock:
            old = bot.INVENTORY._items.get(PROJECT.key)
            bot.INVENTORY._items[PROJECT.key] = item
        try:
            with mock.patch.object(bot, "git", return_value="deadbeef"), mock.patch.object(
                bot, "head_line", return_value="deadbeef fixture"
            ), mock.patch.object(bot, "commit_stat", return_value="1 file"):
                rendered = " ".join(bot.stats_lines(PROJECT)).lower()
            self.assertIn("test-blocks=", rendered)
            self.assertNotIn("passing", rendered)
        finally:
            with bot.INVENTORY._lock:
                if old is None:
                    bot.INVENTORY._items.pop(PROJECT.key, None)
                else:
                    bot.INVENTORY._items[PROJECT.key] = old


if __name__ == "__main__":
    unittest.main()
