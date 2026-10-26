"""Rule evaluation, evidence handling and the fake file system."""

from __future__ import annotations

import unittest

from macaudit.context import CommandOutput, FakeFileSystem, replay_context
from macaudit.engine import _evidence, apply_rules


class ApplyRulesTest(unittest.TestCase):
    def test_first_matching_rule_wins(self) -> None:
        rules = [
            {"when": "regex", "pattern": "On", "status": "pass"},
            {"when": "regex", "pattern": "FileVault", "status": "fail"},
        ]
        self.assertEqual(apply_rules(rules, CommandOutput(0, "FileVault is On.")).status, "pass")

    def test_no_match_is_unknown(self) -> None:
        rules = [{"when": "regex", "pattern": "nothing", "status": "pass"}]
        self.assertEqual(apply_rules(rules, CommandOutput(0, "something else")).status, "unknown")

    def test_regex_sees_stderr(self) -> None:
        rules = [{"when": "regex", "pattern": "does not exist", "status": "skipped"}]
        out = CommandOutput(1, "", "The domain/default pair of (x, y) does not exist")
        self.assertEqual(apply_rules(rules, out).status, "skipped")

    def test_exit_rule_and_negation(self) -> None:
        rules = [{"when": "exit", "codes": [0], "negate": True, "status": "unknown"}]
        self.assertEqual(apply_rules(rules, CommandOutput(1, "")).status, "unknown")
        rules = [{"when": "exit", "codes": [0], "status": "fail"}]
        self.assertEqual(apply_rules(rules, CommandOutput(0, "x")).status, "fail")

    def test_int_range_formats_value(self) -> None:
        rule = {
            "when": "int_range",
            "pattern": r"^(\d+)$",
            "min": 1,
            "max": 1200,
            "status": "pass",
            "otherwise": "fail",
            "reason": "ok {value}",
            "otherwise_reason": "bad {value}",
        }
        self.assertEqual(apply_rules([rule], CommandOutput(0, "600")).reason, "ok 600")
        outcome = apply_rules([rule], CommandOutput(0, "0"))
        self.assertEqual((outcome.status, outcome.reason), ("fail", "bad 0"))

    def test_line_count(self) -> None:
        rule = {"when": "line_count", "max": 2, "status": "pass", "otherwise": "fail", "reason": "{value}"}
        self.assertEqual(apply_rules([rule], CommandOutput(0, "a\nb\n")).status, "pass")
        self.assertEqual(apply_rules([rule], CommandOutput(0, "a\nb\nc\n")).status, "fail")


class EvidenceTest(unittest.TestCase):
    def test_strips_timestamps_and_truncates(self) -> None:
        text = "2026-10-26 09:00:00.000 sysadminctl[4242:1337] screenLock delay is immediate"
        self.assertEqual(_evidence(text), "screenLock delay is immediate")
        long = _evidence("x" * 500)
        assert long is not None
        self.assertEqual(len(long), 200)

    def test_home_and_user_names_are_redacted(self) -> None:
        text = "The domain/default pair of (/Users/alice/Library/x, Key) does not exist"
        self.assertEqual(
            _evidence(text, "/Users/alice"), "The domain/default pair of (~/Library/x, Key) does not exist"
        )
        self.assertEqual(_evidence("(/Users/bob/Library/x, Key)"), "(/Users/<user>/Library/x, Key)")

    def test_empty_output_has_no_evidence(self) -> None:
        self.assertIsNone(_evidence("\n\n"))


class FakeFileSystemTest(unittest.TestCase):
    def test_parents_symlinks_and_modes(self) -> None:
        fs = FakeFileSystem(
            {
                "/a/b/file": {"mode": "0600", "content": "hi"},
                "/a/link": {"type": "symlink", "target": "/a/b/file"},
            }
        )
        self.assertTrue(fs.is_dir("/a/b"))
        self.assertEqual(fs.listdir("/a"), ["b", "link"])
        self.assertTrue(fs.is_symlink("/a/link"))
        self.assertTrue(fs.is_file("/a/link"))
        self.assertEqual(fs.mode("/a/link"), 0o600)
        self.assertEqual(fs.read_bytes("/a/b/file"), b"hi")
        with self.assertRaises(FileNotFoundError):
            fs.mode("/missing")


class ContextTest(unittest.TestCase):
    def test_tilde_expansion_and_cache(self) -> None:
        ctx = replay_context(
            {
                "home": "/Users/x",
                "env": {"PATH": "~/bin:/usr/bin"},
                "commands": {"echo hi": {"stdout": "hi"}},
            }
        )
        self.assertEqual(ctx.env["PATH"], "/Users/x/bin:/usr/bin")
        first = ctx.run_cached(["echo", "hi"])
        second = ctx.run_cached(["echo", "hi"])
        self.assertIs(first, second)
        self.assertEqual(len(ctx.cache), 1)


if __name__ == "__main__":
    unittest.main()
