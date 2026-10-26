"""Every check, every path: pass, fail and unknown from recorded command output."""

from __future__ import annotations

import collections
import unittest

from macaudit.engine import run_check
from tests.helpers import catalogue, context_for, load_cases


class FixtureCoverageTest(unittest.TestCase):
    def test_every_check_has_pass_fail_and_unknown_fixtures(self) -> None:
        seen = collections.defaultdict(set)
        for case in load_cases():
            seen[case["check"]].add(case["expect"])
        for check in catalogue().checks:
            with self.subTest(check=check.id):
                missing = {"pass", "fail", "unknown"} - seen[check.id]
                self.assertFalse(missing, f"{check.id} lacks fixtures for {sorted(missing)}")

    def test_fixtures_only_reference_known_checks(self) -> None:
        ids = {c.id for c in catalogue().checks}
        for case in load_cases():
            self.assertIn(case["check"], ids, case["_file"])

    def test_fixture_files_match_check_areas(self) -> None:
        cat = catalogue()
        for case in load_cases():
            check = cat.get(case["check"])
            assert check is not None
            self.assertEqual(case["_file"], f"{check.area}.json", case["check"])


class FixtureCasesTest(unittest.TestCase):
    def test_recorded_cases(self) -> None:
        cat = catalogue()
        for case in load_cases():
            label = f"{case['check']} {case['expect']} {case.get('name', '')}".strip()
            with self.subTest(case=label):
                check = cat.get(case["check"])
                assert check is not None
                result = run_check(check, context_for(case))
                self.assertEqual(result.status, case["expect"], f"{label}: {result.reason}")
                self.assertTrue(result.reason, f"{label}: empty reason")


class SkipPathsTest(unittest.TestCase):
    def test_missing_tool_is_skipped_for_every_command_check(self) -> None:
        for check in catalogue().checks:
            if check.probe.type != "command":
                continue
            with self.subTest(check=check.id):
                ctx = context_for({"missing_tools": [check.probe.argv[0]], "euid": 0})
                result = run_check(check, ctx)
                self.assertEqual(result.status, "skipped")
                self.assertIn("not available", result.reason)

    def test_root_checks_are_skipped_without_root_and_never_run(self) -> None:
        root_checks = [c for c in catalogue().checks if c.probe.requires_root]
        self.assertTrue(root_checks, "the catalogue should contain at least one root-only check")
        for check in root_checks:
            with self.subTest(check=check.id):
                ctx = context_for({"euid": 501})
                result = run_check(check, ctx)
                self.assertEqual(result.status, "skipped")
                self.assertIn("Requires root", result.reason)
                self.assertEqual(ctx.cache, {}, "a skipped root check must not run its command")

    def test_unrecorded_command_is_unknown(self) -> None:
        check = catalogue().get("MA-ENC-01")
        assert check is not None
        result = run_check(check, context_for({}))
        self.assertEqual(result.status, "unknown")

    def test_timeout_is_unknown(self) -> None:
        check = catalogue().get("MA-ENC-01")
        assert check is not None
        result = run_check(check, context_for({"commands": {"fdesetup status": {"error": "timeout"}}}))
        self.assertEqual(result.status, "unknown")
        self.assertIn("timed out", result.reason)


class SensitiveOutputTest(unittest.TestCase):
    def test_sensitive_checks_never_carry_evidence(self) -> None:
        cat = catalogue()
        for case in load_cases():
            check = cat.get(case["check"])
            assert check is not None
            if not check.sensitive:
                continue
            with self.subTest(check=check.id, expect=case["expect"]):
                result = run_check(check, context_for(case))
                self.assertIsNone(result.evidence)

    def test_listing_evidence_is_limited_to_the_matching_line(self) -> None:
        check = catalogue().get("MA-SHR-01")
        assert check is not None
        listing = 'disabled services = {\n\t"com.vendor.agent" => enabled\n\t"com.openssh.sshd" => enabled\n}\n'
        ctx = context_for({"commands": {"launchctl print-disabled system": {"stdout": listing}}})
        result = run_check(check, ctx)
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.evidence, '"com.openssh.sshd" => enabled')

    def test_builtins_never_echo_network_names_or_key_material(self) -> None:
        cat = catalogue()
        for case in load_cases():
            if case["check"] not in ("MA-WL-03", "MA-SSH-03"):
                continue
            check = cat.get(case["check"])
            assert check is not None
            result = run_check(check, context_for(case))
            evidence = result.evidence or ""
            self.assertNotIn("Network-", evidence)
            self.assertNotIn("BEGIN", evidence)


if __name__ == "__main__":
    unittest.main()
