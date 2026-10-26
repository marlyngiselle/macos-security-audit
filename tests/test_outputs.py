"""Report, renderers, SARIF validity, exit codes and the CLI end to end."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from typing import Any, Dict, List

from macaudit import catalogue as cat
from macaudit import cli, render
from macaudit.context import replay_context
from macaudit.engine import run_all
from macaudit.report import build_report, exit_code_for
from tests.helpers import SAMPLE_HOST, SARIF_SCHEMA, catalogue, jsonschema, load_json


def sample_report(fail_on: str = "high") -> Dict[str, Any]:
    c = catalogue()
    ctx = replay_context(load_json(SAMPLE_HOST))
    return build_report(run_all(c.checks, ctx), c, ctx, fail_on)


def run_cli(argv: List[str]) -> tuple[int, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = cli.main(argv)
    return code, buffer.getvalue()


class ExitCodeTest(unittest.TestCase):
    def rows(self, *pairs: tuple[str, str]) -> List[Dict[str, str]]:
        return [{"severity": sev, "status": status} for sev, status in pairs]

    def test_threshold(self) -> None:
        rows = self.rows(("medium", "fail"), ("high", "pass"), ("low", "fail"))
        self.assertEqual(exit_code_for(rows, "high"), 0)
        self.assertEqual(exit_code_for(rows, "medium"), 12)
        self.assertEqual(exit_code_for(rows, "low"), 12)
        self.assertEqual(exit_code_for(rows, "none"), 0)

    def test_worst_severity_wins_and_info_never_fails(self) -> None:
        rows = self.rows(("critical", "fail"), ("high", "fail"), ("info", "fail"))
        self.assertEqual(exit_code_for(rows, "low"), 14)
        self.assertEqual(exit_code_for(self.rows(("info", "fail")), "low"), 0)

    def test_unknown_and_skipped_never_fail(self) -> None:
        rows = self.rows(("critical", "unknown"), ("critical", "skipped"))
        self.assertEqual(exit_code_for(rows, "low"), 0)


class ReportTest(unittest.TestCase):
    def test_sample_report_summary(self) -> None:
        report = sample_report()
        s = report["summary"]
        self.assertEqual(s["total"], len(catalogue().checks))
        self.assertEqual(s["pass"] + s["fail"] + s["unknown"] + s["skipped"], s["total"])
        self.assertEqual(report["policy"]["exit_code"], 13)
        self.assertEqual(report["generated_at"], "2026-10-26T09:00:00Z")

    def test_report_has_no_personal_fields(self) -> None:
        text = json.dumps(sample_report())
        for needle in ("hostname", "serial", "person@example.com", "/Users/sample"):
            self.assertNotIn(needle, text)

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_report_matches_schema(self) -> None:
        assert jsonschema is not None
        schema = load_json(os.path.join(cat.DATA_DIR, "report.schema.json"))
        jsonschema.Draft202012Validator.check_schema(schema)
        for fail_on in ("none", "low", "high"):
            jsonschema.validate(sample_report(fail_on), schema, cls=jsonschema.Draft202012Validator)


class RenderTest(unittest.TestCase):
    def test_table(self) -> None:
        text = render.to_table(sample_report())
        self.assertIn("MA-SHR-01", text)
        self.assertIn("Exit code 13", text)
        self.assertNotIn("\033[", text)
        self.assertIn("\033[31m", render.to_table(sample_report(), color=True))

    def test_markdown(self) -> None:
        text = render.to_markdown(sample_report(), catalogue())
        self.assertIn("# macaudit report", text)
        self.assertIn("## Findings", text)
        self.assertIn("<code>MA-SHR-01</code>", text)
        self.assertNotIn("**", text)

    def test_markdown_without_findings(self) -> None:
        report = sample_report()
        for row in report["results"]:
            row["status"] = "pass"
        self.assertIn("No check failed.", render.to_markdown(report, catalogue()))


class SarifTest(unittest.TestCase):
    def sarif(self) -> Dict[str, Any]:
        result: Dict[str, Any] = json.loads(render.to_sarif(sample_report(), catalogue()))
        return result

    def test_structure(self) -> None:
        sarif = self.sarif()
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), len(catalogue().checks))
        for rule in rules:
            self.assertIn("security-severity", rule["properties"])
            float(rule["properties"]["security-severity"])
        report = sample_report()
        failed = {r["id"] for r in report["results"] if r["status"] == "fail" and r["severity"] != "info"}
        self.assertEqual({r["ruleId"] for r in run["results"]}, failed)
        for res in run["results"]:
            self.assertEqual(rules[res["ruleIndex"]]["id"], res["ruleId"])
            loc = res["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uri"], "macaudit/data/catalogue.json")
            self.assertGreater(loc["region"]["startLine"], 1)

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_matches_official_schema(self) -> None:
        assert jsonschema is not None
        schema = load_json(SARIF_SCHEMA)
        jsonschema.validate(self.sarif(), schema, cls=jsonschema.Draft4Validator)


class CliTest(unittest.TestCase):
    def test_run_writes_every_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = {k: os.path.join(tmp, f"out.{k}") for k in ("json", "md", "sarif")}
            code, out = run_cli(
                [
                    "run",
                    "--replay",
                    SAMPLE_HOST,
                    "--no-color",
                    "--json-out",
                    paths["json"],
                    "--markdown-out",
                    paths["md"],
                    "--sarif-out",
                    paths["sarif"],
                ]
            )
            self.assertEqual(code, 13)
            self.assertIn("STATUS", out)
            report = load_json(paths["json"])
            self.assertEqual(report["summary"]["total"], len(catalogue().checks))
            self.assertEqual(load_json(paths["sarif"])["version"], "2.1.0")
            code, md = run_cli(["render", "--input", paths["json"], "--format", "markdown"])
            self.assertEqual(code, 0)
            with open(paths["md"], encoding="utf-8") as handle:
                self.assertEqual(md, handle.read())

    def test_fail_on_none_and_filters(self) -> None:
        code, _ = run_cli(["run", "--replay", SAMPLE_HOST, "--fail-on", "none"])
        self.assertEqual(code, 0)
        code, out = run_cli(["run", "--replay", SAMPLE_HOST, "--area", "ssh", "--format", "json"])
        self.assertEqual({r["area"] for r in json.loads(out)["results"]}, {"ssh"})
        code, out = run_cli(["run", "--replay", SAMPLE_HOST, "--check", "ma-enc-01", "--format", "json"])
        self.assertEqual([r["id"] for r in json.loads(out)["results"]], ["MA-ENC-01"])

    def test_usage_errors(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run_cli(["run", "--replay", SAMPLE_HOST, "--area", "nope"])[0], 2)
            self.assertEqual(run_cli(["run", "--replay", SAMPLE_HOST, "--check", "MA-XX-99"])[0], 2)
            self.assertEqual(run_cli(["explain", "MA-XX-99"])[0], 2)

    def test_explain_and_list(self) -> None:
        code, out = run_cli(["explain", "MA-ENC-01"])
        self.assertEqual(code, 0)
        self.assertIn("Remediation", out)
        self.assertIn("never changes the system", out)
        code, out = run_cli(["list"])
        self.assertIn(f"{len(catalogue().checks)} checks", out)


if __name__ == "__main__":
    unittest.main()
