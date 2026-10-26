"""Renderers. Each one takes the canonical report (or the catalogue) and returns text."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Mapping, Optional

from macaudit import TOOL_NAME, __version__
from macaudit.catalogue import SEVERITIES, Catalogue, Check

INFORMATION_URI = "https://github.com/marlyngiselle/macos-security-audit"
SECURITY_SEVERITY = {"info": "0.0", "low": "3.0", "medium": "5.5", "high": "8.0", "critical": "9.5"}
SARIF_LEVEL = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
STATUS_ORDER = {"fail": 0, "unknown": 1, "skipped": 2, "pass": 3}
COLORS = {"pass": "32", "fail": "31", "unknown": "33", "skipped": "90"}


def _sev_key(row: Mapping[str, Any]) -> int:
    return -SEVERITIES.index(str(row["severity"]))


def _host_line(report: Mapping[str, Any]) -> str:
    host = report["host"]
    return f"macOS {host.get('os_version', 'unknown')} ({host.get('build', 'unknown')}), {host.get('arch', 'unknown')}"


def _threshold_text(fail_on: str) -> str:
    return "never" if fail_on == "none" else f"{fail_on} and above"


def to_json(report: Mapping[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def to_table(report: Mapping[str, Any], color: bool = False) -> str:
    def paint(status: str, text: str) -> str:
        return f"\033[{COLORS[status]}m{text}\033[0m" if color else text

    rows = report["results"]
    id_w = max([len("ID")] + [len(r["id"]) for r in rows])
    area_w = max([len("AREA")] + [len(r["area"]) for r in rows])
    out: List[str] = [
        f"{TOOL_NAME} {report['tool']['version']}  {_host_line(report)}  {report['generated_at']}",
        "",
        f"{'STATUS':<8} {'SEVERITY':<9} {'ID':<{id_w}} {'AREA':<{area_w}} CHECK",
    ]
    for r in rows:
        status = str(r["status"])
        out.append(
            f"{paint(status, f'{status.upper():<8}')} "
            f"{r['severity']:<9} {r['id']:<{id_w}} {r['area']:<{area_w}} {r['title']}"
        )
        if status in ("fail", "unknown"):
            out.append(f"{'':<8} {'':<9} {'':<{id_w}} {'':<{area_w}} -> {r['reason']}")
    s = report["summary"]
    score = "n/a" if s["score"] is None else f"{s['score']}%"
    policy = report["policy"]
    out += [
        "",
        f"{s['total']} checks: {s['pass']} pass, {s['fail']} fail, "
        f"{s['unknown']} unknown, {s['skipped']} skipped. Score {score}.",
        f"Policy: fail on {_threshold_text(policy['fail_on'])}. Exit code {policy['exit_code']}.",
        f"Run '{TOOL_NAME} explain <ID>' for remediation steps. Nothing was changed on this machine.",
    ]
    return "\n".join(out) + "\n"


def _md_cell(text: Optional[str]) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ")


def to_markdown(report: Mapping[str, Any], catalogue: Optional[Catalogue] = None) -> str:
    s = report["summary"]
    policy = report["policy"]
    score = "n/a" if s["score"] is None else f"{s['score']}%"
    lines: List[str] = [
        f"# {TOOL_NAME} report",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Host | {_host_line(report)} |",
        f"| Generated | {report['generated_at']} |",
        f"| Tool | {TOOL_NAME} {report['tool']['version']} |",
        f"| Score | {score} of scored checks pass |",
        f"| Policy | fail on {_threshold_text(policy['fail_on'])}, exit code {policy['exit_code']} |",
        "",
        "## Summary",
        "",
        "| Total | Pass | Fail | Unknown | Skipped |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {s['total']} | {s['pass']} | {s['fail']} | {s['unknown']} | {s['skipped']} |",
        "",
        "## By area",
        "",
        "| Area | Pass | Fail | Unknown | Skipped |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for area in report["areas"]:
        lines.append(f"| {area['title']} | {area['pass']} | {area['fail']} | {area['unknown']} | {area['skipped']} |")
    failed = sorted((r for r in report["results"] if r["status"] == "fail"), key=_sev_key)
    lines += ["", "## Findings", ""]
    if not failed:
        lines.append("No check failed.")
    else:
        lines += ["| Severity | ID | Check | Reason |", "| --- | --- | --- | --- |"]
        for r in failed:
            lines.append(f"| {r['severity']} | `{r['id']}` | {_md_cell(r['title'])} | {_md_cell(r['reason'])} |")
        if catalogue is not None:
            lines += ["", "### Remediation", ""]
            for r in failed:
                check = catalogue.get(str(r["id"]))
                if check is None:
                    continue
                lines.append(f"<details><summary><code>{check.id}</code> {check.title}</summary>")
                lines.append("")
                for number, step in enumerate(check.remediation, start=1):
                    lines.append(f"{number}. {step}")
                lines += ["", "</details>", ""]
    lines += [
        "",
        "## All results",
        "",
        "<details><summary>Every check, with the reason for its status</summary>",
        "",
        "| Status | Severity | ID | Check | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in sorted(report["results"], key=lambda x: (STATUS_ORDER[x["status"]], _sev_key(x), x["id"])):
        lines.append(
            f"| {r['status']} | {r['severity']} | `{r['id']}` | {_md_cell(r['title'])} | {_md_cell(r['reason'])} |"
        )
    lines += [
        "",
        "</details>",
        "",
        "Remediation is never applied automatically. Run `macaudit explain <ID>` for steps.",
        "",
    ]
    return "\n".join(lines)


def _rule(check: Check) -> Dict[str, Any]:
    steps = "\n".join(f"{n}. {step}" for n, step in enumerate(check.remediation, start=1))
    return {
        "id": check.id,
        "name": "".join(word.capitalize() for word in check.title.replace("(", "").replace(")", "").split()),
        "shortDescription": {"text": check.title},
        "fullDescription": {"text": check.rationale},
        "help": {
            "text": f"Expected: {check.expected}\n\nRemediation:\n{steps}",
            "markdown": f"Expected: {check.expected}\n\nRemediation:\n\n{steps}",
        },
        "helpUri": f"{INFORMATION_URI}/blob/main/docs/checks.md#{check.area}",
        "defaultConfiguration": {"level": SARIF_LEVEL[check.severity]},
        "properties": {
            "tags": ["security", "macos", check.area],
            "security-severity": SECURITY_SEVERITY[check.severity],
            "precision": "high",
        },
    }


def to_sarif(report: Mapping[str, Any], catalogue: Catalogue) -> str:
    rules = [_rule(check) for check in catalogue.checks]
    index = {check.id: n for n, check in enumerate(catalogue.checks)}
    uri = os.path.relpath(catalogue.path, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    results = []
    for r in report["results"]:
        if r["status"] != "fail" or r["severity"] == "info":
            continue
        check = catalogue.get(str(r["id"]))
        if check is None:
            continue
        message = f"{check.title}: {r['reason']}"
        if r.get("evidence"):
            message += f" Evidence: {r['evidence']}"
        results.append(
            {
                "ruleId": check.id,
                "ruleIndex": index[check.id],
                "level": SARIF_LEVEL[check.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri.replace(os.sep, "/")},
                            "region": {"startLine": check.line},
                        }
                    }
                ],
                "partialFingerprints": {"macauditCheck/v1": f"{check.id}:{r['severity']}"},
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "host": report["host"],
                    "summary": report["summary"],
                    "generatedAt": report["generated_at"],
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def catalogue_markdown(catalogue: Catalogue) -> str:
    lines = [
        "# Check catalogue",
        "",
        "Generated from [`macaudit/data/catalogue.json`](../macaudit/data/catalogue.json) with",
        "`python3 -m macaudit list --format markdown`. Do not edit by hand. A unit test fails when",
        "this file and the catalogue disagree.",
        "",
        "| Area | Checks | Critical | High | Medium | Low | Info | Needs root |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for area_id, area in catalogue.areas.items():
        checks = [c for c in catalogue.checks if c.area == area_id]
        counts = [sum(1 for c in checks if c.severity == sev) for sev in ("critical", "high", "medium", "low", "info")]
        root = sum(1 for c in checks if c.probe.requires_root)
        lines.append(f"| [{area.title}](#{area_id}) | {len(checks)} | " + " | ".join(map(str, counts)) + f" | {root} |")
    total = len(catalogue.checks)
    totals = [
        sum(1 for c in catalogue.checks if c.severity == sev) for sev in ("critical", "high", "medium", "low", "info")
    ]
    root_total = sum(1 for c in catalogue.checks if c.probe.requires_root)
    lines.append(f"| Total | {total} | " + " | ".join(map(str, totals)) + f" | {root_total} |")
    for area_id, area in catalogue.areas.items():
        checks = [c for c in catalogue.checks if c.area == area_id]
        lines += [
            "",
            f'<a id="{area_id}"></a>',
            "",
            f"## {area.title}",
            "",
            area.description,
            "",
            "| ID | Check | Severity | Probe | Expected |",
            "| --- | --- | --- | --- | --- |",
        ]
        for c in checks:
            probe = f"`{_md_cell(c.probe.display())}`" + (" (root)" if c.probe.requires_root else "")
            lines.append(f"| `{c.id}` | {_md_cell(c.title)} | {c.severity} | {probe} | {_md_cell(c.expected)} |")
    return "\n".join(lines) + "\n"


def catalogue_table(catalogue: Catalogue) -> str:
    id_w = max(len(c.id) for c in catalogue.checks)
    area_w = max(len(c.area) for c in catalogue.checks)
    out = [f"{'ID':<{id_w}} {'SEVERITY':<9} {'AREA':<{area_w}} {'ROOT':<5} CHECK"]
    for c in catalogue.checks:
        root = "yes" if c.probe.requires_root else "no"
        out.append(f"{c.id:<{id_w}} {c.severity:<9} {c.area:<{area_w}} {root:<5} {c.title}")
    out.append(f"\n{len(catalogue.checks)} checks in {len(catalogue.areas)} areas.")
    return "\n".join(out) + "\n"


def catalogue_json(catalogue: Catalogue) -> str:
    rows = [
        {
            "id": c.id,
            "title": c.title,
            "area": c.area,
            "severity": c.severity,
            "probe": c.probe.display(),
            "requires_root": c.probe.requires_root,
        }
        for c in catalogue.checks
    ]
    return json.dumps(rows, indent=2) + "\n"


def explain(check: Check, catalogue: Catalogue) -> str:
    area = catalogue.areas[check.area]
    out = [
        f"{check.id}  {check.title}",
        "",
        f"Area:       {area.title}",
        f"Severity:   {check.severity}",
        f"Probe:      {check.probe.display()}",
        f"Needs root: {'yes' if check.probe.requires_root else 'no'}",
        "",
        "Why it matters",
        f"  {check.rationale}",
        "",
        "Expected state",
        f"  {check.expected}",
        "",
        "Remediation (apply it yourself, macaudit never changes the system)",
    ]
    out += [f"  {n}. {step}" for n, step in enumerate(check.remediation, start=1)]
    if check.references:
        out += ["", "References"] + [f"  - {ref}" for ref in check.references]
    return "\n".join(out) + "\n"
