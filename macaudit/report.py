"""Build the canonical JSON report. Every renderer starts from this document."""

from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, List, Mapping, Optional, Sequence

from macaudit import TOOL_NAME, __version__
from macaudit.catalogue import SEVERITIES, STATUSES, Catalogue
from macaudit.context import Context
from macaudit.engine import Result

REPORT_SCHEMA_VERSION = "1.0"
FAIL_ON_CHOICES = ("none", "low", "medium", "high", "critical")
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INTERNAL = 3
EXIT_FINDINGS_BASE = 10  # 11 low, 12 medium, 13 high, 14 critical


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def exit_code_for(results: Sequence[Mapping[str, Any]], fail_on: str) -> int:
    """0 when nothing at or above the threshold failed, else 10 + worst severity rank."""

    if fail_on == "none":
        return EXIT_OK
    floor = severity_rank(fail_on)
    worst = -1
    for result in results:
        if result["status"] != "fail" or result["severity"] == "info":
            continue
        rank = severity_rank(str(result["severity"]))
        if rank >= floor:
            worst = max(worst, rank)
    return EXIT_OK if worst < 0 else EXIT_FINDINGS_BASE + worst


def host_info(ctx: Context) -> Dict[str, Any]:
    if ctx.host:
        info: Dict[str, Any] = {"os": "macOS"}
        info.update(ctx.host)
    else:

        def first_line(argv: List[str]) -> str:
            out = ctx.runner.run(argv)
            return out.stdout.strip().splitlines()[0] if out.exit_code == 0 and out.stdout.strip() else "unknown"

        info = {
            "os": "macOS",
            "os_version": first_line(["sw_vers", "-productVersion"]),
            "build": first_line(["sw_vers", "-buildVersion"]),
            "arch": first_line(["uname", "-m"]),
        }
    info["ran_as_root"] = ctx.euid == 0
    return info


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_report(
    results: Sequence[Result],
    catalogue: Catalogue,
    ctx: Context,
    fail_on: str,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for r in results:
        rows.append(
            {
                "id": r.check.id,
                "title": r.check.title,
                "area": r.check.area,
                "severity": r.check.severity,
                "status": r.status,
                "reason": r.reason,
                "evidence": r.evidence,
                "requires_root": r.check.probe.requires_root,
                "probe": r.check.probe.display(),
                "references": list(r.check.references),
            }
        )
    counts = {status: sum(1 for row in rows if row["status"] == status) for status in STATUSES}
    scored = [row for row in rows if row["severity"] != "info" and row["status"] in ("pass", "fail")]
    passed = sum(1 for row in scored if row["status"] == "pass")
    score = round(100 * passed / len(scored)) if scored else None
    failed_by_severity = {
        sev: sum(1 for row in rows if row["status"] == "fail" and row["severity"] == sev) for sev in SEVERITIES
    }
    areas = []
    for area_id, area in catalogue.areas.items():
        in_area = [row for row in rows if row["area"] == area_id]
        if not in_area:
            continue
        entry: Dict[str, Any] = {"id": area_id, "title": area.title}
        for status in STATUSES:
            entry[status] = sum(1 for row in in_area if row["status"] == status)
        areas.append(entry)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": generated_at or ctx.generated_at or _now(),
        "host": host_info(ctx),
        "policy": {"fail_on": fail_on, "exit_code": exit_code_for(rows, fail_on)},
        "summary": {
            "total": len(rows),
            **counts,
            "score": score,
            "failed_by_severity": failed_by_severity,
        },
        "areas": areas,
        "results": rows,
    }
