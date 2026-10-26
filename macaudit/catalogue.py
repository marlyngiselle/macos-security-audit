"""Load and validate the declarative check catalogue."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CATALOGUE_PATH = os.path.join(DATA_DIR, "catalogue.json")

SEVERITIES: Tuple[str, ...] = ("info", "low", "medium", "high", "critical")
STATUSES: Tuple[str, ...] = ("pass", "fail", "unknown", "skipped")
RULE_KINDS: Tuple[str, ...] = ("regex", "exit", "int_range", "line_count")
ID_PATTERN = re.compile(r"^MA-[A-Z]{2,3}-\d{2}$")


class CatalogueError(ValueError):
    """The catalogue is malformed. Raised at load time, never during an audit."""


@dataclass(frozen=True)
class Area:
    id: str
    title: str
    description: str


@dataclass(frozen=True)
class Probe:
    type: str
    argv: Tuple[str, ...] = ()
    name: str = ""
    params: Mapping[str, Any] = field(default_factory=dict)
    env: Mapping[str, str] = field(default_factory=dict)
    timeout: int = 20
    requires_root: bool = False

    def display(self) -> str:
        if self.type == "command":
            return " ".join(self.argv)
        return f"builtin:{self.name}"


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    area: str
    severity: str
    rationale: str
    expected: str
    probe: Probe
    evaluate: Tuple[Mapping[str, Any], ...]
    remediation: Tuple[str, ...]
    references: Tuple[str, ...]
    sensitive: bool = False
    line: int = 1


@dataclass(frozen=True)
class Catalogue:
    areas: Mapping[str, Area]
    checks: Tuple[Check, ...]
    path: str

    def get(self, check_id: str) -> Optional[Check]:
        wanted = check_id.upper()
        for check in self.checks:
            if check.id == wanted:
                return check
        return None


def _require(obj: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in obj:
        raise CatalogueError(f"{where}: missing '{key}'")
    return obj[key]


def _validate_rule(rule: Mapping[str, Any], where: str) -> None:
    kind = _require(rule, "when", where)
    if kind not in RULE_KINDS:
        raise CatalogueError(f"{where}: unknown rule kind '{kind}'")
    if _require(rule, "status", where) not in STATUSES:
        raise CatalogueError(f"{where}: invalid status '{rule['status']}'")
    if "otherwise" in rule and rule["otherwise"] not in STATUSES:
        raise CatalogueError(f"{where}: invalid otherwise '{rule['otherwise']}'")
    if kind in ("regex", "int_range"):
        try:
            re.compile(str(_require(rule, "pattern", where)))
        except re.error as exc:
            raise CatalogueError(f"{where}: bad pattern: {exc}") from exc
    if kind == "exit" and not isinstance(_require(rule, "codes", where), list):
        raise CatalogueError(f"{where}: 'codes' must be a list")


def _line_numbers(text: str) -> Dict[str, int]:
    lines: Dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        match = re.search(r'"id":\s*"(MA-[A-Z]{2,3}-\d{2})"', line)
        if match:
            lines.setdefault(match.group(1), number)
    return lines


def parse(data: Mapping[str, Any], source_text: str = "", path: str = CATALOGUE_PATH) -> Catalogue:
    from macaudit.probes import BUILTINS  # local import keeps the module graph acyclic

    areas = {
        key: Area(id=key, title=str(v["title"]), description=str(v["description"]))
        for key, v in dict(_require(data, "areas", "catalogue")).items()
    }
    lines = _line_numbers(source_text)
    checks: List[Check] = []
    seen = set()
    for raw in _require(data, "checks", "catalogue"):
        cid = str(_require(raw, "id", "check"))
        where = f"check {cid}"
        if not ID_PATTERN.match(cid):
            raise CatalogueError(f"{where}: id must look like MA-ABC-01")
        if cid in seen:
            raise CatalogueError(f"{where}: duplicate id")
        seen.add(cid)
        area = _require(raw, "area", where)
        if area not in areas:
            raise CatalogueError(f"{where}: unknown area '{area}'")
        severity = _require(raw, "severity", where)
        if severity not in SEVERITIES:
            raise CatalogueError(f"{where}: invalid severity '{severity}'")
        praw = _require(raw, "probe", where)
        ptype = _require(praw, "type", where)
        probe = Probe(
            type=ptype,
            argv=tuple(str(a) for a in praw.get("argv", [])),
            name=str(praw.get("name", "")),
            params=dict(praw.get("params", {})),
            env={str(k): str(v) for k, v in dict(praw.get("env", {})).items()},
            timeout=int(praw.get("timeout", 20)),
            requires_root=bool(praw.get("requires_root", False)),
        )
        rules = tuple(raw.get("evaluate", []))
        if ptype == "command":
            if not probe.argv:
                raise CatalogueError(f"{where}: command probe needs argv")
            if not rules:
                raise CatalogueError(f"{where}: command probe needs evaluate rules")
            for index, rule in enumerate(rules):
                _validate_rule(rule, f"{where} rule {index}")
        elif ptype == "builtin":
            if probe.name not in BUILTINS:
                raise CatalogueError(f"{where}: unknown builtin '{probe.name}'")
        else:
            raise CatalogueError(f"{where}: unknown probe type '{ptype}'")
        remediation = tuple(str(s) for s in _require(raw, "remediation", where))
        if not remediation:
            raise CatalogueError(f"{where}: remediation must not be empty")
        checks.append(
            Check(
                id=cid,
                title=str(_require(raw, "title", where)),
                area=str(area),
                severity=str(severity),
                rationale=str(_require(raw, "rationale", where)),
                expected=str(_require(raw, "expected", where)),
                probe=probe,
                evaluate=rules,
                remediation=remediation,
                references=tuple(str(s) for s in raw.get("references", [])),
                sensitive=bool(raw.get("sensitive", False)),
                line=lines.get(cid, 1),
            )
        )
    return Catalogue(areas=areas, checks=tuple(checks), path=path)


def load(path: str = CATALOGUE_PATH) -> Catalogue:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CatalogueError(f"{path}: invalid JSON: {exc}") from exc
    return parse(data, text, path)
