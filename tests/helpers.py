"""Shared helpers for the test suite. Standard library only."""

from __future__ import annotations

import glob
import json
import os
from typing import Any, Dict, List, Optional

from macaudit import catalogue as cat
from macaudit.context import Context, replay_context

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_DIR = os.path.join(ROOT, "tests", "fixtures", "cases")
SAMPLE_HOST = os.path.join(ROOT, "examples", "replay", "sample-host.json")
SARIF_SCHEMA = os.path.join(ROOT, "tests", "schemas", "sarif-schema-2.1.0.json")

try:  # jsonschema is a dev dependency. Schema tests skip cleanly without it.
    import jsonschema as _jsonschema

    jsonschema: Optional[Any] = _jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

BASE_CONTEXT: Dict[str, Any] = {
    "generated_at": "2026-01-01T00:00:00Z",
    "host": {"os_version": "15.5", "build": "24F74", "arch": "arm64"},
    "euid": 501,
    "home": "/Users/sample",
    "env": {"PATH": "/usr/bin:/bin"},
}


def load_cases() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    for path in sorted(glob.glob(os.path.join(CASES_DIR, "*.json"))):
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        for case in data["cases"]:
            case = dict(case)
            case["_file"] = os.path.basename(path)
            cases.append(case)
    return cases


def context_for(case: Dict[str, Any]) -> Context:
    data = dict(BASE_CONTEXT)
    for key in ("commands", "files", "missing_tools", "euid"):
        if key in case:
            data[key] = case[key]
    if "env" in case:
        data["env"] = case["env"]
    return replay_context(data)


def load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def catalogue() -> cat.Catalogue:
    return cat.load()
