"""Run checks against a Context and turn probe output into results."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional

from macaudit.catalogue import Check
from macaudit.context import CommandOutput, Context
from macaudit.probes import BUILTINS, Outcome

EVIDENCE_LIMIT = 200


@dataclass(frozen=True)
class Result:
    check: Check
    status: str
    reason: str
    evidence: Optional[str] = None


def _evidence(text: str, home: str = "") -> Optional[str]:
    """One line of command output, without timestamps, home paths or user names."""

    if home and home != "/":
        text = text.replace(home, "~")
    text = re.sub(r"/Users/[^/\s,)]+", "/Users/<user>", text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    # defaults and sysadminctl prefix stderr with a timestamp and pid. Drop it.
    cleaned = [re.sub(r"^\d{4}-\d\d-\d\d [\d:.]+ \S+\[\d+:\w+\]\s*", "", line) for line in lines]
    joined = " | ".join(line for line in cleaned if line)
    if len(joined) > EVIDENCE_LIMIT:
        joined = joined[: EVIDENCE_LIMIT - 3] + "..."
    return joined or None


def _fmt(template: str, value: object) -> str:
    return template.replace("{value}", str(value))


def apply_rules(rules: Iterable[Mapping[str, Any]], output: CommandOutput) -> Outcome:
    """First matching rule wins. No match means the state is unknown."""

    text = output.text
    for rule in rules:
        kind = rule["when"]
        status = str(rule["status"])
        reason = str(rule.get("reason", ""))
        if kind == "regex":
            match = re.search(str(rule["pattern"]), text, re.MULTILINE)
            if match:
                # Evidence is the matching line only, so long listings never leak unrelated entries.
                start = text.rfind("\n", 0, match.start()) + 1
                end = text.find("\n", match.end())
                return Outcome(status, reason, text[start : end if end != -1 else len(text)])
        elif kind == "exit":
            hit = output.exit_code in list(rule["codes"])
            if bool(rule.get("negate", False)):
                hit = not hit
            if hit:
                return Outcome(status, reason)
        elif kind == "int_range":
            match = re.search(str(rule["pattern"]), output.stdout, re.MULTILINE)
            if match:
                value = int(match.group(1))
                low = rule.get("min")
                high = rule.get("max")
                inside = (low is None or value >= int(low)) and (high is None or value <= int(high))
                if inside:
                    return Outcome(status, _fmt(reason, value))
                other = str(rule.get("otherwise", "fail"))
                return Outcome(other, _fmt(str(rule.get("otherwise_reason", reason)), value))
        elif kind == "line_count":
            count = sum(1 for line in output.stdout.splitlines() if line.strip())
            high = int(rule.get("max", 0))
            if count <= high:
                return Outcome(status, _fmt(reason, count))
            other = str(rule.get("otherwise", "fail"))
            return Outcome(other, _fmt(str(rule.get("otherwise_reason", reason)), count))
    return Outcome("unknown", "Output did not match any known state.")


def run_check(check: Check, ctx: Context) -> Result:
    probe = check.probe
    if probe.requires_root and ctx.euid != 0:
        return Result(check, "skipped", "Requires root. Run with sudo to include this check.")
    if probe.type == "builtin":
        try:
            outcome = BUILTINS[probe.name](ctx, probe.params)
        except OSError as exc:
            outcome = Outcome("unknown", f"Probe could not read a file: {exc.strerror or exc}.")
        return Result(check, outcome.status, outcome.reason, outcome.evidence)

    argv: List[str] = list(probe.argv)
    if not ctx.runner.which(argv[0]):
        return Result(check, "skipped", f"{argv[0]} is not available on this machine.")
    output = ctx.run_cached(argv, env=probe.env, timeout=probe.timeout)
    if output.error == "not_found":
        return Result(check, "skipped", f"{argv[0]} is not available on this machine.")
    if output.error == "timeout":
        return Result(check, "unknown", f"{argv[0]} timed out after {probe.timeout} seconds.")
    if output.error:
        return Result(check, "unknown", "No recorded output for this command.")
    outcome = apply_rules(check.evaluate, output)
    evidence = None if check.sensitive else _evidence(outcome.evidence or output.text, ctx.home)
    return Result(check, outcome.status, outcome.reason, evidence)


def run_all(checks: Iterable[Check], ctx: Context) -> List[Result]:
    return [run_check(check, ctx) for check in checks]
