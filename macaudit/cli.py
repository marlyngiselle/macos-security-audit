"""Command line interface.

macaudit run      audit this Mac (or a recorded replay) and report
macaudit list     print the check catalogue
macaudit explain  print why a check matters and how to fix it
macaudit render   re-render a saved JSON report in another format
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from typing import Any, Dict, List, Optional

from macaudit import TOOL_NAME, __version__, render
from macaudit import catalogue as cat
from macaudit.context import Context, replay_context, system_context
from macaudit.engine import run_all
from macaudit.report import EXIT_INTERNAL, EXIT_USAGE, FAIL_ON_CHOICES, build_report

FORMATS = ("table", "json", "markdown", "sarif")


def _write(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _render(fmt: str, report: Dict[str, Any], catalogue: cat.Catalogue, color: bool = False) -> str:
    if fmt == "json":
        return render.to_json(report)
    if fmt == "markdown":
        return render.to_markdown(report, catalogue)
    if fmt == "sarif":
        return render.to_sarif(report, catalogue)
    return render.to_table(report, color=color)


def _use_color(args: argparse.Namespace) -> bool:
    return args.format == "table" and not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()


def cmd_run(args: argparse.Namespace, catalogue: cat.Catalogue) -> int:
    checks = list(catalogue.checks)
    if args.area:
        unknown = sorted(set(args.area) - set(catalogue.areas))
        if unknown:
            print(f"{TOOL_NAME}: unknown area: {', '.join(unknown)}", file=sys.stderr)
            return EXIT_USAGE
        checks = [c for c in checks if c.area in args.area]
    if args.check:
        wanted = {c.upper() for c in args.check}
        missing = sorted(wanted - {c.id for c in catalogue.checks})
        if missing:
            print(f"{TOOL_NAME}: unknown check: {', '.join(missing)}", file=sys.stderr)
            return EXIT_USAGE
        checks = [c for c in checks if c.id in wanted]

    ctx: Context
    if args.replay:
        with open(args.replay, encoding="utf-8") as handle:
            ctx = replay_context(json.load(handle))
    else:
        if platform.system() != "Darwin":
            print(f"{TOOL_NAME}: live audits run on macOS only. Use --replay to render a recording.", file=sys.stderr)
            return EXIT_USAGE
        ctx = system_context()

    report = build_report(run_all(checks, ctx), catalogue, ctx, args.fail_on)
    for fmt, path in (("json", args.json_out), ("markdown", args.markdown_out), ("sarif", args.sarif_out)):
        if path:
            _write(path, _render(fmt, report, catalogue))
    output = _render(args.format, report, catalogue, color=_use_color(args))
    if args.output:
        _write(args.output, output)
    else:
        sys.stdout.write(output)
    return int(report["policy"]["exit_code"])


def cmd_list(args: argparse.Namespace, catalogue: cat.Catalogue) -> int:
    if args.format == "markdown":
        sys.stdout.write(render.catalogue_markdown(catalogue))
    elif args.format == "json":
        sys.stdout.write(render.catalogue_json(catalogue))
    else:
        sys.stdout.write(render.catalogue_table(catalogue))
    return 0


def cmd_explain(args: argparse.Namespace, catalogue: cat.Catalogue) -> int:
    check = catalogue.get(args.id)
    if check is None:
        print(f"{TOOL_NAME}: unknown check '{args.id}'. Run '{TOOL_NAME} list' to see them all.", file=sys.stderr)
        return EXIT_USAGE
    sys.stdout.write(render.explain(check, catalogue))
    return 0


def cmd_render(args: argparse.Namespace, catalogue: cat.Catalogue) -> int:
    with open(args.input, encoding="utf-8") as handle:
        report = json.load(handle)
    sys.stdout.write(_render(args.format, report, catalogue))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Read-only macOS security posture audit. Nothing is ever changed on the machine.",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    parser.add_argument("--catalogue", default=cat.CATALOGUE_PATH, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    run = sub.add_parser("run", help="audit this Mac and print a report")
    run.add_argument("--format", choices=FORMATS, default="table", help="format printed to stdout (default: table)")
    run.add_argument("--output", metavar="FILE", help="write the --format output to FILE instead of stdout")
    run.add_argument("--json-out", metavar="FILE", help="also write the JSON report to FILE")
    run.add_argument("--markdown-out", metavar="FILE", help="also write the Markdown report to FILE")
    run.add_argument("--sarif-out", metavar="FILE", help="also write a SARIF 2.1.0 log to FILE")
    run.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="high",
        help="exit non-zero when a check of this severity or above fails (default: high)",
    )
    run.add_argument("--area", action="append", metavar="AREA", help="only run checks in AREA (repeatable)")
    run.add_argument("--check", action="append", metavar="ID", help="only run check ID (repeatable)")
    run.add_argument("--replay", metavar="FILE", help="evaluate a recorded host instead of this Mac")
    run.add_argument("--no-color", action="store_true", help="disable ANSI colours in the table")

    lst = sub.add_parser("list", help="print the check catalogue")
    lst.add_argument("--format", choices=("table", "json", "markdown"), default="table")

    exp = sub.add_parser("explain", help="explain a check and print remediation steps")
    exp.add_argument("id", metavar="ID")

    ren = sub.add_parser("render", help="render a saved JSON report in another format")
    ren.add_argument("--input", required=True, metavar="FILE")
    ren.add_argument("--format", choices=FORMATS, default="markdown")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_USAGE
    try:
        catalogue = cat.load(args.catalogue)
    except (OSError, cat.CatalogueError) as exc:
        print(f"{TOOL_NAME}: cannot load catalogue: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    handlers = {"run": cmd_run, "list": cmd_list, "explain": cmd_explain, "render": cmd_render}
    try:
        return handlers[args.command](args, catalogue)
    except OSError as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except BrokenPipeError:  # pragma: no cover - e.g. piping into head
        return 0
