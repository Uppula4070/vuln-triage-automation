from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import __version__, jira, report
from .dedupe import dedupe
from .enrich import OfflineSource, OnlineSource, enrich
from .parsers import load
from .prioritize import prioritize

TOOLS = ("semgrep", "zap", "nuclei", "pip-audit")
PRIORITIES = ("P1", "P2", "P3", "P4")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulntriage",
        description="Merge, de-duplicate and risk-rank findings from security scanners.",
    )
    inputs = p.add_argument_group("scanner results (give at least one; each can repeat)")
    for tool in TOOLS:
        inputs.add_argument(f"--{tool}", action="append", default=[], metavar="FILE", help=f"{tool} JSON output")
    p.add_argument("--offline-data", metavar="DIR", help="use saved KEV/EPSS/OSV data instead of live APIs")
    p.add_argument("--no-enrich", action="store_true", help="skip CVSS/EPSS/KEV lookups entirely")
    p.add_argument("-o", "--output", metavar="FILE", help="write a Markdown report")
    p.add_argument("--json", metavar="FILE", help="write JSON results")
    p.add_argument("--csv", metavar="FILE", help="write CSV results")
    p.add_argument("--jira-project", metavar="KEY", help="build Jira issues for P1/P2 findings in this project")
    p.add_argument(
        "--jira-out", metavar="FILE", default="jira-issues.json", help="where to save Jira payloads (dry run)"
    )
    p.add_argument("--jira-create", action="store_true", help="actually create the issues (needs JIRA_* env vars)")
    p.add_argument("--fail-on", choices=PRIORITIES, help="exit with code 1 if any finding is this priority or higher")
    p.add_argument("--as-of", type=date.fromisoformat, default=date.today(), help="date used for due dates")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    files = {tool: getattr(args, tool.replace("-", "_")) for tool in TOOLS}
    if not any(files.values()):
        parser.error("give at least one scanner result file")
    raw = [f for tool, paths in files.items() for path in paths for f in load(tool, path)]

    findings = dedupe(raw)
    if not args.no_enrich:
        enrich(findings, OfflineSource(args.offline_data) if args.offline_data else OnlineSource())
    findings = prioritize(findings)

    report.write(findings, len(raw), args.as_of, md=args.output, json_path=args.json, csv_path=args.csv)

    counts = {p: sum(f.priority == p for f in findings) for p in PRIORITIES}
    print(f"{len(raw)} raw findings -> {len(findings)} unique  |  " + "  ".join(f"{p}: {n}" for p, n in counts.items()))
    for f in findings[:5]:
        print(f"  {f.priority}  {f.title[:70]:<70}  {f.reason}")

    if args.jira_project:
        urgent = [f for f in findings if f.priority in ("P1", "P2")]
        payloads = [jira.issue_payload(f, args.jira_project, args.as_of) for f in urgent]
        if args.jira_create:
            print("created Jira issues: " + ", ".join(jira.create_issues(payloads)))
        else:
            Path(args.jira_out).write_text(json.dumps(payloads, indent=2), encoding="utf-8")
            print(f"dry run: {len(payloads)} Jira issue payloads written to {args.jira_out}")

    if args.fail_on and any(f.priority <= args.fail_on for f in findings):
        print(f"failing: found {args.fail_on} or higher", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
