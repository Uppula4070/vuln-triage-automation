"""Write triaged findings as Markdown, JSON or CSV."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

from .models import Finding
from .prioritize import SLA_DAYS, effective_score

CSV_FIELDS = [
    "priority", "due", "title", "kind", "location", "cwe", "cves",
    "cvss", "epss", "kev", "sources", "reason", "fix",
]  # fmt: skip


def due_date(f: Finding, as_of: date) -> str:
    days = SLA_DAYS[f.priority]
    return (as_of + timedelta(days=days)).isoformat() if days else "backlog"


def _row(f: Finding, as_of: date) -> dict:
    return {
        "priority": f.priority,
        "due": due_date(f, as_of),
        "title": f.title,
        "kind": f.kind,
        "location": f.location,
        "cwe": f.cwe or "",
        "cves": " ".join(f.cves),
        "cvss": effective_score(f),
        "epss": "" if f.epss is None else round(f.epss, 4),
        "kev": "yes" if f.in_kev else "",
        "sources": "+".join(f.sources),
        "reason": f.reason,
        "fix": f.fix,
    }


def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def markdown(findings: list[Finding], raw_count: int, as_of: date) -> str:
    by_priority = Counter(f.priority for f in findings)
    reduction = 1 - len(findings) / raw_count if raw_count else 0
    lines = [
        "# Vulnerability triage report",
        "",
        f"Generated {as_of.isoformat()}. **{raw_count}** raw findings became **{len(findings)}** unique issues "
        f"({reduction:.0%} less noise).",
        "",
        "| Priority | Fix within | Count |",
        "|---|---|---|",
    ]
    for p in ("P1", "P2", "P3", "P4"):
        sla = f"{SLA_DAYS[p]} days" if SLA_DAYS[p] else "backlog"
        lines.append(f"| {p} | {sla} | {by_priority.get(p, 0)} |")
    lines += [
        "",
        "## Findings",
        "",
        "| # | Priority | Due | Issue | Location | CVSS | EPSS | KEV | Found by | Why this priority |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for i, f in enumerate(findings, 1):
        r = _row(f, as_of)
        epss = f"{f.epss:.1%}" if f.epss is not None else "–"
        lines.append(
            f"| {i} | **{f.priority}** | {r['due']} | {_md(f.title)} | `{_md(f.location)}` | {r['cvss']} | "
            f"{epss} | {'⚠️ yes' if f.in_kev else ''} | {r['sources']} | {_md(f.reason)} |"
        )
    urgent = [f for f in findings if f.priority in ("P1", "P2")]
    if urgent:
        lines += ["", "## P1 and P2 details", ""]
        for f in urgent:
            lines += [f"### {f.priority}: {f.title}", "", f"- **Location:** `{f.location}`"]
            if f.cwe:
                lines.append(f"- **Weakness:** {f.cwe}")
            if f.cves:
                lines.append(f"- **CVEs:** {', '.join(f.cves)}")
            if f.cvss_vector:
                lines.append(f"- **CVSS vector:** `{f.cvss_vector}`")
            if f.duplicates:
                lines.append(f"- **Merged:** {f.duplicates} duplicate report(s) from {', '.join(f.sources)}")
            if f.evidence:
                lines.append(f"- **Evidence:** `{_md(f.evidence)[:200]}`")
            if f.fix:
                lines.append(f"- **Fix:** {_md(f.fix)[:300]}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write(findings: list[Finding], raw_count: int, as_of: date, md=None, json_path=None, csv_path=None) -> None:
    if md:
        Path(md).write_text(markdown(findings, raw_count, as_of), encoding="utf-8")
    if json_path:
        data = [{**f.to_dict(), "due": due_date(f, as_of)} for f in findings]
        Path(json_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(_row(f, as_of) for f in findings)
