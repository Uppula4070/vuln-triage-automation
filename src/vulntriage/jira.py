"""Turn triaged findings into Jira issues (dry run by default)."""

from __future__ import annotations

import base64
import json
import os
import urllib.request
from datetime import date

from .models import Finding
from .report import due_date

JIRA_PRIORITY = {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}


def issue_payload(f: Finding, project: str, as_of: date) -> dict:
    lines = [
        f"*Priority:* {f.priority} ({f.reason})",
        f"*Location:* {{{{{f.location}}}}}",
        f"*Found by:* {', '.join(f.sources)}",
    ]
    if f.cwe:
        lines.append(f"*Weakness:* {f.cwe}")
    if f.cves:
        lines.append(f"*CVEs:* {', '.join(f.cves)}")
    if f.cvss_vector:
        lines.append(f"*CVSS:* {f.cvss_score} {{{{{f.cvss_vector}}}}}")
    if f.epss is not None:
        lines.append(f"*EPSS:* {f.epss:.1%}")
    if f.fix:
        lines.append(f"*Fix:* {f.fix}")
    lines.append("Close this ticket only after a rescan confirms the finding is gone.")
    fields = {
        "project": {"key": project},
        "issuetype": {"name": "Bug"},
        "summary": f"[{f.priority}] {f.title}"[:250],
        "description": "\n".join(lines),
        "priority": {"name": JIRA_PRIORITY[f.priority]},
        "labels": ["security", f"triage-{f.priority.lower()}", f.kind],
    }
    due = due_date(f, as_of)
    if due != "backlog":
        fields["duedate"] = due
    return {"fields": fields}


def create_issues(payloads: list[dict]) -> list[str]:
    """POST each payload. Needs JIRA_URL, JIRA_EMAIL and JIRA_API_TOKEN in the environment."""
    base = os.environ["JIRA_URL"].rstrip("/")
    if not base.startswith("https://"):
        raise ValueError("JIRA_URL must use https:// so the API token is never sent in clear text")
    token = base64.b64encode(f"{os.environ['JIRA_EMAIL']}:{os.environ['JIRA_API_TOKEN']}".encode()).decode()
    keys = []
    for payload in payloads:
        req = urllib.request.Request(  # noqa: S310 - https enforced above
            f"{base}/rest/api/2/issue",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            keys.append(json.load(resp)["key"])
    return keys
