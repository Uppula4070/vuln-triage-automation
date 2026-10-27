"""Assign P1-P4 by exploitation evidence first, severity second.

CVSS says how bad a flaw would be; EPSS and CISA KEV say how likely it is to be
used against you. A medium-severity CVE that is being exploited today outranks a
critical one nobody has a working exploit for.
"""

from __future__ import annotations

from .models import Finding

# Used when no CVSS score is available: a typical score for the tool's own rating.
DEFAULT_SCORE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}
SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": None}
EPSS_URGENT = 0.5
EPSS_ELEVATED = 0.1


def effective_score(f: Finding) -> float:
    return f.cvss_score if f.cvss_score is not None else DEFAULT_SCORE[f.severity]


def classify(f: Finding) -> tuple[str, str]:
    score = effective_score(f)
    basis = f"CVSS {score}" if f.cvss_score is not None else "scanner rating, no CVSS available"
    if f.in_kev:
        return "P1", "listed in CISA KEV: exploited in the wild"
    if f.epss is not None and f.epss >= EPSS_URGENT:
        return "P1", f"EPSS {f.epss:.0%}: likely to be exploited within 30 days"
    if score >= 9.0:
        return "P1", f"critical ({basis})"
    if score >= 7.0:
        return "P2", f"high ({basis})"
    if f.epss is not None and f.epss >= EPSS_ELEVATED:
        return "P2", f"EPSS {f.epss:.0%}, above the {EPSS_ELEVATED:.0%} watch threshold"
    if score >= 4.0:
        return "P3", f"medium ({basis})"
    return "P4", f"low ({basis})"


def prioritize(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        f.priority, f.reason = classify(f)
    return sorted(
        findings,
        key=lambda f: (f.priority, not f.in_kev, -(f.epss or 0.0), -effective_score(f), f.location),
    )
