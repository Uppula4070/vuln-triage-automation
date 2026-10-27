"""Collapse findings that describe the same issue, within one tool or across tools."""

from __future__ import annotations

from .models import SEVERITY_RANK, Finding


def dedupe_key(f: Finding) -> tuple:
    if f.kind == "dependency":
        # The same advisory has several IDs (PYSEC, GHSA, CVE); key on the CVE when there is one.
        return ("dependency", f.location, f.cves[0] if f.cves else f.rule_id)
    # Code and web issues are the same when they share a weakness (CWE) and a place.
    # Without a CWE, fall back to the rule plus any CVE so unrelated rules don't merge.
    return (f.kind, f.cwe or f"{f.rule_id}:{','.join(f.cves)}", f.location)


def dedupe(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple, Finding] = {}
    for f in findings:
        key = dedupe_key(f)
        kept = merged.get(key)
        if kept is None:
            f.sources = [f.tool]
            merged[key] = f
            continue
        kept.duplicates += 1
        if f.tool not in kept.sources:
            kept.sources.append(f.tool)
        if SEVERITY_RANK[f.severity] > SEVERITY_RANK[kept.severity]:
            kept.severity = f.severity
            kept.title = f.title
        kept.cves = sorted(set(kept.cves) | set(f.cves))
        kept.cvss_vector = kept.cvss_vector or f.cvss_vector
        kept.evidence = kept.evidence or f.evidence
        kept.fix = kept.fix or f.fix
    return list(merged.values())
