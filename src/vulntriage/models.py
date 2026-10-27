from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    """One issue reported by a scanner, normalized to a common shape."""

    tool: str
    rule_id: str
    title: str
    severity: str
    kind: str  # "code", "web" or "dependency"
    location: str  # file:line, normalized URL, or package==version
    cwe: str | None = None
    cves: list[str] = field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    epss: float | None = None
    in_kev: bool = False
    evidence: str = ""
    fix: str = ""
    sources: list[str] = field(default_factory=list)
    duplicates: int = 0
    priority: str | None = None
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
