"""CVSS v3.x base score calculator, following the FIRST v3.1 specification."""

from __future__ import annotations

import math

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required weighs more when the scope changes.
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts[0].startswith("CVSS:3"):
        raise ValueError(f"not a CVSS v3 vector: {vector!r}")
    metrics = dict(part.split(":", 1) for part in parts[1:])
    missing = [m for m in REQUIRED if m not in metrics]
    if missing:
        raise ValueError(f"vector is missing {', '.join(missing)}: {vector!r}")
    return metrics


def roundup(value: float) -> float:
    """Round up to one decimal, avoiding floating point surprises (spec Appendix A)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    scope = m["S"]
    iss = 1 - ((1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]]))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = (
        8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]] * PR_WEIGHTS[scope][m["PR"]] * WEIGHTS["UI"][m["UI"]]
    )
    if impact <= 0:
        return 0.0
    if scope == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"
