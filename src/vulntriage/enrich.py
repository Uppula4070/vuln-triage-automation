"""Add real-world risk data: CVSS vectors (OSV), exploit likelihood (EPSS), known exploitation (CISA KEV)."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

from . import cvss
from .models import Finding

OSV_URL = "https://api.osv.dev/v1/vulns/{}"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH = 50


def _get_json(url: str, timeout: int = 20) -> dict:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "vulntriage"})  # noqa: S310 - https checked above
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.load(resp)


def _cvss_v3(osv_record: dict) -> str | None:
    for sev in osv_record.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            return sev["score"]
    return None


class OnlineSource:
    """Live lookups. Any network failure is reported and skipped, never fatal."""

    def kev_ids(self) -> set[str]:
        try:
            return {v["cveID"] for v in _get_json(KEV_URL)["vulnerabilities"]}
        except Exception as exc:  # noqa: BLE001
            print(f"warning: CISA KEV lookup failed: {exc}", file=sys.stderr)
            return set()

    def epss(self, cves: list[str]) -> dict[str, float]:
        scores: dict[str, float] = {}
        for i in range(0, len(cves), EPSS_BATCH):
            batch = ",".join(cves[i : i + EPSS_BATCH])
            try:
                for row in _get_json(EPSS_URL.format(batch))["data"]:
                    scores[row["cve"]] = float(row["epss"])
            except Exception as exc:  # noqa: BLE001
                print(f"warning: EPSS lookup failed: {exc}", file=sys.stderr)
        return scores

    def cvss_vector(self, ids: list[str]) -> str | None:
        for vuln_id in ids:
            try:
                vector = _cvss_v3(_get_json(OSV_URL.format(vuln_id)))
            except Exception:  # noqa: BLE001, S112 - unknown IDs are normal, try the next alias
                continue
            if vector:
                return vector
        return None


class OfflineSource:
    """Reads saved copies of the same feeds, for tests and air-gapped runs.

    The directory holds kev.json (CISA format), epss.json (FIRST format) and
    osv/<ID>.json (OSV format).
    """

    def __init__(self, directory: str | Path):
        self.dir = Path(directory)

    def _read(self, name: str) -> dict:
        path = self.dir / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def kev_ids(self) -> set[str]:
        return {v["cveID"] for v in self._read("kev.json").get("vulnerabilities", [])}

    def epss(self, cves: list[str]) -> dict[str, float]:
        wanted = set(cves)
        return {
            row["cve"]: float(row["epss"]) for row in self._read("epss.json").get("data", []) if row["cve"] in wanted
        }

    def cvss_vector(self, ids: list[str]) -> str | None:
        for vuln_id in ids:
            vector = _cvss_v3(self._read(f"osv/{vuln_id}.json"))
            if vector:
                return vector
        return None


def enrich(findings: list[Finding], source) -> None:
    kev = source.kev_ids()
    epss = source.epss(sorted({c for f in findings for c in f.cves}))
    for f in findings:
        if not f.cvss_vector and f.kind == "dependency":
            f.cvss_vector = source.cvss_vector([f.rule_id, *f.cves])
        if f.cvss_vector and f.cvss_score is None:
            try:
                f.cvss_score = cvss.base_score(f.cvss_vector)
                f.severity = cvss.severity(f.cvss_score)
            except (ValueError, KeyError):
                pass  # e.g. a CVSS v4 vector; keep the tool's own severity
        known = [epss[c] for c in f.cves if c in epss]
        f.epss = max(known) if known else None
        f.in_kev = any(c in kev for c in f.cves)
