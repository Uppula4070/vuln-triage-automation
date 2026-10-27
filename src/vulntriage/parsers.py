"""Turn each scanner's JSON output into a list of Findings."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .models import Finding

SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def normalize_cwe(value) -> str | None:
    """Accept 'CWE-89: Improper...', 'cwe-89', '89' or 89 and return 'CWE-89'."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    number = str(value).strip().upper().removeprefix("CWE-").split(":")[0].strip()
    if not number.isdigit() or int(number) <= 0:
        return None
    return f"CWE-{int(number)}"


def normalize_url(url: str, param: str | None = None) -> str:
    """Reduce a URL to what identifies the issue: host, path and parameter names.

    Parameter values are dropped so that `?q=test` and `?q='` count as the same
    place. A finding with no parameter at all (missing headers, banner leaks) is a
    site-wide setting, so it is grouped per host. `param=None` means the scanner
    didn't say, so the names come from the query string; `param=""` means the
    scanner said no parameter is involved.
    """
    parts = urlsplit(url)
    host = f"{parts.scheme}://{parts.netloc}".lower()
    if param is None:
        names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    else:
        names = [param] if param else []
    if not names:
        return host
    return f"{host}{parts.path or '/'}?{'&'.join(names)}"


def _cves(ids) -> list[str]:
    return sorted({i.upper() for i in ids if i and i.upper().startswith("CVE-")})


def parse_semgrep(data: dict) -> list[Finding]:
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        findings.append(
            Finding(
                tool="semgrep",
                rule_id=r["check_id"],
                title=extra.get("message", r["check_id"]).split("\n")[0][:200],
                severity=SEMGREP_SEVERITY.get(extra.get("severity", "").upper(), "medium"),
                kind="code",
                location=f"{r['path']}:{r['start']['line']}",
                cwe=normalize_cwe(meta.get("cwe")),
                evidence=extra.get("lines", "").strip(),
                fix=extra.get("fix", ""),
            )
        )
    return findings


def parse_zap(data: dict) -> list[Finding]:
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            for inst in alert.get("instances", []) or [{"uri": site.get("@name", "")}]:
                findings.append(
                    Finding(
                        tool="zap",
                        rule_id=str(alert.get("pluginid", "")),
                        title=alert.get("name") or alert.get("alert", ""),
                        severity=ZAP_RISK.get(str(alert.get("riskcode")), "info"),
                        kind="web",
                        location=normalize_url(inst.get("uri", ""), inst.get("param", "")),
                        cwe=normalize_cwe(alert.get("cweid")),
                        evidence=inst.get("evidence", ""),
                        fix=_strip_html(alert.get("solution", "")),
                    )
                )
    return findings


def parse_nuclei(lines: list[dict]) -> list[Finding]:
    findings = []
    for r in lines:
        info = r.get("info", {})
        cls = info.get("classification") or {}
        findings.append(
            Finding(
                tool="nuclei",
                rule_id=r.get("template-id", ""),
                title=info.get("name", r.get("template-id", "")),
                severity=(info.get("severity") or "info").lower(),
                kind="web",
                location=normalize_url(r.get("matched-at") or r.get("host", "")),
                cwe=normalize_cwe(cls.get("cwe-id")),
                cves=_cves(cls.get("cve-id") or []),
                cvss_vector=cls.get("cvss-metrics") or None,
                evidence=r.get("matched-at", ""),
                fix=info.get("remediation", ""),
            )
        )
    return findings


def parse_pip_audit(data: dict) -> list[Finding]:
    findings = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            fixes = v.get("fix_versions") or []
            cves = _cves([v["id"], *v.get("aliases", [])])
            findings.append(
                Finding(
                    tool="pip-audit",
                    rule_id=v["id"],
                    title=f"Vulnerable dependency {dep['name']} {dep['version']} ({cves[0] if cves else v['id']})",
                    severity="medium",  # pip-audit has no severity; enrichment fills it in
                    kind="dependency",
                    location=f"{dep['name'].lower()}=={dep['version']}",
                    cves=cves,
                    evidence=" ".join((v.get("description") or "").split())[:300],
                    fix=f"Upgrade to {fixes[0]} or later" if fixes else "",
                )
            )
    return findings


def _strip_html(text: str) -> str:
    return text.replace("<p>", "").replace("</p>", " ").strip()


def load(tool: str, path: str | Path) -> list[Finding]:
    text = Path(path).read_text(encoding="utf-8")
    if tool == "nuclei":
        return parse_nuclei([json.loads(line) for line in text.splitlines() if line.strip()])
    parser = {"semgrep": parse_semgrep, "zap": parse_zap, "pip-audit": parse_pip_audit}[tool]
    return parser(json.loads(text))
