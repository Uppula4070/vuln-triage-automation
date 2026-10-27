import json

from vulntriage.dedupe import dedupe
from vulntriage.parsers import load


def test_two_semgrep_rules_on_one_line_merge(samples):
    findings = dedupe(load("semgrep", samples / "semgrep.json"))
    sqli = [f for f in findings if f.cwe == "CWE-89"]
    assert len(sqli) == 1
    assert sqli[0].severity == "high"  # keeps the higher of WARNING and ERROR
    assert sqli[0].duplicates == 1


def test_zap_and_nuclei_agree_on_sqli(samples):
    raw = load("zap", samples / "zap.json") + load("nuclei", samples / "nuclei.jsonl")
    sqli = [f for f in dedupe(raw) if f.cwe == "CWE-89"]
    assert len(sqli) == 1
    assert sqli[0].sources == ["zap", "nuclei"]
    assert sqli[0].severity == "critical"
    assert sqli[0].duplicates == 2


def test_header_issues_group_per_host(samples):
    findings = dedupe(load("zap", samples / "zap.json"))
    banner = [f for f in findings if f.cwe == "CWE-497"]
    assert len(banner) == 1
    assert banner[0].duplicates == 3


def test_pip_audit_duplicates_collapse(samples):
    raw = json.loads((samples / "pip-audit.json").read_text())
    unique = {(d["name"], v["id"]) for d in raw["dependencies"] for v in d["vulns"]}
    findings = dedupe(load("pip-audit", samples / "pip-audit.json"))
    assert len(findings) == len(unique)


def test_different_weaknesses_stay_separate(samples):
    findings = dedupe(load("semgrep", samples / "semgrep.json"))
    assert sorted(f.cwe for f in findings) == ["CWE-489", "CWE-798", "CWE-89"]
