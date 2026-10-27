import json

import pytest

from vulntriage.parsers import load, normalize_cwe, normalize_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (["CWE-89: Improper Neutralization"], "CWE-89"),
        ("cwe-79", "CWE-79"),
        ("89", "CWE-89"),
        (497, "CWE-497"),
        ("-1", None),
        ("0", None),
        ([], None),
        (None, None),
    ],
)
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


def test_normalize_url_drops_param_values():
    a = normalize_url("http://Host:5000/notes/unsafe?q=test")
    b = normalize_url("http://host:5000/notes/unsafe?q=%27")
    assert a == b == "http://host:5000/notes/unsafe?q"


def test_normalize_url_uses_explicit_param():
    assert normalize_url("http://h/search?q=x&page=2", "q") == "http://h/search?q"


def test_normalize_url_without_params_is_site_wide():
    assert normalize_url("http://h:5000/robots.txt") == "http://h:5000"
    # The scanner said no parameter is involved, even though the URL has a query.
    assert normalize_url("http://h:5000/notes?q=test", "") == "http://h:5000"


def test_semgrep(samples):
    findings = load("semgrep", samples / "semgrep.json")
    assert len(findings) == 4
    sqli = findings[1]
    assert (sqli.severity, sqli.cwe, sqli.location) == ("high", "CWE-89", "app/app.py:98")


def test_zap_creates_one_finding_per_instance(samples):
    findings = load("zap", samples / "zap.json")
    assert len(findings) == 8
    assert {f.severity for f in findings if f.cwe == "CWE-89"} == {"high"}


def test_nuclei_reads_cves_and_cvss(samples):
    findings = load("nuclei", samples / "nuclei.jsonl")
    log4j = [f for f in findings if f.rule_id == "CVE-2021-44228"]
    assert len(log4j) == 2
    assert log4j[0].cves == ["CVE-2021-44228"]
    assert log4j[0].cvss_vector.startswith("CVSS:3.1/")


def test_pip_audit_keeps_cve_aliases(samples):
    findings = load("pip-audit", samples / "pip-audit.json")
    raw = json.loads((samples / "pip-audit.json").read_text())
    assert len(findings) == sum(len(d["vulns"]) for d in raw["dependencies"])
    requests_vuln = next(f for f in findings if f.rule_id == "PYSEC-2018-28")
    assert requests_vuln.cves == ["CVE-2018-18074"]
    assert requests_vuln.location == "requests==2.19.1"
