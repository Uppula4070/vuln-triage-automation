import pytest

from vulntriage.enrich import OfflineSource, enrich
from vulntriage.models import Finding
from vulntriage.prioritize import classify, prioritize


def make(**kw) -> Finding:
    base = {"tool": "t", "rule_id": "r", "title": "x", "severity": "medium", "kind": "web", "location": "l"}
    return Finding(**{**base, **kw})


@pytest.mark.parametrize(
    ("finding", "priority"),
    [
        (make(severity="low", in_kev=True), "P1"),  # exploited in the wild beats a low score
        (make(severity="medium", epss=0.6), "P1"),
        (make(severity="critical"), "P1"),
        (make(cvss_score=7.5, severity="high"), "P2"),
        (make(severity="medium", epss=0.2), "P2"),
        (make(severity="medium", epss=0.01), "P3"),
        (make(severity="low"), "P4"),
        (make(severity="info"), "P4"),
    ],
)
def test_classify(finding, priority):
    assert classify(finding)[0] == priority


def test_kev_reason_is_explained():
    assert "CISA KEV" in classify(make(in_kev=True))[1]


def test_sort_order_puts_exploited_first():
    findings = prioritize(
        [
            make(location="a", severity="critical"),
            make(location="b", severity="medium", in_kev=True),
            make(location="c", severity="low"),
        ]
    )
    assert [f.location for f in findings] == ["b", "a", "c"]


def test_offline_enrichment(offline):
    dep = make(kind="dependency", rule_id="PYSEC-2018-28", cves=["CVE-2018-18074"], location="requests==2.19.1")
    log4j = make(cves=["CVE-2021-44228"], severity="critical")
    enrich([dep, log4j], OfflineSource(offline))
    assert dep.cvss_score == 7.5 and dep.severity == "high"
    assert dep.epss == pytest.approx(0.06925)
    assert not dep.in_kev
    assert log4j.in_kev and log4j.epss > 0.99
