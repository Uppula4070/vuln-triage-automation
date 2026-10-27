import pytest

from vulntriage.cvss import base_score, roundup, severity


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # typical unauthenticated RCE
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # reflected XSS
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # CVE-2018-18074
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score_matches_nvd(vector, expected):
    assert base_score(vector) == expected


def test_roundup():
    assert roundup(4.02) == 4.1
    assert roundup(4.0) == 4.0
    # Tiny floating point noise must not push a score up a whole tenth.
    assert roundup(4.000000001) == 4.0


@pytest.mark.parametrize("bad", ["CVSS:4.0/AV:N/AC:L", "CVSS:3.1/AV:N/AC:L", "garbage"])
def test_rejects_bad_vectors(bad):
    with pytest.raises(ValueError):
        base_score(bad)


@pytest.mark.parametrize(
    ("score", "label"), [(9.8, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"), (0, "info")]
)
def test_severity_bands(score, label):
    assert severity(score) == label
