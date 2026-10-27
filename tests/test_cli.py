import csv
import json

import pytest

from vulntriage.cli import main


def run(samples, offline, tmp_path, *extra):
    return main(
        [
            "--semgrep", str(samples / "semgrep.json"),
            "--zap", str(samples / "zap.json"),
            "--nuclei", str(samples / "nuclei.jsonl"),
            "--pip-audit", str(samples / "pip-audit.json"),
            "--offline-data", str(offline),
            "--as-of", "2026-10-27",
            *extra,
        ]
    )  # fmt: skip


def test_end_to_end_reports(samples, offline, tmp_path, capsys):
    md, js, cs = tmp_path / "r.md", tmp_path / "r.json", tmp_path / "r.csv"
    assert run(samples, offline, tmp_path, "-o", str(md), "--json", str(js), "--csv", str(cs)) == 0

    results = json.loads(js.read_text())
    assert results[0]["title"].startswith("Apache Log4j2")  # KEV-listed, so ranked first
    assert results[0]["priority"] == "P1" and results[0]["due"] == "2026-11-03"
    assert results[0]["duplicates"] == 1

    text = md.read_text(encoding="utf-8")
    assert "# Vulnerability triage report" in text and "less noise" in text
    rows = list(csv.DictReader(cs.open(encoding="utf-8")))
    assert len(rows) == len(results)
    assert "raw findings ->" in capsys.readouterr().out


def test_jira_dry_run(samples, offline, tmp_path):
    out = tmp_path / "jira.json"
    run(samples, offline, tmp_path, "--jira-project", "SEC", "--jira-out", str(out))
    payloads = json.loads(out.read_text())
    assert payloads, "expected P1/P2 issues"
    fields = payloads[0]["fields"]
    assert fields["project"]["key"] == "SEC"
    assert fields["summary"].startswith("[P1]")
    assert fields["priority"]["name"] == "Highest"
    assert fields["duedate"] == "2026-11-03"


def test_fail_on_gate(samples, offline, tmp_path):
    assert run(samples, offline, tmp_path, "--fail-on", "P1") == 1


def test_requires_an_input():
    with pytest.raises(SystemExit):
        main([])
