# Roadmap

Small, self-contained improvements, each one commit that keeps CI green.
Size: 🟢 under an hour · 🟡 an evening · 🔴 a weekend.

## More scanners

Each parser needs a sample file in `samples/`, a function in `parsers.py`, a matching flag in `cli.py` (like `--semgrep`), and tests.

- [ ] 🟢 Bandit (Python SAST) JSON parser
- [ ] 🟡 Trivy JSON parser (container and filesystem scans)
- [ ] 🟡 Nessus `.nessus` XML parser (use `defusedxml`, never plain XML parsing on untrusted files)

## Prioritization

- [ ] 🟢 Cache KEV and EPSS downloads on disk for a day, so repeat runs don't hit the APIs
- [ ] 🟡 Asset criticality: a small config file that raises priority for findings on crown-jewel assets
- [ ] 🟡 Support CVSS 4.0 vectors

## Output

- [ ] 🟢 SARIF output so results show in GitHub's Security tab
- [ ] 🟡 Package as a reusable GitHub Action (`action.yml`) that other repos can call
