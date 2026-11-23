# CVE grid fixture data

Inputs for `tests/cve_grid.py`.

| File | What | Source |
| --- | --- | --- |
| `CVE-2021-44228.json` | Log4Shell, with CISA's ADP container (Vulnrichment: CVSS and SSVC) | CVE List record, copied from vuln-mosaic-tap's test corpus (commit `1e9902c`) |
| `CVE-2022-0001.json` | Branch History Injection, with CISA ADP | the same |
| `CVE-2022-0179.json` | A CNA-scored record with no ADP container | the same |
| `CVE-2022-0303.json` | A record with no CVSS metrics | the same |
| `GHSA-fmf4-pr35-46c2.json` | A GitHub advisory with a CVSS vector | the same |
| `CVE-2019-9514.json` | HTTP/2 Reset Flood, a CNA-scored network, no-privileges, no-interaction vector (the environmental-vector tests) | CVE List record, fetched from cveawg.mitre.org on 2026-11-23 |

The advisory records are real. CVE List records are published by the CVE Program under its terms of use; GitHub
advisory records are published by GitHub under CC BY 4.0. The KEV catalog and EPSS scores the fixture seeds are
illustrative, not CISA's or FIRST's data: see `KEV_LISTED` and `EPSS` in `tests/cve_grid.py`.
