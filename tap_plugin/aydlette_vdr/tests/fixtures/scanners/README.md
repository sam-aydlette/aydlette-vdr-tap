# Scanner grid fixture data

Inputs for `tests/scanner_grid.py`. **Simulated, not recorded.** Each file is written from the vendor's documented
response format; none came from a real console, and no field's behaviour here has been checked against one.

| File | Shaped like |
| --- | --- |
| `tenable_sc_cumulative.json` | Tenable Security Center, `POST /rest/analysis` with tool `vulndetails`, source `cumulative` (current vulnerabilities) |
| `tenable_sc_patched.json` | The same query with source `patched` (the mitigated database) |
| `qualys_host_detections.xml` | Qualys VM, `GET /api/2.0/fo/asset/host/vm/detection/?action=list` |
| `qualys_knowledge_base.xml` | Qualys VM, `GET /api/2.0/fo/knowledge_base/vuln/?action=list` for the QIDs above |

The hosts, addresses, host ids and repository are invented (`*.fixture.test`, `10.0.0.0/8`). The CVE ids are real, and
are the ones whose advisory records are in `../cve_grid/`. Plugin ids and QIDs are illustrative: some match the
vendor's real check for that CVE and some are made up, and no test depends on which.
