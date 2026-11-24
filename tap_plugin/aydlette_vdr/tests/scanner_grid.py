"""The scanner grid fixture: simulated Tenable Security Center and Qualys VM output, as findings on a real grid.

The method reads `compliance_core` findings and does not care which scanner produced them. This fixture checks that
claim on output shaped like two scanners': it reads each scanner's export, writes the findings a scanner adapter would
write, and leaves everything after that to the code that ships (vuln_mosaic's enrichment, reconciliation, the
evaluation, the Searches and the bridge).

**The translators here are a test harness, not an integration.** No plugin on the grid turns Tenable or Qualys output
into `compliance_core` findings today, so `tenable_findings` and `qualys_findings` do the least such an adapter must:
one finding per detection, open or resolved, carried by the host it was found on, concerning each CVE it names, with
the scanner's severity as a fact. The export files are written from the vendors' documented response formats, not
recorded from a console (`fixtures/scanners/README.md`).

The scenario:

| Host | Declared | Observed |
|---|---|---|
| `web01` 10.0.1.10 | public-edge, public data | a path, inside-out and outside-in |
| `app01` 10.0.2.20 | public-backed, PII; a declared flow from `web01` carrying PII | no path; every ingress authenticated |
| `db01` 10.0.3.30 | internal, PII and CUI, single agency | no path |
| `lab07` 10.0.9.70 | nothing | nothing |

What each rule below does with a scanner's own states:

| Scanner | State | Finding |
|---|---|---|
| Tenable | a row in the cumulative database | open (`hasBeenMitigated` 1 means it was fixed once and came back) |
| Tenable | a row in the mitigated ("patched") database | resolved |
| Tenable | severity Info | not a finding |
| Qualys | status New, Active or Re-Opened | open |
| Qualys | status Fixed | resolved |
| Qualys | type Potential | open: a detection the scanner could not confirm is not a false positive |
| Qualys | type Info | not a finding |

A host is matched to a component by its IP address, through `ADDRESSES`. Joining a scanner's hosts to an inventory is
its own problem and is not solved here.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET  # noqa: S405 - parses this repository's own fixture files, never network input
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import cve_grid as g

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "scanners"
NOW = g.NOW
TENABLE = "tenable-sc-fixture"
QUALYS = "qualys-vm-fixture"
DECLARATIONS = "scanner-grid-fixture"
ADDRESSES = {"10.0.1.10": "web01", "10.0.2.20": "app01", "10.0.3.30": "db01", "10.0.9.70": "lab07"}
#: Qualys rates severity 1 to 5. The method's severity fallback reads words, so the harness maps them. A real adapter
#: would govern this mapping; it is used only for a finding with no CVSS vector.
QUALYS_SEVERITY = {"1": "low", "2": "low", "3": "medium", "4": "high", "5": "critical"}


def tenable_findings() -> list[dict[str, Any]]:
    """One finding per Security Center result: `key`, `name`, `ip`, `cves`, `severity`, `status`, `first`."""
    out = []
    for name, status in (("tenable_sc_cumulative.json", "open"), ("tenable_sc_patched.json", "resolved")):
        doc = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        for r in doc["response"]["results"]:
            if r["severity"]["id"] == "0":
                continue
            out.append({
                "source": TENABLE,
                "key": f"{r['repository']['id']}:{r['ip']}:{r['pluginID']}:{r['port']}:{r['protocol'].lower()}",
                "name": r["pluginName"], "ip": r["ip"], "cves": [c for c in r["cve"].split(",") if c],
                "severity": r["severity"]["name"].lower(), "status": status,
                "first": datetime.fromtimestamp(int(r["firstSeen"]), UTC),
            })  # fmt: skip
    return out


def qualys_findings() -> list[dict[str, Any]]:
    """One finding per Qualys detection, with its CVEs and title from the knowledge base."""
    kb = {
        v.findtext("QID"): v
        for v in ET.parse(FIXTURES / "qualys_knowledge_base.xml").getroot().iter("VULN")  # noqa: S314
    }
    out = []
    for host in ET.parse(FIXTURES / "qualys_host_detections.xml").getroot().iter("HOST"):  # noqa: S314
        for d in host.iter("DETECTION"):
            if d.findtext("TYPE") == "Info":
                continue
            qid = d.findtext("QID") or ""
            out.append({
                "source": QUALYS,
                "key": f"{host.findtext('ID')}:{qid}:{d.findtext('PORT') or '0'}:{d.findtext('PROTOCOL') or ''}",
                "name": kb[qid].findtext("TITLE") or qid, "ip": host.findtext("IP"),
                "cves": [c.findtext("ID") or "" for c in kb[qid].iter("CVE")],
                "severity": QUALYS_SEVERITY[d.findtext("SEVERITY") or ""],
                "status": "resolved" if d.findtext("STATUS") == "Fixed" else "open",
                "first": datetime.fromisoformat((d.findtext("FIRST_FOUND_DATETIME") or "").replace("Z", "+00:00")),
            })  # fmt: skip
    return out


def build_grid() -> dict[str, str]:
    """Seed the rules and the starter profile, create the hosts with their declarations and observations, and write
    both scanners' findings. Returns entity ids: hosts by name, findings by `<source>|<key>`."""
    import tap_plugin.fedramp_20x_vdr as vdr_pkg

    from tap_grid.grift import grift_import
    from tap_grid.models import Entity
    from tap_grid.services import create_edge, create_node

    from .. import models as _models  # noqa: F401

    pkg = Path(__file__).resolve().parents[1]
    for path in (Path(vdr_pkg.__file__).parent / "grift" / "dimension.grift.json",
                 Path(vdr_pkg.__file__).parent / "grift" / "timeframes.grift.json",
                 pkg / "grift" / "profiles.grift.json"):  # fmt: skip
        result = grift_import(json.loads(path.read_text(encoding="utf-8")))
        assert result.success, (path.name, result.errors)

    ids: dict[str, str] = {}

    def node(etype: str, payload: dict[str, Any]) -> str:
        made = create_node(etype, payload)
        assert made.success, (etype, made.errors)
        return str(made.entity_id)

    def edge(a: str, b: str, etype: str) -> None:
        create_edge(Entity.objects.get(pk=a), Entity.objects.get(pk=b), etype, {})

    for host in ADDRESSES.values():
        ids[host] = node("computing_core__host", {"name": host, "realm": "fixture", "stable_id": host})

    declarations: dict[str, dict[str, Any]] = {
        "web01": {"exposure_intent": "public-edge", "data": ["public"], "agency_scope": "multi"},
        "app01": {"exposure_intent": "public-backed", "data": ["pii"], "agency_scope": "multi"},
        "db01": {"exposure_intent": "internal", "data": ["pii", "cui"], "agency_scope": "single"},
    }
    for host, fields in declarations.items():
        d = node("aydlette_vdr__declaration", {"source": DECLARATIONS, "declaration_key": host,
                                               "classified_by": "data owner", "criticality_judged_by": "system owner",
                                               "exposure_rationale": f"Fixture: {host}.", **fields})  # fmt: skip
        edge(d, ids[host], "DECLARES_COMPONENT__aydlette_vdr")
    f = node("aydlette_vdr__declared_flow", {"source": DECLARATIONS, "flow_key": "web01>app01", "carries": ["pii"]})
    edge(f, ids["web01"], "FLOW_SOURCE__aydlette_vdr")
    edge(f, ids["app01"], "FLOW_TARGET__aydlette_vdr")

    seen = (NOW - timedelta(hours=1)).isoformat()
    for host, observer, kind, found in (
        ("web01", "inside-out", "internet-path", True), ("web01", "outside-in", "internet-path", True),
        ("app01", "inside-out", "internet-path", False), ("db01", "inside-out", "internet-path", False),
        ("app01", "inside-out", "unauth-ingress", False),
    ):  # fmt: skip
        o = node("aydlette_vdr__observation", {
            "source": DECLARATIONS, "observation_key": f"{host}|{observer}|{kind}", "observer": observer, "kind": kind,
            "path_found": found, "observed_at": seen, "allowlisted": False if observer == "outside-in" else None,
            "method": "fixture", "evidence": f"fixture {observer} {kind} observation of {host}"})  # fmt: skip
        edge(o, ids[host], "OBSERVES_COMPONENT__aydlette_vdr")

    vulns: dict[str, str] = {}
    for finding in tenable_findings() + qualys_findings():
        key = {"source": finding["source"], "source_key": finding["key"]}
        fid = node("compliance_core__compliance_finding", {
            **key, "name": finding["name"][:255], "status": finding["status"],
            "first_detected_at": finding["first"].isoformat()})  # fmt: skip
        ids[f"{finding['source']}|{finding['key']}"] = fid
        if finding["ip"] in ADDRESSES:
            edge(ids[ADDRESSES[finding["ip"]]], fid, "CARRIES_COMPLIANCE_FINDING__compliance_core")
        for cve in finding["cves"]:
            if cve not in vulns:
                vulns[cve] = node("compliance_core__compliance_vulnerability", {"vuln_id": cve})
            edge(fid, vulns[cve], "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core")
        facts = node("aydlette_vdr__finding_facts", {"source": finding["source"], "facts_key": finding["key"],
                                                     "scanner_severity": finding["severity"]})  # fmt: skip
        edge(facts, fid, "DESCRIBES_FINDING__aydlette_vdr")
    return ids
