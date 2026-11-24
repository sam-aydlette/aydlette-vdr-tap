"""The method end to end on simulated scanner output: Tenable Security Center and Qualys VM detections, written to a
grid as findings, enriched by vuln_mosaic and rated. The scenario and the harness that reads the exports are in
`scanner_grid.py`."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from . import cve_grid as g
from . import scanner_grid as s

# vuln_mosaic fills the advisory records, as in test_grid_cve.py: these tests skip where it is not installed and run in
# a session that composes both plugins.
pytest.importorskip(
    "tap_plugin.vuln_mosaic.collectors.refresh.gridwrite", reason="needs vuln_mosaic installed beside aydlette_vdr"
)

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])

INPUTS = {"fedramp_class": "c", "now": s.NOW.isoformat()}

# The findings, by scanner and what was found where.
T_LOG4SHELL_WEB = (s.TENABLE, "1:10.0.1.10:155999:8080:tcp", g.LOG4SHELL)
T_CERT_WEB = (s.TENABLE, "1:10.0.1.10:51192:443:tcp", None)  # a plugin with no CVE
T_RESET_FLOOD_APP = (s.TENABLE, "1:10.0.2.20:127907:8443:tcp", g.RESET_FLOOD)
T_KERNEL_DB_BHI = (s.TENABLE, "1:10.0.3.30:158900:0:tcp", g.BHI)  # one plugin, two CVEs; fixed once and came back
T_KERNEL_DB_0303 = (s.TENABLE, "1:10.0.3.30:158900:0:tcp", g.C0303)
T_FRAMEWORK_LAB = (s.TENABLE, "1:10.0.9.70:160301:8080:tcp", g.C0179)  # on a host nobody declared
Q_LOG4SHELL_WEB = (s.QUALYS, "700101:376157:8080:tcp", g.LOG4SHELL)
Q_FRAMEWORK_APP = (s.QUALYS, "700202:730418:8443:tcp", g.C0179)
Q_KERNEL_APP = (s.QUALYS, "700202:198712:0:", g.BHI)  # a Potential detection
Q_RESET_FLOOD_DB = (s.QUALYS, "700303:87412:8443:tcp", g.RESET_FLOOD)
OPEN = {
    T_LOG4SHELL_WEB, T_CERT_WEB, T_RESET_FLOOD_APP, T_KERNEL_DB_BHI, T_KERNEL_DB_0303, T_FRAMEWORK_LAB,
    Q_LOG4SHELL_WEB, Q_FRAMEWORK_APP, Q_KERNEL_APP, Q_RESET_FLOOD_DB,
}  # fmt: skip


@pytest.fixture
def grid(tmp_path: Path) -> dict[str, Any]:
    ids: dict[str, Any] = dict(s.build_grid())
    ids["_enrichment"] = g.enrich(tmp_path / "vuln-mosaic-home")
    return ids


def rows() -> dict[tuple[str, str, str | None], dict[str, Any]]:
    from tap_plugin.aydlette_vdr.searches.pain import aydlette_pain

    out = aydlette_pain(None, INPUTS, db_alias="default")  # type: ignore[arg-type]
    return {(r["finding_source"], r["source_key"], r["vuln_id"]): r for r in out["rows"]}


def hours(row: dict[str, Any]) -> float | None:
    if not row["due_at"]:
        return None
    return (datetime.fromisoformat(row["due_at"]) - datetime.fromisoformat(row["clock_start"])).total_seconds() / 3600


@pytest.mark.spec("req-aydlette-vdr-grid-10")
def test_every_open_detection_from_both_scanners_is_rated_and_nothing_else(grid):
    out = grid["_enrichment"]
    assert (out.patched, out.failed) == (5, 0), out.problems  # the five CVEs the two scanners name between them
    r = rows()
    assert set(r) == OPEN
    # Left out: Tenable's Info plugin and Qualys's Info detection (not findings), the result in Tenable's mitigated
    # database and the Qualys detection with status Fixed (both written as resolved findings).
    from tap_plugin.compliance_core.models.compliance_finding import ComplianceFinding

    stored = {(f.source, f.source_key): f.status for f in ComplianceFinding.objects.all()}
    assert len(stored) == 11 and sorted(k for k, v in stored.items() if v == "resolved") == [
        (s.QUALYS, "700303:376157:9200:tcp"),
        (s.TENABLE, "1:10.0.1.10:127907:443:tcp"),
    ]
    assert all(r[k]["vector_source"] == "record" for k in OPEN - {T_CERT_WEB, T_KERNEL_DB_0303})
    assert r[T_LOG4SHELL_WEB]["clock_start"] == "2026-11-06T12:00:00+00:00"  # Tenable's firstSeen
    assert r[Q_LOG4SHELL_WEB]["clock_start"] == "2026-11-05T05:30:00+00:00"  # Qualys's FIRST_FOUND_DATETIME


@pytest.mark.spec("req-aydlette-vdr-grid-11")
def test_one_flaw_reported_by_two_scanners_is_rated_alike(grid):
    r = rows()
    t, q = r[T_LOG4SHELL_WEB], r[Q_LOG4SHELL_WEB]
    same = ("irv", "irv_basis", "lev", "lev_basis", "technical_impact", "pain", "column", "due_at", "gates")
    assert {k: t[k] for k in same} == {k: q[k] for k in same}
    assert (t["irv_basis"], t["lev_basis"]) == ("declared public-edge", "known exploited (KEV)")
    # KEV's own due date replaces the timeframe, and it passed years ago: G1 on both.
    assert t["due_at"].startswith("2021-12-24") and t["state"] == "overdue" and t["gates"]["G1"] and q["gates"]["G1"]


@pytest.mark.spec("req-aydlette-vdr-grid-12")
def test_evidence_moves_scanner_findings_out_of_the_urgent_column(grid):
    from tap_plugin.aydlette_vdr.searches.pain import aydlette_reconcile

    r = rows()
    # The reset flood on app01: the scanner's vector says no privileges; every ingress into app01 is authenticated, so
    # the floor no longer decides and the low prediction does.
    flood = r[T_RESET_FLOOD_APP]
    assert flood["environmental"]["modified"] == {"MPR": "L"}
    assert (flood["irv"], flood["lev"], flood["lev_basis"]) == (True, False, "prediction 0.02 < theta 0.1")
    # The same flaw on db01: declared internal and backed by an observation, so the vector takes Adjacent.
    inner = r[Q_RESET_FLOOD_DB]
    assert inner["environmental"]["modified"] == {"MAV": "A"} and inner["irv_basis"] == "declared internal"
    assert (inner["irv"], inner["lev"]) == (False, False)
    # A local kernel flaw with a very low prediction, on both scanners.
    assert r[T_KERNEL_DB_BHI]["lev_basis"] == r[Q_KERNEL_APP]["lev_basis"] == "prediction 0.0005 < theta 0.1"
    moved = (T_RESET_FLOOD_APP, Q_RESET_FLOOD_DB, T_KERNEL_DB_BHI, Q_KERNEL_APP)
    assert {r[k]["column"] for k in moved} == {"nlev"}
    # Each has a deadline many times the 96 hours the same rating takes when reachable and likely exploitable.
    assert all((hours(r[k]) or 0) > 1000 and r[k]["state"] == "on time" for k in moved)
    assert r[Q_FRAMEWORK_APP]["pain"] == "N4" and hours(r[Q_FRAMEWORK_APP]) == 96
    rec = {x["component"]: x for x in aydlette_reconcile(None, {"now": s.NOW.isoformat()}, db_alias="default")["rows"]}  # type: ignore[arg-type]
    assert rec[grid["app01"]]["ingress_authenticated"] and rec[grid["db01"]]["perimeter_backed"]


@pytest.mark.spec("req-aydlette-vdr-grid-13")
def test_what_the_scanner_or_the_inventory_cannot_say_takes_the_worst_case(grid):
    r = rows()
    # A host nobody declared: reachable, the fail-safe classification, and overdue on the short timeframe.
    lab = r[T_FRAMEWORK_LAB]
    assert (lab["resolved"], lab["irv_basis"]) == (False, "unresolved (fail-safe)")
    assert lab["needs"] == {"c": "high", "i": "high", "a": "high"} and lab["agency_scope"] == "multi"
    assert lab["lev_basis"] == "prediction 0.21 >= theta 0.1" and lab["state"] == "overdue" and lab["gates"]["G3"]
    # A plugin with no CVE has no record: access is unknown, and impact comes from the scanner's severity word.
    cert = r[T_CERT_WEB]
    assert cert["lev_basis"] == "floor: access unknown, read as the worst case"
    assert cert["technical_impact_basis"] == "severity fallback (medium)"
    # A CVE whose record has no vector and no score, on an internal host: not reachable, still likely exploitable.
    bare = r[T_KERNEL_DB_0303]
    assert (bare["irv"], bare["lev"], bare["lev_basis"]) == (False, True, "no prediction score (fail-safe)")
    assert bare["column"] == "lev_nirv" and bare["technical_impact_basis"] == "severity fallback (medium)"
    # A detection the scanner could not confirm, and one that was fixed and came back, are open findings.
    assert Q_KERNEL_APP in r and T_KERNEL_DB_BHI in r


@pytest.mark.spec("req-aydlette-vdr-grid-14")
def test_the_bridge_writes_one_evaluation_per_scanner_finding_at_its_worst(grid):
    from tap_plugin.fedramp_20x_vdr.evaluations import backed_factors

    from tap_grid.grift import grift_import

    from tap_plugin.aydlette_vdr.method.reconcile import ComponentState
    from tap_plugin.aydlette_vdr.searches.pain import evaluate_rows
    from tap_plugin.aydlette_vdr.vdr_bridge import EVALUATION, build_evaluations

    states: dict[str, ComponentState] = {}
    evaluated, block = evaluate_rows({"now": s.NOW.isoformat()}, deadlines=False, states_sink=states)
    doc, counts = build_evaluations(evaluated, states, block["profile"], s.NOW)
    result = grift_import(doc)
    assert result.success, result.errors
    # Ten rows, nine findings: the kernel plugin's two CVEs are one finding.
    assert len(evaluated) == 10 and counts["evaluations"] == 9
    kernel = f"{T_KERNEL_DB_BHI[0]}|{T_KERNEL_DB_BHI[1]}"
    (written,) = [
        n["node"]
        for n in doc["batches"][0]["nodes"]
        if n["entity"]["entity_type"] == EVALUATION and n["node"]["finding_source_key"] == T_KERNEL_DB_BHI[1]
    ]
    # One of its CVEs is not likely exploitable and the other is: the finding takes the worse answer.
    assert (written["internet_reachable"], written["likely_exploitable"]) == (False, True)
    assert g.BHI in written["rationale"] and g.C0303 in written["rationale"]
    # Only the two findings on db01, whose perimeter reconciliation backs, are handed over as not reachable.
    flood = f"{Q_RESET_FLOOD_DB[0]}|{Q_RESET_FLOOD_DB[1]}"
    findings = {k: v for k, v in grid.items() if "|" in k}
    backed = backed_factors(list(findings.values()), scheme="aydlette")
    assert {k for k, v in findings.items() if backed[v]["internet_reachable"] is False} == {kernel, flood}
    assert counts["backed_unreachable"] == 2
    assert all(backed[v]["likely_exploitable"] is None for v in findings.values())
