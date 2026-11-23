"""The method end to end on a grid: CVE and GHSA findings, enriched by vuln_mosaic, through all four Searches and the
fedramp_20x_vdr bridge. The scenario is in `cve_grid.py`."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from . import cve_grid as g

# vuln_mosaic is not a dependency of this plugin (any enricher may fill the advisory fields), so this plugin's own CI
# record, closed over depends_on, does not install it and these tests skip there. They run in a session that composes
# both plugins; for the method's definition of done a skip does not count (CONTRIBUTING.md).
pytest.importorskip(
    "tap_plugin.vuln_mosaic.collectors.refresh.gridwrite", reason="needs vuln_mosaic installed beside aydlette_vdr"
)

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])

INPUTS = {"fedramp_class": "c", "now": g.NOW.isoformat()}
OVERLAY_ID = "fixture-overlay"


@pytest.fixture
def grid(tmp_path: Path) -> dict[str, Any]:
    ids: dict[str, Any] = dict(g.build_grid())
    ids["_enrichment"] = g.enrich(tmp_path / "vuln-mosaic-home")
    return ids


def rows_by_key(inputs: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    from tap_plugin.aydlette_vdr.searches.pain import aydlette_pain

    out = aydlette_pain(None, {**INPUTS, **(inputs or {})}, db_alias="default")  # type: ignore[arg-type]
    return {r["source_key"]: r for r in out["rows"]}


def vuln(vid: str) -> Any:
    from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability

    return ComplianceVulnerability.objects.get(vuln_id=vid)


def overlay_profile() -> None:
    from tap_grid.services import create_node

    starter = json.loads((Path(__file__).resolve().parents[1] / "grift" / "profiles.grift.json").read_text())
    (doc,) = [
        n["node"]["document"] for n in starter["batches"][0]["nodes"] if n["node"]["profile_id"] == "aydlette-starter"
    ]
    doc = {**doc, "ssvc_overlay": {"automatable_floor": True, "poc_check": True}}
    made = create_node("aydlette_vdr__profile", {"profile_id": OVERLAY_ID, "version": "1", "document": doc})
    assert made.success, made.errors


# ------------------------------------------------------------------------------------------------------- enrichment
@pytest.mark.spec("req-aydlette-vdr-grid-1")
def test_enrichment_fills_the_bare_advisory_records(grid):
    out = grid["_enrichment"]
    assert (out.patched, out.failed, out.stopped_early) == (len(g.VULN_IDS), 0, False), out.problems
    log4shell = vuln(g.LOG4SHELL)
    assert log4shell.cvss_source == "CISA-ADP" and log4shell.cvss_vector.startswith("CVSS:3.1/AV:N")
    assert (log4shell.kev, str(log4shell.kev_due_date), log4shell.epss_score) == (True, "2021-12-24", 0.97)
    assert (log4shell.ssvc_exploitation, log4shell.ssvc_automatable, log4shell.ssvc_technical_impact) == (
        "active", "yes", "total")  # fmt: skip
    assert vuln(g.UNHELD).kev is False and vuln(g.UNHELD).cvss_vector is None  # a fresh catalog's "not listed"
    assert vuln(g.GHSA).cvss_source == "GitHub advisory" and vuln(g.GHSA).kev is None  # KEV lists CVEs only


# ----------------------------------------------------------------------------------------------------- the findings
@pytest.mark.spec("req-aydlette-vdr-grid-2")
def test_each_factor_is_decided_by_the_feed_that_holds_it(grid):
    r = rows_by_key()
    assert (r["F1"]["irv"], r["F1"]["lev"], r["F1"]["lev_basis"]) == (True, True, "known exploited (KEV)")
    assert (r["F2"]["irv"], r["F2"]["irv_basis"]) == (False, "declared internal")
    assert (r["F2"]["lev"], r["F2"]["lev_basis"]) == (False, "prediction 0.0005 < theta 0.1")
    assert (r["F3"]["irv"], r["F3"]["lev"], r["F3"]["lev_basis"]) == (True, True, "prediction 0.21 >= theta 0.1")
    assert all(r[k]["vector_source"] == "record" for k in ("F1", "F2", "F3", "F6"))
    assert r["F2"]["prediction"]["feed_date"] == "2026-11-20"


@pytest.mark.spec("req-aydlette-vdr-grid-3")
def test_what_no_feed_holds_takes_the_worst_case(grid):
    r = rows_by_key()
    assert (r["F4"]["lev_basis"], r["F4"]["technical_impact"]) == ("no prediction score (fail-safe)", "total")
    assert (r["F5"]["resolved"], r["F5"]["irv_basis"]) == (False, "unresolved (fail-safe)")
    assert r["F5"]["lev_basis"] == "floor: access unknown, read as the worst case"
    assert r["F6"]["lev_basis"] == "no prediction score (fail-safe)"  # a local flaw off the floor, with no EPSS


@pytest.mark.spec("req-aydlette-vdr-sources-2")
def test_a_finding_with_no_record_is_evaluated_in_the_same_stream(grid):
    r = rows_by_key()
    assert set(r) == set(g.FINDINGS) and r["F7"]["vuln_id"] is None and r["F7"]["resolved"]


@pytest.mark.spec("req-aydlette-vdr-gates-1")
def test_kev_past_its_due_date_fails_g1_on_the_grid(grid):
    r = rows_by_key()
    assert r["F1"]["gates"]["G1"] and not any(r[k]["gates"]["G1"] for k in r if k != "F1")


@pytest.mark.spec("req-aydlette-vdr-rules-2")
def test_due_dates_come_from_the_seeded_rule_rows(grid):
    from tap_plugin.fedramp_20x_vdr.deadlines import acceptance_hours, deadline_hours

    from tap_plugin.aydlette_vdr.searches.pain import aydlette_pain

    r = rows_by_key()["F3"]
    detected = g.NOW - timedelta(days=30)
    hours = deadline_hours("c", r["pain"], r["column"])
    assert hours is not None
    assert r["due_at"] == (detected + timedelta(hours=hours)).isoformat()
    assert r["accept_by"] == (detected + timedelta(hours=acceptance_hours())).isoformat()
    rules = aydlette_pain(None, INPUTS, db_alias="default")["info"]["rules"]  # type: ignore[arg-type]
    assert rules["source"] == "fedramp_20x_vdr timeframe rows" and rules["rows"] > 0


@pytest.mark.spec("req-aydlette-vdr-grid-4")
def test_the_overlay_reads_vulnrichment_and_is_named(grid):
    overlay_profile()
    r = rows_by_key({"profile_id": OVERLAY_ID})
    assert (r["F2"]["technical_impact"], r["F2"]["technical_impact_basis"]) == ("partial", "ssvc")
    assert r["F1"]["lev_basis"] == "known exploited (KEV)"  # KEV still decides first


@pytest.mark.spec("req-aydlette-vdr-lev-16")
def test_each_output_says_whether_the_overlay_is_on(grid):
    from tap_plugin.aydlette_vdr.searches.pain import aydlette_pain

    overlay_profile()
    on = aydlette_pain(None, {**INPUTS, "profile_id": OVERLAY_ID}, db_alias="default")["info"]["profile"]  # type: ignore[arg-type]
    off = aydlette_pain(None, INPUTS, db_alias="default")["info"]["profile"]  # type: ignore[arg-type]
    assert (on["ssvc_overlay"], off["ssvc_overlay"]) == (True, False)


# ---------------------------------------------------------------------------------------- summary, reconcile, coverage
@pytest.mark.spec("req-aydlette-vdr-publication-1")
def test_the_summary_counts_gates_the_queue_and_the_withheld_tier(grid):
    from tap_plugin.aydlette_vdr.searches.pain import aydlette_summary

    (s,) = aydlette_summary(None, INPUTS, db_alias="default")["rows"]  # type: ignore[arg-type]
    assert s["findings"] == 7 and s["gates"]["G1"] == {"failed": True, "findings": 1}
    assert s["public_tier_withheld"] == 4  # F1, F3, F5, F6: open, IRV and LEV (the tier itself is the pipeline's, T26)
    assert s["queue"]["by_kind"]["unresolved"] == 1 and s["queue"]["rate"]["unresolved"] == "1/7"


@pytest.mark.spec("req-aydlette-vdr-grid-5")
def test_reconciliation_on_the_grid(grid):
    from tap_plugin.aydlette_vdr.searches.pain import aydlette_reconcile

    rows = {r["component"]: r for r in aydlette_reconcile(None, {"now": g.NOW.isoformat()}, db_alias="default")["rows"]}  # type: ignore[arg-type]
    assert {rows[grid[c]]["cell"] for c in ("www", "api", "db")} == {"consistent"}
    assert rows[grid["www"]]["publicly_exposed"] and not rows[grid["api"]]["publicly_exposed"]
    assert grid["stray"] not in rows


@pytest.mark.spec("req-aydlette-vdr-grid-6")
def test_coverage_counts_what_the_feeds_hold(grid):
    from tap_plugin.aydlette_vdr.searches.coverage import aydlette_coverage

    c = {r["key"]: r for r in aydlette_coverage(None, {"now": g.NOW.isoformat()}, db_alias="default")["rows"]}  # type: ignore[arg-type]
    share = {k: (c[k]["covered"], c[k]["total"]) for k in c}
    assert share["advisory_cvss"] == (4, 6) and share["advisory_kev"] == (5, 6)
    assert share["advisory_epss"] == (3, 6) and share["advisory_ssvc"] == (2, 6)
    assert share["check_vector"] == (0, 1) and share["findings_resolved"] == (6, 7)
    assert share["declared"] == (3, 4) and c["declared"]["missing"] == ["stray"]
    assert any(g.GHSA in m for m in c["advisory_kev"]["missing"])


# ------------------------------------------------------------------------------------------------------- the bridge
@pytest.mark.spec("req-aydlette-vdr-grid-7")
def test_the_bridge_backs_only_reconciled_unreachability(grid):
    from tap_plugin.fedramp_20x_vdr.evaluations import backed_factors

    from tap_grid.grift import grift_import

    from tap_plugin.aydlette_vdr.method.reconcile import ComponentState
    from tap_plugin.aydlette_vdr.searches.pain import evaluate_rows
    from tap_plugin.aydlette_vdr.vdr_bridge import build_evaluations

    states: dict[str, ComponentState] = {}
    rows, block = evaluate_rows({"now": g.NOW.isoformat()}, deadlines=False, states_sink=states)
    doc, counts = build_evaluations(rows, states, block["profile"], g.NOW)
    result = grift_import(doc)
    assert result.success, result.errors
    assert counts["evaluations"] == 7 and counts["backed_unreachable"] == 3
    backed = backed_factors([grid[k] for k in g.FINDINGS], scheme="aydlette")
    assert {k for k in g.FINDINGS if backed[grid[k]]["internet_reachable"] is False} == {"F2", "F4", "F7"}
    assert all(backed[grid[k]]["likely_exploitable"] is None for k in g.FINDINGS)


# ------------------------------------------------------------------------------------------- the environmental vector
def reset_flood(grid: dict[str, Any], tmp_path: Path, *, authenticated_ingress: bool | None) -> dict[str, Any]:
    g.add_reset_flood(grid, authenticated_ingress=authenticated_ingress)
    out = g.enrich(tmp_path / "vuln-mosaic-home-f8")
    assert out.failed == 0, out.problems
    return rows_by_key()["F8"]


@pytest.mark.spec("req-aydlette-vdr-grid-8")
def test_with_nothing_backed_the_floor_decides_the_reset_flood(grid, tmp_path):
    r = reset_flood(grid, tmp_path, authenticated_ingress=None)
    assert vuln(g.RESET_FLOOD).cvss_vector.startswith("CVSS:3.0/AV:N/AC:L/PR:N/UI:N")
    assert (r["irv"], r["lev"]) == (True, True) and r["lev_basis"].startswith("floor: reachable, network")
    assert r["environmental"]["modified"] == {}


@pytest.mark.spec("req-aydlette-vdr-grid-8")
def test_an_unauthenticated_route_backs_nothing(grid, tmp_path):
    r = reset_flood(grid, tmp_path, authenticated_ingress=False)
    assert r["lev_basis"].startswith("floor") and r["environmental"]["modified"] == {}


@pytest.mark.spec("req-aydlette-vdr-grid-9")
def test_authenticated_ingress_lowers_privileges_and_the_prediction_decides(grid, tmp_path):
    from tap_plugin.aydlette_vdr.searches.pain import aydlette_reconcile

    r = reset_flood(grid, tmp_path, authenticated_ingress=True)
    env = r["environmental"]
    assert env["modified"] == {"MPR": "L"} and env["vector"] == vuln(g.RESET_FLOOD).cvss_vector + "/MPR:L"
    assert (r["irv"], r["lev"], r["lev_basis"]) == (True, False, "prediction 0.02 < theta 0.1")
    rows = {x["component"]: x for x in aydlette_reconcile(None, {"now": g.NOW.isoformat()}, db_alias="default")["rows"]}  # type: ignore[arg-type]
    assert rows[grid["api"]]["ingress_authenticated"] and not rows[grid["db"]]["ingress_authenticated"]
