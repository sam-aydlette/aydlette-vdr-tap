"""aydlette_vdr results as fedramp_20x_vdr evaluations: what is written, and what is backed."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tap_plugin.aydlette_vdr import vdr_bridge as vb
from tap_plugin.aydlette_vdr.method.reconcile import ComponentState

NOW = datetime(2026, 11, 18, tzinfo=UTC)
PROFILE = {"profile_id": "p", "version": "1", "sha256": "ab" * 32}


def row(fid="f1", cid="c1", irv=False, basis="declared internal", lev=False, pain="N2", vuln=None):
    return {"finding_id": fid, "finding_source": "scan", "source_key": f"k-{fid}", "component_id": cid, "irv": irv,
            "irv_basis": basis, "lev": lev, "lev_basis": "below theta", "pain": pain, "needs_basis": "declared",
            "vuln_id": vuln}  # fmt: skip


def state(cell="consistent", path=False, intent="internal", g4=(), g5=(), g7=()):
    return ComponentState(component="c1", intent=intent, observed_path=path, cell=cell, publicly_exposed=False,
                          suggested_intent="internal", g4=list(g4), g5=list(g5), g7=list(g7), queue=[],
                          inherited_data=(), evidence=[{"observer": "outside-in", "observed_at": "t", "path_found": False,
                                                        "fresh": True, "allowlisted": False, "evidence": "probe"}])  # fmt: skip


def kinds(doc, etype):
    b = doc["batches"][0]
    return [n for n in b["nodes"] if n["entity"]["entity_type"] == etype] + [
        e for e in b["edges"] if e["edge"]["edge_type"] == etype]  # fmt: skip


@pytest.mark.spec("req-aydlette-vdr-bridge-1")
def test_reconciled_internal_component_backs_unreachable_with_evidence():
    doc, counts = vb.build_evaluations([row()], {"c1": state()}, PROFILE, NOW)
    (ev,) = kinds(doc, vb.EVALUATION)
    assert (
        ev["node"]["internet_reachable"] is False
        and ev["node"]["pain"] is None
        and "PAIN N2" in ev["node"]["rationale"]
    )
    assert ev["node"]["scheme"] == "aydlette" and ev["entity"]["dimensions"]["vdr.scheme"] == "aydlette"
    (factor,) = kinds(doc, vb.FACTOR_EVIDENCE)
    assert factor["edge"]["properties"]["factor"] == "internet_reachable"
    assert factor["edge"]["properties"]["basis"] == "protected_at_perimeter"
    (cites,) = kinds(doc, vb.FINDING_EVIDENCE)
    assert cites["edge"]["from_entity_id"] == "f1" and len(kinds(doc, vb.EVIDENCE)) == 1
    assert cites["edge"]["properties"]["support_kind"] == "informational"  # never makes the finding pass
    assert counts["backed_unreachable"] == 1


@pytest.mark.spec("req-aydlette-vdr-bridge-2")
def test_nothing_is_backed_without_clean_reconciliation():
    for st in (state(g7=["stale"]), state(cell="unobserved", path=None), state(g5=["conflict"]), None):
        doc, counts = vb.build_evaluations([row()], {"c1": st} if st else {}, PROFILE, NOW)
        assert counts["backed_unreachable"] == 0 and not kinds(doc, vb.FACTOR_EVIDENCE)
        assert kinds(doc, vb.EVALUATION)[0]["node"]["internet_reachable"] is False  # recorded, not backed


@pytest.mark.spec("req-aydlette-vdr-bridge-3")
def test_dispositions_and_lev_are_recorded_but_never_backed():
    doc, _ = vb.build_evaluations([row(basis="deflection d1")], {"c1": state()}, PROFILE, NOW)
    assert not kinds(doc, vb.FACTOR_EVIDENCE)
    assert kinds(doc, vb.EVALUATION)[0]["node"]["likely_exploitable"] is False


@pytest.mark.spec("req-aydlette-vdr-bridge-4")
def test_several_cves_on_one_finding_combine_to_the_worst():
    rows = [row(vuln="a", pain="N2"), row(vuln="b", irv=True, basis="declared public-edge", lev=True, pain="N4")]
    doc, counts = vb.build_evaluations(rows, {"c1": state()}, PROFILE, NOW)
    (ev,) = kinds(doc, vb.EVALUATION)
    assert (
        ev["node"]["internet_reachable"] and ev["node"]["likely_exploitable"] and "PAIN N4" in ev["node"]["rationale"]
    )
    assert counts == {"evaluations": 1, "backed_unreachable": 0, "irv": 1, "lev": 1}


@pytest.mark.spec("req-aydlette-vdr-bridge-5")
def test_one_evidence_node_per_component():
    doc, counts = vb.build_evaluations([row("f1"), row("f2")], {"c1": state()}, PROFILE, NOW)
    assert len(kinds(doc, vb.EVIDENCE)) == 1 and counts["backed_unreachable"] == 2
