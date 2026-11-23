"""Coverage of the method's prerequisites, on the pure core."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tap_plugin.aydlette_vdr.method.coverage import coverage, is_advisory, summary
from tap_plugin.aydlette_vdr.method.evaluate import Declaration
from tap_plugin.aydlette_vdr.method.reconcile import Flow, Observation, reconcile

NOW = datetime(2026, 11, 19, 12, tzinfo=UTC)


def D(cid, intent="internal", data=("internal",), **kw):  # noqa: N802
    return Declaration(cid, exposure_intent=intent, data=tuple(data), **kw)


def seen(target, found=False, observer="inside-out", age_h=1, source=None, kind="internet-path"):
    return Observation(f"{observer}:{source}>{target}", observer, kind, target, found, NOW - timedelta(hours=age_h),
                       source=source)  # fmt: skip


def row(fid, vuln_id=None, *, irv_basis="declared internal", lev_basis="prediction 0.01 < theta 0.1",
        vector_source="record", needs_basis="declared", resolved=True):  # fmt: skip
    return {"finding_id": fid, "finding": fid, "vuln_id": vuln_id, "irv_basis": irv_basis, "lev_basis": lev_basis,
            "vector_source": vector_source, "needs_basis": needs_basis, "resolved": resolved}  # fmt: skip


def run(decls, obs=(), flows=(), rows=(), vulns=None, inventory=()):
    decls = {d.component_id: d for d in decls}
    states = reconcile(decls, list(obs), list(flows), now=NOW)
    checks = coverage(inventory=set(inventory) | {o.target for o in obs}, declarations=decls, states=states,
                      observations=list(obs), flows=list(flows), rows=list(rows), vulns=vulns or {})  # fmt: skip
    return {c.key: c for c in checks}


@pytest.mark.spec("req-aydlette-vdr-coverage-1")
def test_untagged_resources_an_observer_saw_count_against_declared():
    c = run([D("api")], [seen("api"), seen("table"), seen("queue")])
    assert (c["declared"].covered, c["declared"].total) == (1, 3)
    assert c["declared"].missing == ("queue", "table")


@pytest.mark.spec("req-aydlette-vdr-coverage-2")
def test_missing_declaration_fields_are_listed_by_component():
    c = run([D("a", data=()), D("b", intent=None, classified_by="sam", agency_scope="single")], [seen("a"), seen("b")])
    assert c["data_classification"].missing == ("a",) and c["exposure_intent"].missing == ("b",)
    assert c["classified_by"].missing == ("a",) and c["agency_scope"].missing == ("a",)


@pytest.mark.spec("req-aydlette-vdr-coverage-3")
def test_observer_gaps_split_inside_out_and_outside_in():
    c = run([D("cdn", "public-edge"), D("db")], [seen("cdn", True, age_h=48)])
    assert c["inside_out"].missing == ("cdn", "db")
    assert (c["outside_in"].total, c["outside_in"].missing) == (1, ("cdn",))


@pytest.mark.spec("req-aydlette-vdr-coverage-4")
def test_public_backed_needs_a_declared_flow_from_a_public_component():
    decls = [D("cdn", "public-edge"), D("site", "public-backed"), D("fn", "public-backed")]
    c = run(decls, flows=[Flow("f1", "cdn", "site", ("public",))])
    assert (c["public_backed_fed"].covered, c["public_backed_fed"].missing) == (1, ("fn",))


@pytest.mark.spec("req-aydlette-vdr-coverage-5")
def test_observed_flows_are_checked_against_declared_flows():
    obs = [seen("bucket", True, observer="inside-out", source="cdn", kind="flow"),
           seen("fn", True, observer="inside-out", source="api", kind="flow")]  # fmt: skip
    c = run([D("bucket"), D("fn")], obs, flows=[Flow("f1", "api", "fn", (), "metadata only: invoke events")])
    assert c["observed_flows_declared"].missing == ("cdn -> bucket",)
    assert c["flows_state_carries"].covered == 1


@pytest.mark.spec("req-aydlette-vdr-coverage-6")
def test_fail_safe_factors_are_counted_per_row():
    rows = [row("f1"), row("f2", irv_basis="unresolved (fail-safe)", lev_basis="no prediction score (fail-safe)",
                         vector_source=None, needs_basis="fail-safe (unresolved)", resolved=False)]  # fmt: skip
    c = run([D("a")], rows=rows)
    for key in ("irv_on_evidence", "lev_on_evidence", "impact_vector", "needs_declared", "findings_resolved"):
        assert (c[key].covered, c[key].total, c[key].missing) == (1, 2, ("f2",)), key


@pytest.mark.spec("req-aydlette-vdr-coverage-7")
def test_advisory_feeds_apply_only_to_advisories_and_checks_need_a_vector():
    rows = [row("f1", "CVE-2026-12345"), row("f2", "samsite-check:checkov:CKV_AWS_117", vector_source=None),
            row("f3", None, vector_source="check-vector (decided by sam on 2026-11-19)")]  # fmt: skip
    vulns = {"CVE-2026-12345": {"cvss_vector": "CVSS:3.1/AV:N", "kev": False, "epss_score": None,
                                "ssvc_exploitation": "none"}}  # fmt: skip
    c = run([D("a")], rows=rows, vulns=vulns)
    assert c["advisory_kev"].total == 1 and c["advisory_kev"].covered == 1
    assert c["advisory_epss"].missing == ("f1 [CVE-2026-12345]",)
    assert (c["check_vector"].total, c["check_vector"].missing) == (2, ("f2 [samsite-check:checkov:CKV_AWS_117]",))


@pytest.mark.spec("req-aydlette-vdr-coverage-8")
def test_no_advisories_is_not_applicable_rather_than_failing():
    c = run([D("a")], rows=[row("f1", "zap:10099")])
    assert c["advisory_cvss"].total == 0 and c["advisory_cvss"].share is None
    s = summary(list(c.values()))
    assert s["not_applicable"] >= 4 and "advisory_cvss" not in " ".join(s["gaps"])


@pytest.mark.parametrize(
    ("vid", "advisory"),
    [("CVE-2024-3094", True), ("cve-2021-44228", True), ("GHSA-jfh8-c2jp-5v3q", True), ("PYSEC-2023-12", True),
     ("GO-2024-2687", True), ("MAL-2023-1234", True), ("MAL-2023-", False), ("CKV_AWS_117", False), ("zap:10099", False), ("AVD-AWS-0089", False), (None, False)],
)  # fmt: skip
@pytest.mark.spec("req-aydlette-vdr-coverage-7")
def test_advisory_ids(vid, advisory):
    assert is_advisory(vid) is advisory


@pytest.mark.spec("req-aydlette-vdr-coverage-9")
def test_summary_lists_gaps_worst_first():
    c = run([D("a", data=()), D("b")], [seen("a"), seen("b"), seen("c")])
    gaps = summary(list(c.values()))["gaps"]
    assert gaps.index("criticality_judged_by: 0/2") < gaps.index("declared: 2/3")
