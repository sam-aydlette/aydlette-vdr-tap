"""Appendix B conformance tests for reconciliation (Figure 6, flows, observer coverage), on the pure core."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tap_plugin.aydlette_vdr.method.evaluate import Declaration
from tap_plugin.aydlette_vdr.method.reconcile import Flow, Observation, reconcile

NOW = datetime(2026, 11, 18, 12, tzinfo=UTC)


def D(cid, intent, data=("internal",)):  # noqa: N802
    return Declaration(cid, exposure_intent=intent, data=tuple(data))


def path(target, found, observer="inside-out", age_h=1, allowlisted=None):
    return Observation(f"{observer}:{target}", observer, "internet-path", target, found, NOW - timedelta(hours=age_h),
                       allowlisted=allowlisted)  # fmt: skip


def flow_seen(src, dst, observer="telemetry"):
    return Observation(f"{observer}:{src}>{dst}", observer, "flow", dst, True, NOW - timedelta(hours=1), source=src)


def run(decls, obs=(), flows=()):
    return reconcile({d.component_id: d for d in decls}, list(obs), list(flows), now=NOW)


def test_t1_t27_internal_with_observed_path_is_undeclared_exposure():
    st = run([D("db", "internal")], [path("db", True)])["db"]
    assert st.cell == "undeclared-exposure" and st.g4


def test_t3_public_edge_with_no_path_is_over_declared_and_queued():
    st = run([D("web", "public-edge")], [path("web", False), path("web", False, "outside-in")])["web"]
    assert st.cell == "over-declared" and st.queue[0]["kind"] == "over-declared" and not st.g4


def test_t4_public_backed_with_declared_public_flow_is_consistent():
    decls = [D("fn", "public-edge"), D("db", "public-backed")]
    st = run(decls, [path("db", False), path("fn", True), path("fn", True, "outside-in")],
             [Flow("f1", "fn", "db", carries=("internal",))])  # fmt: skip
    assert st["db"].cell == "consistent" and not st["db"].g5 and not st["db"].g4


def test_public_backed_without_a_public_flow_is_over_declared():
    assert run([D("db", "public-backed")], [path("db", False)])["db"].cell == "over-declared"


def test_t5_declared_public_flow_into_internal_fails_g5():
    st = run([D("fn", "public-edge"), D("db", "internal")], [path("db", False)],
             [Flow("f1", "fn", "db", carries=("internal",))])  # fmt: skip
    assert st["db"].g5


def test_t39_observed_public_flow_into_internal_is_undeclared_exposure():
    st = run([D("fn", "public-edge"), D("db", "internal")], [path("db", False), flow_seen("fn", "db")])
    assert st["db"].cell == "undeclared-exposure" and st["db"].g4


def test_other_undeclared_flow_is_queued():
    st = run([D("a", "internal"), D("b", "internal")], [path("b", False), flow_seen("a", "b")])
    assert any(q["kind"] == "undeclared-flow" for q in st["b"].queue) and not st["b"].g4


def test_t45_flow_carrying_pii_into_unflagged_component_fails_g5():
    st = run([D("a", "internal", ("pii",)), D("b", "internal")], [path("b", False)],
             [Flow("f", "a", "b", carries=("pii",))])  # fmt: skip
    assert any("carries pii" in g for g in st["b"].g5)


def test_t46_metadata_only_flow_with_reason_is_accepted():
    st = run([D("a", "internal", ("pii",)), D("b", "internal")], [path("b", False)],
             [Flow("f", "a", "b", metadata_reason="scanner agent: host names and package versions only")])  # fmt: skip
    assert not st["b"].g5


def test_metadata_only_flow_without_reason_fails_g5():
    st = run([D("a", "internal"), D("b", "internal")], [path("b", False)], [Flow("f", "a", "b")])
    assert st["b"].g5


def test_t47_telemetry_flow_from_pii_component_is_queued_and_inherits_pii():
    st = run([D("a", "internal", ("pii",)), D("b", "internal")], [path("b", False), flow_seen("a", "b")])["b"]
    assert st.inherited_data == ("pii",) and any(q["kind"] == "undeclared-flow" for q in st.queue)


def test_stale_or_missing_inside_out_observation_fails_g7():
    assert run([D("a", "internal")])["a"].g7
    st = run([D("a", "internal")], [path("a", False, age_h=30)])["a"]
    assert st.g7 and st.cell == "unobserved"


def test_public_edge_needs_an_outside_in_observation():
    st = run([D("web", "public-edge")], [path("web", True)])["web"]
    assert any("outside-in" in g for g in st.g7)


def test_t42_allowlisted_probe_is_recorded():
    st = run([D("web", "public-edge")], [path("web", True), path("web", True, "outside-in", allowlisted=True)])["web"]
    assert any(e["allowlisted"] for e in st.evidence)


def test_t63_public_backed_is_not_publicly_exposed():
    decls = [D("fn", "public-edge"), D("db", "public-backed")]
    st = run(decls, [path("db", False)], [Flow("f", "fn", "db", carries=("internal",))])
    assert not st["db"].publicly_exposed and st["fn"].publicly_exposed


def test_suggested_intent_never_replaces_the_declaration():
    st = run([Declaration("x", data=("internal",))], [path("x", True)])["x"]
    assert st.cell == "undeclared" and st.intent is None and st.suggested_intent == "public-edge"


def test_suggests_public_backed_for_a_component_fed_by_a_reachable_one():
    st = run([Declaration("fn", data=("public",)), Declaration("db", data=("internal",))],
             [path("fn", True), path("db", False), flow_seen("fn", "db", "inside-out")])  # fmt: skip
    assert st["db"].suggested_intent == "public-backed"


def test_public_backed_with_a_direct_path_is_undeclared_exposure():
    """Figure 6: a backed component has no direct path. One reachable around its front is drift (G4)."""
    st = run([D("fn", "public-edge"), D("api", "public-backed")], [path("api", True)])["api"]
    assert st.cell == "undeclared-exposure" and st.g4
