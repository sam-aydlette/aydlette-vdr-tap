"""The environmental vector: CVSS Environmental metrics set only where reconciliation backs them, on the pure core."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tap_plugin.aydlette_vdr.method import vector as vec
from tap_plugin.aydlette_vdr.method.evaluate import Declaration
from tap_plugin.aydlette_vdr.method.reconcile import (
    Observation,
    ingress_authenticated,
    perimeter_backed,
    reconcile,
)

from .test_conformance import NET, OVERLAY, D, F, P, ev

NOW = datetime(2026, 11, 18, 12, tzinfo=UTC)
NET_LOW_PRIV = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
AUTHED = {"ingress_authenticated": True}
PERIMETER = {"perimeter_backed": True}


# ------------------------------------------------------------------------------------------------ the modified metrics
@pytest.mark.spec("req-aydlette-vdr-env-1")
def test_backed_authenticated_ingress_sets_mpr_low_and_lifts_the_floor():
    open_ = ev(F(cvss_vector=NET, prediction=0.01), [D("public-backed")])
    authed = ev(F(cvss_vector=NET, prediction=0.01), [D("public-backed", **AUTHED)])
    assert open_.lev and open_.lev_basis.startswith("floor")
    assert not authed.lev and authed.lev_basis == "prediction 0.01 < theta 0.1"
    assert authed.environmental["modified"] == {"MPR": "L"}
    assert authed.environmental["vector"] == NET + "/MPR:L"
    assert authed.environmental["basis"]["MPR"].startswith("authenticated ingress backed")


@pytest.mark.spec("req-aydlette-vdr-env-2")
def test_a_backed_perimeter_sets_mav_adjacent():
    e = ev(F(cvss_vector=NET), [D("internal", **PERIMETER)])
    assert e.environmental["modified"] == {"MAV": "A"} and e.environmental["vector"].endswith("/MAV:A")
    assert e.irv_basis == "declared internal"  # reachability is still decided by Figure 5


@pytest.mark.spec("req-aydlette-vdr-env-2")
def test_mav_adjacent_makes_a_vector_read_flaw_not_automatable_under_the_overlay():
    plain = ev(F(cvss_vector=NET, ssvc_exploitation="poc", prediction=0.01), [D("internal")], profile=P(**OVERLAY))
    backed = ev(F(cvss_vector=NET, ssvc_exploitation="poc", prediction=0.01), [D("internal", **PERIMETER)],
                profile=P(**OVERLAY))  # fmt: skip
    assert plain.lev and plain.lev_basis.startswith("public proof of concept")
    assert not backed.lev


@pytest.mark.spec("req-aydlette-vdr-env-3")
def test_a_modified_metric_only_lowers_a_network_or_none_base_value():
    e = ev(F(cvss_vector=NET_LOW_PRIV), [D("public-backed", **AUTHED)])
    assert e.environmental["modified"] == {}
    e = ev(F(cvss_vector=LOCAL), [D("internal", **PERIMETER)])
    assert e.environmental["modified"] == {}


@pytest.mark.spec("req-aydlette-vdr-env-4")
def test_nothing_backed_keeps_the_base_vector():
    e = ev(F(cvss_vector=NET), [D("public-backed")])
    assert e.environmental == {"base_vector": NET, "vector": NET, "modified": {}, "basis": {}}


@pytest.mark.spec("req-aydlette-vdr-env-4")
def test_the_records_own_environmental_metrics_are_never_read():
    published = NET + "/MAV:L/MPR:H/CR:H"  # the publisher's environment, not this one
    e = ev(F(cvss_vector=published, prediction=0.01), [D("public-backed")])
    assert e.lev and e.lev_basis.startswith("floor")
    assert e.environmental["vector"] == NET


@pytest.mark.spec("req-aydlette-vdr-env-5")
def test_an_unresolved_finding_takes_no_modified_metric():
    e = ev(F(cvss_vector=NET, prediction=0.01))
    assert not e.resolved and e.environmental["modified"] == {} and e.lev


@pytest.mark.spec("req-aydlette-vdr-env-5")
def test_a_finding_on_several_components_needs_the_backing_on_all_of_them():
    both = [Declaration("a", "public-backed", data=("internal",), **AUTHED),
            Declaration("b", "public-backed", data=("internal",), **AUTHED)]  # fmt: skip
    one = [both[0], Declaration("b", "public-backed", data=("internal",))]
    assert ev(F(cvss_vector=NET), both).environmental["modified"] == {"MPR": "L"}
    assert ev(F(cvss_vector=NET), one).environmental["modified"] == {}


@pytest.mark.spec("req-aydlette-vdr-env-6")
def test_scanner_access_takes_the_same_modified_metrics():
    e = ev(F(access=(True, False, False), prediction=0.01), [D("public-backed", **AUTHED)])
    assert e.environmental["modified"] == {"MPR": "L"} and e.environmental["vector"] is None
    assert not e.lev


@pytest.mark.spec("req-aydlette-vdr-env-6")
def test_a_cvss_4_vector_takes_the_same_modified_metrics():
    e = ev(F(cvss_vector=V4, prediction=0.01), [D("public-backed", **AUTHED)])
    assert e.environmental["vector"] == V4 + "/MPR:L" and not e.lev


@pytest.mark.spec("req-aydlette-vdr-env-4")
def test_the_environmental_vector_keeps_only_base_metrics_and_the_methods_own():
    v4 = V4 + "/E:X/CR:X/MAV:X/MPR:X/S:X"
    assert vec.with_environmental(v4, {"MPR": "L"}) == V4 + "/MPR:L"
    assert vec.parse(vec.with_environmental(NET, {"MAV": "A", "MPR": "L"})) == vec.parse(NET)  # parse reads Base only


# ---------------------------------------------------------------------------------------------- what reconciliation backs
def obs(kind, target, found, observer="inside-out", age_h=1, source=None):
    return Observation(f"{observer}:{kind}:{target}", observer, kind, target, found, NOW - timedelta(hours=age_h),
                       source=source)  # fmt: skip


def run(decls, observations):
    return reconcile({d.component_id: d for d in decls}, list(observations), [], now=NOW)


def api(intent="public-edge"):
    return Declaration("api", exposure_intent=intent, data=("internal",))


@pytest.mark.spec("req-aydlette-vdr-env-7")
def test_ingress_is_authenticated_only_on_a_fresh_answer_with_no_unauthenticated_path():
    seen = [obs("internet-path", "api", True), obs("internet-path", "api", True, "outside-in")]
    assert ingress_authenticated(run([api()], [*seen, obs("unauth-ingress", "api", False)])["api"])
    assert not ingress_authenticated(run([api()], [*seen, obs("unauth-ingress", "api", True)])["api"])
    assert not ingress_authenticated(run([api()], seen)["api"])  # no answer: nothing backed, nothing fails
    stale = run([api()], [*seen, obs("unauth-ingress", "api", False, age_h=48)])["api"]
    assert stale.unauthenticated_path is None and not stale.g7 and not ingress_authenticated(stale)


@pytest.mark.spec("req-aydlette-vdr-env-7")
def test_one_unauthenticated_answer_outweighs_another_that_found_none():
    seen = [obs("internet-path", "api", True), obs("internet-path", "api", True, "outside-in")]
    two = [obs("unauth-ingress", "api", False), obs("unauth-ingress", "api", True, "telemetry")]
    assert run([api()], [*seen, *two])["api"].unauthenticated_path is True


@pytest.mark.spec("req-aydlette-vdr-env-7")
def test_ingress_backing_needs_a_consistent_component_with_no_gate_failing_or_undeclared_flow():
    authed = obs("unauth-ingress", "api", False)
    no_inside_out = run([api()], [obs("internet-path", "api", True, "outside-in"), authed])["api"]
    assert no_inside_out.g7 and not ingress_authenticated(no_inside_out)
    over = run([api()], [obs("internet-path", "api", False), obs("internet-path", "api", False, "outside-in"), authed])
    assert over["api"].cell == "over-declared" and not ingress_authenticated(over["api"])
    decls = [api(), Declaration("job", exposure_intent="internal", data=("internal",))]
    flows = [obs("internet-path", "api", True), obs("internet-path", "api", True, "outside-in"), authed,
             obs("flow", "api", True, "telemetry", source="job"), obs("internet-path", "job", False)]  # fmt: skip
    assert not ingress_authenticated(run(decls, flows)["api"])


@pytest.mark.spec("req-aydlette-vdr-env-8")
def test_the_perimeter_is_backed_only_for_a_consistent_internal_component_with_no_path():
    db = Declaration("db", exposure_intent="internal", data=("internal",))
    assert perimeter_backed(run([db], [obs("internet-path", "db", False)])["db"])
    assert not perimeter_backed(run([db], [obs("internet-path", "db", True)])["db"])
    assert not perimeter_backed(run([db], [obs("internet-path", "db", False, age_h=48)])["db"])
    assert not perimeter_backed(run([api("public-backed")], [obs("internet-path", "api", False)])["api"])
