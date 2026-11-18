"""Appendix B conformance tests that the method decides on its own (no observer, no build), run on the pure core.

Each test is named for its row in Appendix B of "Vulnerability Evidence as a Product" (samaydlette.com, 2026-10-23). Tests
that need an observer, a signed build or a live system (T2, T3, T17, T20, T27, T42, T51, T52, T72 to T74, among others) are
not here: they are the pipeline's, not the method's. Timeframes are the Class C VDR-TFR-PVR cells; the method reads
whatever the pinned rules say, so the numbers only make the tests concrete.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from tap_plugin.aydlette_vdr.method import profile as prof
from tap_plugin.aydlette_vdr.method.evaluate import Declaration, Disposition, Finding, evaluate

LEVELS = ("N1", "N2", "N3", "N4", "N5")
NOW = datetime(2026, 11, 18, 12, tzinfo=UTC)
TODAY = NOW.date()
CLASS_C = {  # (pain, column) -> hours
    ("N5", "lev_irv"): 48, ("N5", "lev_nirv"): 96, ("N5", "nlev"): 384,
    ("N4", "lev_irv"): 96, ("N4", "lev_nirv"): 192, ("N4", "nlev"): 1536,
    ("N3", "lev_irv"): 384, ("N3", "lev_nirv"): 768, ("N3", "nlev"): 3072,
    ("N2", "lev_irv"): 1152, ("N2", "lev_nirv"): 3072, ("N2", "nlev"): 4608,
}  # fmt: skip
MAX_OVERDUE = 192 * 24
BASE = {"profile_id": "test", "version": "1", "theta": 0.10, "theta_rationale": "test value"}
NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL_AVAIL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
AVAIL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"  # the HTTP/2 flood scenario: availability only


def P(**over):  # noqa: N802
    return prof.validate({**BASE, **over}, LEVELS)


def ev(finding=None, decls=(), disps=(), profile=None, now=NOW):
    return evaluate(
        finding or Finding("f", first_detected_at=NOW - timedelta(days=1)),
        list(decls),
        list(disps),
        profile or P(),
        now=now,
        timeframe_hours=lambda p, c: CLASS_C.get((p, c)),
        max_overdue_hours=MAX_OVERDUE,
        top_level="N5",
    )


def D(intent="public-edge", data=("internal",), **kw):  # noqa: N802
    return Declaration("comp", exposure_intent=intent, data=tuple(data), **kw)


def F(**kw):  # noqa: N802
    kw.setdefault("first_detected_at", NOW - timedelta(days=1))
    return Finding("f", **kw)


def disp(kind, **kw):
    kw.setdefault("review_by", TODAY + timedelta(days=30))
    kw.setdefault("decided_by", "owner")
    kw.setdefault("decided_on", TODAY - timedelta(days=1))
    return Disposition(f"d-{kind}", kind, reason="r", **kw)


# ---------------------------------------------------------------------------------------------------- reachability, G4/G5
def test_t1_declared_internal_with_observed_path_fails_g4_and_is_irv():
    e = ev(F(), [D("internal", undeclared_exposure=True)])
    assert e.gates["G4"] and e.irv


def test_t4_public_backed_is_irv_and_no_gate_fails():
    e = ev(F(cvss_vector=LOCAL_AVAIL, prediction=0.0), [D("public-backed")])
    assert e.irv and not e.gates["G5"] and not e.gates["G4"]


def test_t6_no_exposure_intent_fails_g5():
    e = ev(F(), [D(None)])
    assert e.gates["G5"] and e.irv


def test_t7_t38_unresolved_is_irv_fail_safe_and_queued():
    e = ev(F(cvss_vector=AVAIL), [])
    assert e.irv and not e.resolved
    assert e.needs == {"c": "high", "i": "high", "a": "high"} and e.agency_scope == "multi"
    assert [q["kind"] for q in e.queue] == ["unresolved"]


def test_t32_non_machine_finding_is_nirv():
    assert not ev(F(non_machine=True), [D()]).irv


def test_t40_narrowing_makes_a_public_finding_nirv():
    assert not ev(F(), [D()], [disp("narrowing")]).irv


def test_deflection_counts_only_when_tested():
    assert ev(F(), [D()], [disp("deflection")]).irv
    assert not ev(F(), [D()], [disp("deflection", tested=True)]).irv


def test_t43_exposure_intent_without_data_class_fails_g5():
    e = ev(F(), [D(data=())])
    assert e.gates["G5"] and e.needs_basis.startswith("fail-safe data")


def test_t44_no_agency_scope_is_multi_agency():
    assert ev(F(), [D(agency_scope=None)]).agency_scope == "multi"


def test_t54_missing_classifier_is_published_as_not_recorded():
    e = ev(F(), [D(data=("cui",))])
    assert e.declared_by["classified_by"] == "not recorded" and e.needs["c"] == "high"


def test_t63_public_backed_is_irv():
    assert ev(F(), [D("public-backed")]).irv


def test_merge_takes_most_exposed_and_most_sensitive():
    a = Declaration("a", exposure_intent="internal", data=("public",), agency_scope="single")
    b = Declaration("b", exposure_intent="public-edge", data=("pii",), mission_critical=True, agency_scope="single")
    e = ev(F(cvss_vector=NET), [a, b])
    assert e.irv and e.needs == {"c": "high", "i": "high", "a": "high"} and e.agency_scope == "single"


# ------------------------------------------------------------------------------------------------------------------ LEV
def test_t8_floor_beats_a_low_prediction():
    e = ev(F(cvss_vector=NET, prediction=0.01), [D()])
    assert e.lev and e.lev_basis.startswith("floor")


def test_t9_nirv_no_score_medium_severity_is_lev():
    e = ev(F(scanner_severity="MEDIUM"), [D("internal")])
    assert e.lev and e.lev_basis.startswith("no prediction")


def test_prediction_below_theta_off_the_floor_is_nlev():
    e = ev(F(cvss_vector=LOCAL_AVAIL, prediction=0.05), [D()])
    assert not e.lev and e.column == "nlev"


def test_t28_override_lapses_at_review_by():
    f = F(cvss_vector=LOCAL_AVAIL)
    assert not ev(f, [D()], [disp("lev_override")]).lev
    lapsed = ev(f, [D()], [disp("lev_override", review_by=TODAY - timedelta(days=1))])
    assert lapsed.lev and any(q["kind"] == "disposition-lapsed" for q in lapsed.queue)


def test_override_never_clears_kev_or_the_floor():
    assert ev(F(kev=True), [D()], [disp("lev_override")]).lev
    assert ev(F(cvss_vector=NET), [D()], [disp("lev_override")]).lev


def test_unknown_access_on_a_reachable_finding_is_lev():
    assert ev(F(prediction=0.0), [D()]).lev_basis.startswith("floor: access unknown")


OVERLAY = {"ssvc_overlay": {"automatable_floor": True, "poc_check": True}}


def test_t55_overlay_automatable_irv_no_privileges_is_lev():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"  # user interaction: off Figure 7's floor
    e = ev(
        F(cvss_vector=v, ssvc_automatable="yes", ssvc_exploitation="none", prediction=0.01), [D()], profile=P(**OVERLAY)
    )
    assert e.lev


def test_t56_overlay_not_automatable_is_nlev():
    e = ev(
        F(cvss_vector=NET, ssvc_automatable="no", ssvc_exploitation="none", prediction=0.01),
        [D()],
        profile=P(**OVERLAY),
    )
    assert not e.lev


def test_t57_overlay_poc_automatable_is_lev_even_nirv():
    e = ev(F(cvss_vector=LOCAL_AVAIL, ssvc_automatable="yes", ssvc_exploitation="poc", prediction=0.01), [D("internal")],
           profile=P(**OVERLAY))  # fmt: skip
    assert e.lev and "proof of concept" in e.lev_basis


def test_t58_overlay_no_recorded_exploitation_skips_the_poc_check():
    e = ev(F(cvss_vector=LOCAL_AVAIL, ssvc_automatable="yes", prediction=0.01), [D("internal")], profile=P(**OVERLAY))
    assert not e.lev


def test_t68_half_an_overlay_fails_the_build():
    with pytest.raises(prof.ProfileError):
        P(ssvc_overlay={"automatable_floor": True, "poc_check": False})


# --------------------------------------------------------------------------------------------------------------- impact
def test_scenario_http2_flood_docs_site_n1_filing_api_n4():
    docs = Declaration("docs", exposure_intent="public-edge", data=("public",), agency_scope="multi")
    api = Declaration("api", exposure_intent="public-edge", data=("cui",), mission_critical=True, agency_scope="multi")
    assert ev(F(cvss_vector=AVAIL), [docs]).pain == "N1"
    assert ev(F(cvss_vector=AVAIL), [api]).pain == "N4"


def test_t48_availability_only_on_cui_not_mission_critical_is_medium_need():
    e = ev(F(cvss_vector=AVAIL), [D(data=("cui",))])
    assert e.pain_values["need_met"] == "medium"


def test_t61_availability_partial_high_need_multi_is_n4():
    e = ev(F(cvss_vector=AVAIL), [D(data=("internal",), mission_critical=True, agency_scope="multi")])
    assert e.technical_impact == "partial" and e.pain == "N4"


def test_t62_c_and_i_high_is_total():
    assert ev(F(cvss_vector=NET), [D()]).technical_impact == "total"


def test_no_vector_no_severity_is_total():
    e = ev(F(), [D()])
    assert e.technical_impact == "total" and e.pain_values["need_met"] == "medium"


def test_severity_fallback_goes_through_the_classification_so_the_fail_safe_holds():
    """The fallback sets technical impact, not the rating: an unresolved config finding stays at the fail-safe."""
    e = ev(F(scanner_severity="MEDIUM"), [])
    assert e.technical_impact == "partial" and e.pain == "N4"  # High need, partial: disruptive, multi-agency


def test_a_fallback_straight_to_the_scale_is_refused():
    """It would skip the classification and the fail-safe (REQ-PAI-6, -7)."""
    with pytest.raises(prof.ProfileError):
        P(severity_fallback={"mode": "scale", "map": {"medium": "N2"}})


def test_cvss_environmental_combining_is_selectable():
    env = {"impact_weights": {"none": 0, "low": 0.22, "high": 0.56},
           "requirement_weights": {"low": 0.5, "medium": 1.0, "high": 1.5},
           "isc_cap": 0.915, "word_thresholds": {"minimal_to_narrow": 0.25, "narrow_to_disruptive": 0.55,
                                                 "disruptive_to_debilitating": 0.80}}  # fmt: skip
    p = P(combining="cvss_environmental", cvss_environmental=env)
    e = ev(F(cvss_vector=AVAIL), [D(data=("public",), agency_scope="single")], profile=p)
    assert e.pain == "N2" and e.pain_values["detail"].startswith("S=")
    assert "combining" in prof.deviations(p)


# ------------------------------------------------------------------------------------------------- dispositions, clock
def test_t15_t23_fully_mitigated_is_n0_never_a_false_positive():
    e = ev(F(cvss_vector=NET), [D()], [disp("fully_mitigated", control_id="flag:feature-x")])
    assert e.pain == "N0" and not e.lev and e.group == "fully_mitigated" and e.due_at is None


def test_mitigation_without_a_control_is_not_in_force():
    e = ev(F(cvss_vector=NET), [D()], [disp("fully_mitigated")])
    assert e.pain != "N0" and e.dispositions[0]["state"].startswith("a mitigation names no control")


def test_t12_t13_vendor_dependency_lapses_when_fixable_or_unknown():
    old = F(cvss_vector=NET, first_detected_at=NOW - timedelta(days=30))
    for state in ("available", None):
        e = ev(Finding("f", first_detected_at=old.first_detected_at, cvss_vector=NET, fix_state=state), [D()],
               [disp("vendor_dependency")])  # fmt: skip
        assert not e.dispositions[0]["in_force"] and e.gates["G3"]
    held = ev(Finding("f", first_detected_at=old.first_detected_at, cvss_vector=NET, fix_state="none_planned"), [D()],
              [disp("vendor_dependency")])  # fmt: skip
    assert held.dispositions[0]["in_force"] and not held.gates["G3"]


def test_t16_past_review_by_is_absent_and_queued():
    e = ev(F(), [D()], [disp("risk_accepted", review_by=TODAY - timedelta(days=1))])
    assert not e.dispositions[0]["in_force"] and e.queue[0]["kind"] == "disposition-lapsed"


def test_t69_t70_vex_false_positive_needs_the_deployed_version_and_a_live_statement():
    f = F(deployed_version="2.2")
    assert ev(f, [D()], [disp("false_positive", vex_version="2.1")]).group == "open"
    assert ev(f, [D()], [disp("false_positive", vex_version="2.2", vex_withdrawn=True)]).group == "open"
    assert ev(f, [D()], [disp("false_positive", vex_version="2.2")]).group == "false_positive"


def test_t10_kev_past_catalog_due_date_fails_g1_even_when_protected():
    f = F(kev=True, kev_due_date=TODAY - timedelta(days=1))
    assert ev(f, [D()], [disp("mitigated", control_id="waf-1", pain_after="N2")]).gates["G1"]


def test_t11_past_timeframe_without_disposition_fails_g3():
    e = ev(F(cvss_vector=NET, first_detected_at=NOW - timedelta(days=5)), [D()])  # N4 lev_irv is 96 h
    assert e.pain == "N4" and e.state == "overdue" and e.gates["G3"]


def test_t14_past_max_overdue_is_reported_accepted():
    e = ev(F(first_detected_at=NOW - timedelta(days=200)), [D()])
    assert e.state.startswith("accepted")


def test_t34_verified_mitigation_starts_a_new_clock_first_evaluation_unchanged():
    start = NOW - timedelta(days=10)
    e = ev(F(cvss_vector=NET, first_evaluated_at=start), [D()],
           [disp("mitigated", control_id="waf-1", pain_after="N2", decided_on=TODAY - timedelta(days=2))])  # fmt: skip
    assert (
        e.pain == "N2"
        and e.clock_basis == "verified mitigation"
        and e.accept_by == start + timedelta(hours=MAX_OVERDUE)
    )


def test_t35_evaluation_change_without_mitigation_keeps_the_clock_start():
    start = NOW - timedelta(days=10)
    e = ev(F(cvss_vector=LOCAL_AVAIL, prediction=0.0, first_evaluated_at=start), [D()])
    assert e.clock_start == start and e.column == "nlev"


def test_kev_due_date_caps_the_deadline():
    f = F(cvss_vector=LOCAL_AVAIL, kev=True, kev_due_date=TODAY + timedelta(days=1), first_detected_at=NOW)
    e = ev(f, [D("internal")])
    assert e.due_at.date() == TODAY + timedelta(days=1)


def test_g2_top_rated_reachable_likely_exploitable_without_disposition():
    e = ev(F(cvss_vector=NET), [D(data=("pii",), mission_critical=True, agency_scope="multi")])
    assert e.pain == "N5" and e.gates["G2"]


# ----------------------------------------------------------------------------------------------------- governed profile
def test_t18_missing_or_invalid_profile_fails():
    with pytest.raises(prof.ProfileError):
        prof.validate(None, LEVELS)
    with pytest.raises(prof.ProfileError):
        prof.validate({**BASE, "theta": None}, LEVELS)  # theta has no default (REQ-LEV-2)
    with pytest.raises(prof.ProfileError):
        prof.validate({**BASE, "theta_rationale": ""}, LEVELS)


def test_t19_a_new_rules_level_fails_until_the_mapping_covers_it():
    with pytest.raises(prof.ProfileError, match="N6"):
        prof.validate(BASE, (*LEVELS, "N6"))


def test_the_global_defaults_have_no_deviations():
    assert prof.deviations(P()) == []
    assert prof.deviations(
        P(needs={**prof.GLOBAL_DEFAULTS["needs"], "public": {"c": "low", "i": "medium", "a": "low"}})
    ) == ["needs.public.i"]


def test_profile_digest_is_stable():
    assert prof.digest({"b": 1, "a": 2}) == prof.digest({"a": 2, "b": 1})


def test_prediction_feed_is_recorded_or_not_recorded():
    e = ev(F(prediction=0.2, prediction_date=date(2026, 11, 18)), [D()])
    assert e.prediction["feed_date"] == "2026-11-18" and e.prediction["model"] == "not recorded"
