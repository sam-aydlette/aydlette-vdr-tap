"""stackArmor's five worked examples, run through this method's CVSS-Environmental combining option.

Venne, "A Deterministic, CVSS-Environmental Method for FedRAMP VDR/VER Vulnerability Prioritization" (stackArmor,
2026; github.com/stackArmor/rfc-fedramp-vdr). The expected N-levels are the memo's, as stackarmor-vdr-tap's tests encode
them (tests/test_score.py, built against stackArmor commit e3368d72). The memo's weights and boundaries become a profile:

* impact weights none 0, low 0.22, high 0.56; requirement weights low 0.5, medium 1.0, high 1.5;
* the cap is the memo's D_H, the score of all-High impact at all-High requirements;
* the word boundaries are the memo's: U at 0.28 and 0.56 (here S = U / D_H against 0.28 / D_H and 0.56 / D_H), and
  S at 0.933;
* the memo's affected-agency flag m is this method's agency scope (1 = multi);
* the memo's N-level table is this method's default scale: minimal N1/N1, narrow N2/N2, disruptive N3/N4,
  debilitating N4/N5.

The examples pass. So this method's framework can run stackArmor's rating, as a published deviation from its own default.
The tests at the bottom show where the two methods still differ, and why.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from tap_plugin.aydlette_vdr.method import vector as vec
from tap_plugin.aydlette_vdr.method.evaluate import pain, technical_impact
from tap_plugin.aydlette_vdr.tests.test_conformance import D, F, P, ev

IW = {"none": 0, "low": 0.22, "high": 0.56}
RW = {"low": 0.5, "medium": 1.0, "high": 1.5}
D_H = 1 - (1 - Decimal("0.56") * Decimal("1.5")) ** 3  # 0.995904
STACKARMOR = {
    "impact_weights": IW,
    "requirement_weights": RW,
    "isc_cap": str(D_H),
    "word_thresholds": {
        "minimal_to_narrow": str(Decimal("0.28") / D_H),
        "narrow_to_disruptive": str(Decimal("0.56") / D_H),
        "disruptive_to_debilitating": "0.933",
    },
}
LEVEL = {"L": "low", "M": "medium", "H": "high"}
CVSS = {"N": "N", "L": "L", "H": "H"}


def profile():
    return P(combining="cvss_environmental", cvss_environmental=STACKARMOR)


def vector(c_i_a: str) -> str:
    c, i, a = c_i_a
    return f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{CVSS[c]}/I:{CVSS[i]}/A:{CVSS[a]}"


def rate(c_i_a: str, cr_ir_ar: str, m: int) -> str:
    finding = F(cvss_vector=vector(c_i_a))
    v = vec.parse(finding.cvss_vector)
    need = {p: LEVEL[x] for p, x in zip(("c", "i", "a"), cr_ir_ar, strict=True)}
    ti, _ = technical_impact(finding, v, profile())
    level, _ = pain(finding, v, need, "multi" if m else "single", ti, profile())
    return level


@pytest.mark.parametrize(
    ("c_i_a", "cr_ir_ar", "m", "expected"),
    [
        ("HHH", "HHH", 1, "N5"),  # example 1
        ("HHH", "MMM", 1, "N4"),  # example 2
        ("HHH", "LLL", 0, "N3"),  # example 3
        ("NNH", "MMH", 0, "N3"),  # example 4
        ("HNN", "LMM", 0, "N2"),  # example 5: U is exactly 0.28, on the first boundary
    ],
)
def test_the_memos_five_worked_examples(c_i_a, cr_ir_ar, m, expected):
    assert rate(c_i_a, cr_ir_ar, m) == expected


@pytest.mark.parametrize(
    ("data", "mission_critical", "scope", "c_i_a", "expected"),
    [
        (("pii",), True, "multi", "HHH", "N5"),  # example 1: PII and Mission Critical is HHH
        (("internal",), False, "multi", "HHH", "N4"),  # example 2: internal is MMM
        (("public",), False, "single", "HHH", "N3"),  # example 3: public is LLL
    ],
)
def test_examples_1_to_3_end_to_end_from_a_declaration(data, mission_critical, scope, c_i_a, expected):
    """The requirements come from the declared classification, as they would on a grid."""
    decl = D("internal", data=data, mission_critical=mission_critical, agency_scope=scope)
    assert ev(F(cvss_vector=vector(c_i_a)), [decl], profile=profile()).pain == expected


def test_examples_4_and_5_need_requirements_no_classification_produces():
    """MMH and LMM are not in the default needs map (Mission Critical raises both I and A), so on a grid examples 4 and
    5 need a profile whose needs map produces them: a published deviation, as REQ-PAI-4 allows."""
    from tap_plugin.aydlette_vdr.method import profile as prof

    produced = {tuple(n.values()) for n in prof.GLOBAL_DEFAULTS["needs"].values()}
    assert ("medium", "medium", "high") not in produced and ("low", "medium", "medium") not in produced


# ------------------------------------------------------------------------------------------- where the two still differ
def test_difference_unresolved_findings_and_missing_vectors():
    """stackArmor: a missing vector is High on C, I and A, rated at the asset profile's requirements.
    This method: the same High impact, but an unresolved finding has the fail-safe classification (PII, CUI, Mission
    Critical, multi-agency), so it is rated at HHH needs and multi-agency scope, never at an archetype default."""
    unresolved = ev(F(), [], profile=profile())
    assert unresolved.pain == "N5"


def test_difference_ssvc_total_raises_the_score():
    """With the SSVC overlay on, a CISA Technical Impact of total that the vector does not show scores every affected
    property High. stackArmor reads only the vector. At HHH needs, single agency, C:H/I:L/A:L scores S = 0.932 as written
    (Disruptive, N3, stackArmor's answer) and 1.0 raised (Debilitating, N4)."""
    over = P(combining="cvss_environmental", cvss_environmental=STACKARMOR,
             ssvc_overlay={"automatable_floor": True, "poc_check": True})  # fmt: skip
    decl = D(data=("pii",), mission_critical=True, agency_scope="single")
    plain = ev(F(cvss_vector=vector("HLL")), [decl], profile=profile()).pain
    f = F(cvss_vector=vector("HLL"), ssvc_technical_impact="total", ssvc_exploitation="none", ssvc_automatable="no")
    raised = ev(f, [decl], profile=over).pain
    assert (plain, raised) == ("N3", "N4")
    assert rate("HLL", "HHH", 0) == "N3"  # stackArmor's own arithmetic on the same inputs
