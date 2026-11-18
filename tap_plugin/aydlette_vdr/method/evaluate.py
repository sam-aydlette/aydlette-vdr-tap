"""The method for one finding: reachability, likely exploitability, impact, clock, dispositions and gates. Pure and
Django-free, so the conformance tests (Appendix B) run on it directly and a provider can run it outside TAP.

Each decision returns its value and its basis, the reason a reader can check by hand. Every absent input reads as the worst
case: an unresolved finding is reachable and takes the fail-safe classification (REQ-IRV-6, REQ-PAI-6), a missing score is
likely exploitable (Figure 7), a missing vector and severity is total impact (REQ-PAI-7), a missing scope is multi-agency
(REQ-PAI-3) and an unknown fix state is fixable (REQ-VD-2).

Reconciliation (method/reconcile.py) runs first and hands its results in on the declaration: undeclared exposure (G4),
contradicting declarations (G5), missing or stale observations (G7) and data flags an undeclared flow may carry in. G6 and
the build-side part of G7 (a stale scanner database, a missing feed) are the pipeline's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any

from . import vector as vec
from .profile import FAIL_SAFE_CLASSIFICATION, NEED_LEVELS

EXPOSURE_ORDER: tuple[str, ...] = ("internal", "public-backed", "public-edge")
NOT_RECORDED = "not recorded"

# Disposition kinds. The first group changes the evaluation; the second records a decision and pauses nothing (REQ-DLN-1).
FALSE_POSITIVE = "false_positive"
FULLY_MITIGATED = "fully_mitigated"
MITIGATED = "mitigated"
NARROWING = "narrowing"
DEFLECTION = "deflection"
LEV_OVERRIDE = "lev_override"
VENDOR_DEPENDENCY = "vendor_dependency"
RISK_ACCEPTED = "risk_accepted"
OPERATIONAL_REQUIREMENT = "operational_requirement"
KINDS: tuple[str, ...] = (
    FALSE_POSITIVE, FULLY_MITIGATED, MITIGATED, NARROWING, DEFLECTION, LEV_OVERRIDE,
    VENDOR_DEPENDENCY, RISK_ACCEPTED, OPERATIONAL_REQUIREMENT,
)  # fmt: skip


# --------------------------------------------------------------------------------------------------------------- inputs
@dataclass(frozen=True)
class Declaration:
    """A component's declarations (REQ-IRV-1, REQ-PAI-3). Empty `data` or a None intent is a missing declaration."""

    component_id: str
    exposure_intent: str | None = None
    exposure_rationale: str | None = None
    data: tuple[str, ...] = ()
    mission_critical: bool = False
    agency_scope: str | None = None  # single | multi; None is multi (REQ-PAI-3, T44)
    classified_by: str | None = None
    criticality_judged_by: str | None = None
    undeclared_exposure: bool = False  # set by reconciliation: an observer saw a path the declaration denies (G4)
    conflicts: tuple[str, ...] = ()  # set by reconciliation: declarations that contradict each other (G5)
    observer_gaps: tuple[str, ...] = ()  # set by reconciliation: no fresh observation (G7)
    inherited_data: tuple[str, ...] = ()  # set by reconciliation: flags an undeclared flow may carry in (REQ-PAI-5)


@dataclass(frozen=True)
class Disposition:
    disposition_id: str
    kind: str
    reason: str | None = None
    decided_by: str | None = None
    decided_on: date | None = None
    review_by: date | None = None
    control_id: str | None = None  # REQ-MIT-1: a mitigation names its control by inventory identifier
    tested: bool = False  # a deflection is verified by an outside-in triggering-payload test (REQ-IRV-5)
    pain_after: str | None = None  # a partial mitigation's reduced rating (FRD-PMV)
    vex_version: str | None = None  # REQ-DSP-5: the product version a VEX statement covers
    vex_withdrawn: bool = False


@dataclass(frozen=True)
class Finding:
    finding_id: str
    status: str = "open"
    first_detected_at: datetime | None = None
    first_evaluated_at: datetime | None = None
    cvss_vector: str | None = None
    vector_source: str | None = None  # "record" (the advisory's own) or "check-vector" (a governed per-check vector)
    scanner_severity: str | None = None
    access: tuple[bool | None, bool | None, bool | None] = (
        None,
        None,
        None,
    )  # scanner: network, privileges, user action
    kev: bool | None = None
    kev_due_date: date | None = None
    exploitation_observed: bool = False
    prediction: float | None = None
    prediction_date: date | None = None
    prediction_model: str | None = None
    ssvc_exploitation: str | None = None  # none | poc | active
    ssvc_automatable: str | None = None  # yes | no
    ssvc_technical_impact: str | None = None  # partial | total
    ssvc_source: str | None = None
    fix_state: str | None = None  # available | none_planned | pending; None is unknown, which counts as available
    deployed_version: str | None = None
    non_machine: bool = False  # a finding on a process that touches no machine-based resource (REQ-SRC-3)


# -------------------------------------------------------------------------------------------------------- declarations
def merge_declarations(decls: list[Declaration]) -> Declaration | None:
    """One declaration for a finding several components carry: the most exposed and the most sensitive (REQ-SRC-3).

    A missing intent or data class on any of them stays missing, so a gap is never hidden behind a sibling's declaration.
    """
    if not decls:
        return None
    if len(decls) == 1:
        return decls[0]
    intents = [d.exposure_intent for d in decls]
    intent = None if None in intents else max(intents, key=lambda i: EXPOSURE_ORDER.index(i))
    data: tuple[str, ...] = ()
    if all(d.data for d in decls):
        flags = {f for d in decls for f in d.data}
        data = tuple(sorted(flags - {"public"})) if flags - {"public"} else ("public",)
        if set(data) - {"pii", "cui"} and set(data) & {"pii", "cui"}:
            data = tuple(sorted(set(data) - {"internal"}))  # PII or CUI need at least what internal does
    scopes = [d.agency_scope for d in decls]
    return Declaration(
        component_id="+".join(sorted(d.component_id for d in decls)),
        exposure_intent=intent,
        exposure_rationale="; ".join(d.exposure_rationale or NOT_RECORDED for d in decls),
        data=data,
        mission_critical=any(d.mission_critical for d in decls),
        agency_scope="single" if all(s == "single" for s in scopes) else "multi",
        classified_by="; ".join(sorted({d.classified_by or NOT_RECORDED for d in decls})),
        criticality_judged_by="; ".join(sorted({d.criticality_judged_by or NOT_RECORDED for d in decls})),
        undeclared_exposure=any(d.undeclared_exposure for d in decls),
        conflicts=tuple(c for d in decls for c in d.conflicts),
        observer_gaps=tuple(g for d in decls for g in d.observer_gaps),
        inherited_data=tuple(sorted({f for d in decls for f in d.inherited_data})),
    )


def declaration_gaps(decl: Declaration | None) -> list[str]:
    """What G5 fails on for this declaration: a missing exposure intent or data classification (T6, T43)."""
    if decl is None:
        return []
    gaps = []
    if decl.exposure_intent not in EXPOSURE_ORDER:
        gaps.append("no exposure_intent")
    if not decl.data:
        gaps.append("no data classification")
    elif "public" in decl.data and len(decl.data) > 1:
        gaps.append("public data excludes every other class")
    gaps.extend(decl.conflicts)
    return gaps


def needs(decl: Declaration | None, profile: dict[str, Any]) -> tuple[dict[str, str], str, str]:
    """The (c, i, a) needs, the agency scope and the basis: the declaration's, or the fail-safe's for what is missing."""
    if decl is None:
        data, mc, scope, basis = FAIL_SAFE_CLASSIFICATION["data"], True, "multi", "fail-safe (unresolved)"
    else:
        data = tuple(decl.data or FAIL_SAFE_CLASSIFICATION["data"])
        mc = decl.mission_critical
        scope = decl.agency_scope or "multi"
        basis = "declared" if decl.data else "fail-safe data (no data classification)"
        if decl.inherited_data:
            data = tuple(sorted(set(data) - {"public"} | set(decl.inherited_data)))
            basis += (
                f"; classified as carrying {', '.join(decl.inherited_data)} until an undeclared flow is decided (T47)"
            )
    rank = {lv: n for n, lv in enumerate(NEED_LEVELS)}
    out = {"c": "low", "i": "low", "a": "low"}
    for flag in data:
        for prop, level in profile["needs"][flag].items():
            out[prop] = max(out[prop], level, key=rank.__getitem__)
    if mc:
        for prop, level in profile["needs"]["mission_critical"].items():
            out[prop] = max(out[prop], level, key=rank.__getitem__)
    return out, scope, basis


# -------------------------------------------------------------------------------------------------------- dispositions
def disposition_state(d: Disposition, finding: Finding, today: date) -> tuple[bool, str]:
    """Whether a disposition is in force, and why not when it is not (REQ-DSP-1, -2, -5, REQ-MIT-1, REQ-VD-2)."""
    if d.kind not in KINDS:
        return False, f"unknown kind {d.kind!r}"
    if d.review_by is None:
        return False, "no review_by"
    if d.review_by < today:
        return False, f"past review_by {d.review_by.isoformat()} (T16)"
    if d.kind in (FULLY_MITIGATED, MITIGATED) and not d.control_id:
        return False, "a mitigation names no control (REQ-MIT-1)"
    if d.kind == MITIGATED and not d.pain_after:
        return False, "a partial mitigation records no reduced rating (FRD-PMV)"
    if d.kind == DEFLECTION and not d.tested:
        return False, "deflection not verified by an outside-in triggering-payload test (REQ-IRV-5)"
    if d.kind == VENDOR_DEPENDENCY and finding.fix_state not in ("none_planned", "pending"):
        return False, "a fix is available or the fix state is unknown (REQ-VD-2, T12, T13)"
    if d.kind == FALSE_POSITIVE and d.vex_version is not None:
        if d.vex_withdrawn:
            return False, "the VEX statement was withdrawn (T70)"
        if d.vex_version != finding.deployed_version:
            return False, f"the VEX statement covers {d.vex_version}, not the deployed version (T69)"
    return True, "in force"


# ------------------------------------------------------------------------------------------------------------ IRV, LEV
def irv(
    finding: Finding, decl: Declaration | None, resolved: bool, in_force: dict[str, Disposition]
) -> tuple[bool, str]:
    """Figure 5's irv(finding), first match deciding."""
    if finding.non_machine:
        return False, "non-machine resource (REQ-SRC-3)"
    if not resolved or decl is None:
        return True, "unresolved (fail-safe)"
    if decl.undeclared_exposure:
        return True, "undeclared exposure (G4)"
    if decl.exposure_intent not in EXPOSURE_ORDER:
        return True, "no exposure_intent (G5)"
    if decl.exposure_intent == "internal":
        return False, "declared internal"
    if DEFLECTION in in_force:
        return False, f"deflection {in_force[DEFLECTION].disposition_id}"
    if NARROWING in in_force:
        return False, f"narrowing {in_force[NARROWING].disposition_id}"
    return True, f"declared {decl.exposure_intent}"


def _access(finding: Finding, v: vec.Vector | None) -> tuple[bool | None, bool | None, bool | None]:
    if v is not None:
        return v.network, v.privileges, v.user_interaction
    return finding.access


def automatable(finding: Finding, v: vec.Vector | None) -> tuple[bool, str]:
    """REQ-LEV-7: the recorded value, else the vector, else automatable (VER-EVA-AIA)."""
    if finding.ssvc_automatable in ("yes", "no"):
        return finding.ssvc_automatable == "yes", "recorded"
    if v is not None:
        return v.network and not v.user_interaction, "vector"
    return True, "default (VER-EVA-AIA)"


def lev(
    finding: Finding,
    irv_value: bool,
    v: vec.Vector | None,
    profile: dict[str, Any],
    in_force: dict[str, Disposition],
) -> tuple[bool, str]:
    """Figure 7, or the SSVC overlay's form of it, first match deciding (REQ-LEV-1).

    A governed LEV override (REQ-LEV-4) replaces only the last two checks: it never clears a known-exploited or observed
    exploitation, and it never clears the FRD-LEV floor, which is the rules' own definition (REQ-LEV-3).
    """
    if FULLY_MITIGATED in in_force:
        return False, "fully mitigated (FRD-LEV)"
    if finding.kev:
        return True, "known exploited (KEV)"
    if finding.exploitation_observed or finding.ssvc_exploitation == "active":
        return True, "exploitation observed"
    network, privileges, user = _access(finding, v)
    if profile["ssvc_overlay"]["automatable_floor"]:
        auto, _ = automatable(finding, v)
        if irv_value and auto and not privileges:
            return True, "floor: reachable, automatable, no privileges (overlay)"
        if finding.ssvc_exploitation == "poc" and auto:
            return True, "public proof of concept on an automatable flaw (overlay, REQ-LEV-6)"
    elif irv_value:
        if network is None or privileges is None or user is None:
            return True, "floor: access unknown, read as the worst case"
        if network and not privileges and not user:
            return True, "floor: reachable, network, no privileges, no user interaction (FRD-LEV)"
    if LEV_OVERRIDE in in_force:
        return False, f"override {in_force[LEV_OVERRIDE].disposition_id} (REQ-LEV-4)"
    if finding.prediction is not None:
        theta = profile["theta"]
        if finding.prediction >= theta:
            return True, f"prediction {finding.prediction:g} >= theta {theta:g}"
        return False, f"prediction {finding.prediction:g} < theta {theta:g}"
    return True, "no prediction score (fail-safe)"


# --------------------------------------------------------------------------------------------------------------- impact
def technical_impact(finding: Finding, v: vec.Vector | None, profile: dict[str, Any]) -> tuple[str, str]:
    """REQ-PAI-7. Under the overlay a recorded Technical Impact takes the vector's place."""
    if profile["ssvc_overlay"]["automatable_floor"] and finding.ssvc_technical_impact in ("partial", "total"):
        return finding.ssvc_technical_impact, "ssvc"
    if v is not None:
        return ("total" if v.total else "partial"), "vector"
    sev = (finding.scanner_severity or "").strip().lower()
    fb = profile["severity_fallback"]
    if sev and fb["mode"] == "technical_impact" and sev in fb["map"]:
        return fb["map"][sev], f"severity fallback ({sev})"
    return "total", "no vector and no mapped severity (REQ-PAI-7)"


def _env_effect(
    v: vec.Vector | None, need: dict[str, str], raise_to_total: bool, env: dict[str, Any]
) -> tuple[str, str]:
    """CVSS-Environmental: U = 1 - prod(1 - impact_weight * requirement_weight), S = min(U, cap) / cap.

    The vector's C, I and A are scored as written, as CVSS does; with no vector all three are High. `raise_to_total` is set
    only when the SSVC overlay supplies a Technical Impact of total that the vector does not show: then every affected
    property scores High, because the overlay knows more than the vector."""
    iw, rw = env["impact_weights"], env["requirement_weights"]
    impact = v.impact if v is not None else ("high", "high", "high")
    survive = Decimal(1)
    for prop, level in zip(("c", "i", "a"), impact, strict=True):
        if raise_to_total and level != "none":
            level = "high"
        survive *= 1 - Decimal(str(iw[level])) * Decimal(str(rw[need[prop]]))
    cap = Decimal(str(env["isc_cap"]))
    s = min(1 - survive, cap) / cap
    t = {k: Decimal(str(x)) for k, x in env["word_thresholds"].items()}
    if s < t["minimal_to_narrow"]:
        effect = "minimal"
    elif s < t["narrow_to_disruptive"]:
        effect = "narrow"
    elif s < t["disruptive_to_debilitating"]:
        effect = "disruptive"
    else:
        effect = "debilitating"
    return effect, f"S={s:.4f}"


def pain(
    finding: Finding,
    v: vec.Vector | None,
    need: dict[str, str],
    scope: str,
    ti: str,
    profile: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """The rating in three layers (REQ-PAI-1): inputs, a governed combining function, a governed mapping onto the scale.

    Returns the level and the values that produced it, so the rating can be checked by hand.
    """
    affected = v.affected if v is not None else ("c", "i", "a")
    rank = {lv: n for n, lv in enumerate(NEED_LEVELS)}
    need_met = max((need[p] for p in affected), key=rank.__getitem__) if affected else "low"
    if profile["combining"] == "cvss_environmental":
        overlay_total = (
            bool(profile["ssvc_overlay"]["automatable_floor"])
            and finding.ssvc_technical_impact == "total"
            and not (v is not None and v.total)
        )
        effect, detail = _env_effect(v, need, overlay_total, profile["cvss_environmental"])
    else:
        effect, detail = profile["effect_table"][need_met][ti], "decision table"
    level = profile["scale"][effect][scope]
    return level, {
        "function": profile["combining"],
        "affected": list(affected),
        "need_met": need_met,
        "technical_impact": ti,
        "effect": effect,
        "scope": scope,
        "detail": detail,
    }


# --------------------------------------------------------------------------------------------------------------- result
@dataclass
class Evaluation:
    finding_id: str
    resolved: bool
    component_id: str | None
    irv: bool
    irv_basis: str
    lev: bool
    lev_basis: str
    pain: str
    pain_values: dict[str, Any]
    technical_impact: str
    technical_impact_basis: str
    needs: dict[str, str]
    needs_basis: str
    agency_scope: str
    column: str
    dispositions: list[dict[str, Any]] = field(default_factory=list)
    group: str = "open"  # open | false_positive | fully_mitigated
    clock_start: datetime | None = None
    clock_basis: str = ""
    due_at: datetime | None = None
    accept_by: datetime | None = None
    state: str = "no deadline"
    gates: dict[str, bool] = field(default_factory=dict)
    queue: list[dict[str, str]] = field(default_factory=list)
    declared_by: dict[str, str] = field(default_factory=dict)
    prediction: dict[str, Any] = field(default_factory=dict)

    def as_row(self) -> dict[str, Any]:
        row = dict(self.__dict__)
        for key in ("clock_start", "due_at", "accept_by"):
            row[key] = row[key].isoformat() if row[key] else None
        return row


def column(lev_value: bool, irv_value: bool) -> str:
    """The column of the timeframe table (reachability does not matter when not likely exploitable)."""
    if not lev_value:
        return "nlev"
    return "lev_irv" if irv_value else "lev_nirv"


def evaluate(
    finding: Finding,
    decls: list[Declaration],
    dispositions: list[Disposition],
    profile: dict[str, Any],
    *,
    now: datetime,
    timeframe_hours: Any,
    max_overdue_hours: int | None,
    top_level: str,
) -> Evaluation:
    """Evaluate one finding. `timeframe_hours(pain, column)` returns hours or None (no timeframe, as for N1);
    `profile` is a validated profile. `top_level` is the scale's highest level, for G2."""
    today = now.date()
    decl = merge_declarations(decls)
    resolved = decl is not None
    queue: list[dict[str, str]] = []
    opened = now.isoformat()

    in_force: dict[str, Disposition] = {}
    records = []
    for d in dispositions:
        ok, why = disposition_state(d, finding, today)
        records.append({
            "id": d.disposition_id, "kind": d.kind, "in_force": ok, "state": why,
            "reason": d.reason or NOT_RECORDED, "decided_by": d.decided_by or NOT_RECORDED,
            "decided_on": d.decided_on.isoformat() if d.decided_on else NOT_RECORDED,
            "review_by": d.review_by.isoformat() if d.review_by else NOT_RECORDED,
        })  # fmt: skip
        if ok:
            in_force.setdefault(d.kind, d)
        else:
            queue.append(
                {
                    "kind": "disposition-lapsed",
                    "subject": d.disposition_id,
                    "opened_at": opened,
                    "why": why,
                    "options": "renew with a new review_by, or let the finding return to evaluation",
                }
            )

    v = vec.parse(finding.cvss_vector)
    irv_value, irv_basis = irv(finding, decl, resolved, in_force)
    lev_value, lev_basis = lev(finding, irv_value, v, profile, in_force)
    need, scope, needs_basis = needs(decl, profile)
    ti, ti_basis = technical_impact(finding, v, profile)
    if FULLY_MITIGATED in in_force:
        level, values = "N0", {"function": "fully mitigated: the scale's lowest level (REQ-PAI-1, T15)"}
    else:
        level, values = pain(finding, v, need, scope, ti, profile)
        if MITIGATED in in_force:
            after = in_force[MITIGATED].pain_after
            if after and after < level:
                values = {**values, "before_mitigation": level, "mitigation": in_force[MITIGATED].disposition_id}
                level = after

    col = column(lev_value, irv_value)
    group = "open"
    if FALSE_POSITIVE in in_force:
        group = FALSE_POSITIVE
    elif FULLY_MITIGATED in in_force:
        group = FULLY_MITIGATED

    # The clock (REQ-DLN-1, -3): the start carries forward; a verified mitigation that changed the rating starts a new one.
    first = finding.first_evaluated_at or finding.first_detected_at
    start, basis = first, "first evaluation" if finding.first_evaluated_at else "detection (evaluated in the same pass)"
    d_on = in_force[MITIGATED].decided_on if MITIGATED in in_force else None
    if d_on is not None and "mitigation" in values:
        start, basis = datetime.combine(d_on, datetime.min.time(), tzinfo=now.tzinfo), "verified mitigation"
    due = None
    if group == "open" and start is not None and level != "N0":
        hours = timeframe_hours(level, col)
        if hours is not None:
            due = start + timedelta(hours=hours)
        if finding.kev and finding.kev_due_date:
            kev_due = datetime.combine(finding.kev_due_date, datetime.max.time(), tzinfo=now.tzinfo)
            due = min(due, kev_due) if due else kev_due
    accept_by = first + timedelta(hours=max_overdue_hours) if first and max_overdue_hours is not None else None

    state = "no deadline"
    if group != "open":
        state = group.replace("_", " ")
    elif accept_by and now >= accept_by:
        state = "accepted (past the maximum overdue period, REQ-DLN-3)"
    elif due:
        margin = timedelta(hours=profile.get("likely_overdue_margin_hours", 0))
        state = "overdue" if now >= due else ("likely overdue" if now >= due - margin else "on time")

    decided = bool(in_force)
    gates = {
        "G1": bool(finding.kev and finding.kev_due_date and finding.kev_due_date < today and finding.status == "open"),
        "G2": bool(group == "open" and level == top_level and irv_value and lev_value and not decided),
        "G3": bool(group == "open" and due is not None and now >= due and not decided),
        "G4": bool(decl is not None and decl.undeclared_exposure),
        "G5": bool(declaration_gaps(decl)),
        "G7": bool(decl is not None and decl.observer_gaps),
    }
    if not resolved:
        queue.append(
            {
                "kind": "unresolved",
                "subject": finding.finding_id,
                "opened_at": opened,
                "why": "the finding matches no declared component; it is IRV at the fail-safe classification",
                "options": "declare the component it belongs to, or record why it has none",
            }
        )
    for gap in declaration_gaps(decl):
        queue.append(
            {
                "kind": "declaration",
                "subject": decl.component_id if decl else "",
                "opened_at": opened,
                "why": gap,
                "options": "declare it (G5 fails until then)",
            }
        )

    return Evaluation(
        finding_id=finding.finding_id, resolved=resolved, component_id=decl.component_id if decl else None,
        irv=irv_value, irv_basis=irv_basis, lev=lev_value, lev_basis=lev_basis, pain=level, pain_values=values,
        technical_impact=ti, technical_impact_basis=ti_basis, needs=need, needs_basis=needs_basis, agency_scope=scope,
        column=col, dispositions=records, group=group, clock_start=start, clock_basis=basis, due_at=due,
        accept_by=accept_by, state=state, gates=gates, queue=queue,
        declared_by={
            "classified_by": (decl.classified_by if decl else None) or NOT_RECORDED,
            "criticality_judged_by": (decl.criticality_judged_by if decl else None) or NOT_RECORDED,
            "exposure_rationale": (decl.exposure_rationale if decl else None) or NOT_RECORDED,
        },
        prediction={
            "score": finding.prediction,
            "feed_date": finding.prediction_date.isoformat() if finding.prediction_date else NOT_RECORDED,
            "model": finding.prediction_model or NOT_RECORDED,
        },
    )  # fmt: skip
