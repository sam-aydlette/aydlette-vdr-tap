"""The method's Searches, as `module` Search runners.

`aydlette-pain` evaluates every open compliance finding, with or without a vulnerability record (REQ-SRC-1: one finding
stream, so configuration and DAST findings are evaluated too), and returns one row per finding and vulnerability with every
decision's value and basis. `aydlette-summary` returns the counts, the gates, the decision queue and the profile block every
output carries (REQ-GOV-1, REQ-PAI-4, REQ-RUL-2). Both read through `read_scope` with the caller's `db_alias` and write
nothing.

A finding resolves to a component by the grid's own edges, the shared identifier (REQ-IRV-6): the declarations on the nodes
that carry it (`CARRIES_COMPLIANCE_FINDING`), else, for a package finding, the declarations on its owner, container and
programs as `fedramp_20x_vdr`'s reach names them. Several declarations merge to the most exposed and most sensitive. No
declaration is unresolved: IRV, the fail-safe classification, queued.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from tap_plugin.compliance_core.models.compliance_finding import ComplianceFinding
from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.fedramp_20x_vdr.deadlines import acceptance_hours, deadline_hours
from tap_plugin.fedramp_20x_vdr.levels import LEVELS
from tap_plugin.fedramp_20x_vdr.models.vdr_timeframe import VdrTimeframe
from tap_plugin.fedramp_20x_vdr.searches.reach import reach_rows

from tap_grid.gryphon import read_scope
from tap_grid.models import Search

from ..method import evaluate as m
from ..method import profile as prof
from ..method import reconcile as rc
from ..models import CheckVector, ComponentDeclaration, DeclaredFlow, Disposition, FindingFacts, Observation, Profile
from .schema import INPUT_SCHEMA, RECONCILE_INPUT_SCHEMA

CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
CARRIES = "CARRIES_COMPLIANCE_FINDING__compliance_core"
DECLARES = "DECLARES_COMPONENT__aydlette_vdr"
DESCRIBES = "DESCRIBES_FINDING__aydlette_vdr"
DISPOSES = "DISPOSES_FINDING__aydlette_vdr"
OBSERVES = "OBSERVES_COMPONENT__aydlette_vdr"
OBSERVES_SENDER = "OBSERVES_SENDER__aydlette_vdr"
FLOW_SOURCE = "FLOW_SOURCE__aydlette_vdr"
FLOW_TARGET = "FLOW_TARGET__aydlette_vdr"


def _as_of(raw: str | None) -> datetime:
    """The evaluation time: the `now` input (ISO 8601; a naive time is UTC), or the current time."""
    if not raw:
        return datetime.now(UTC)
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError(f"now must be an ISO 8601 date-time, such as 2026-11-18T12:00:00Z; got {raw!r}") from None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _inputs(inputs: dict[str, Any], schema: dict[str, Any] = INPUT_SCHEMA) -> dict[str, Any]:
    props = schema["properties"]
    unknown = sorted(set(inputs) - set(props))
    if unknown:
        raise ValueError(f"unknown input {', '.join(unknown)}")
    p = {k: s["default"] for k, s in props.items() if "default" in s}
    p.update({k: v for k, v in inputs.items() if v is not None})
    if "fedramp_class" in schema["required"] and p.get("fedramp_class") not in ("a", "b", "c", "d"):
        raise ValueError("fedramp_class is required: one of a, b, c, d")
    return p


def load_profile(profile_id: str, *, db_alias: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The validated profile and its published block. A missing or invalid profile fails (REQ-GOV-1, T18)."""
    row = (
        read_scope.node_relation(read_scope.DEFAULT_SCOPE, Profile, db_alias=db_alias)
        .filter(profile_id=profile_id)
        .first()
    )
    if row is None:
        raise prof.ProfileError(f"no governed profile {profile_id!r} (REQ-GOV-1, T18)")
    document = {**(row.document or {}), "profile_id": row.profile_id, "version": row.version}
    merged = prof.validate(document, LEVELS)
    block = {
        "profile_id": row.profile_id,
        "version": row.version,
        "sha256": prof.digest(document),
        "combining": merged["combining"],
        "theta": merged["theta"],
        "theta_rationale": merged["theta_rationale"],
        "ssvc_overlay": bool(merged["ssvc_overlay"]["automatable_floor"]),
        "severity_fallback": merged["severity_fallback"]["mode"],
        "deviations": prof.deviations(document),
    }
    return merged, block


def rules_block(*, db_alias: str) -> dict[str, Any]:
    """Where the timeframes came from (REQ-RUL-2): fedramp_20x_vdr's seeded rows and the date they were read."""
    rows = read_scope.node_relation(read_scope.DEFAULT_SCOPE, VdrTimeframe, db_alias=db_alias)
    read_at = sorted({str(r) for r in rows.values_list("canon_read_at", flat=True) if r})
    urls = sorted({u for u in rows.values_list("canon_url", flat=True) if u})
    return {"source": "fedramp_20x_vdr timeframe rows", "rows": rows.count(), "read_at": read_at, "urls": urls}


def _pairs(edge_type: str, *, db_alias: str, **filters: Any) -> list[tuple[str, str]]:
    rel = read_scope.edge_relation(read_scope.DEFAULT_SCOPE, db_alias=db_alias).filter(edge_type=edge_type, **filters)
    return [(str(a), str(b)) for a, b in rel.values_list("from_entity_id", "to_entity_id")]


def _nodes(model: Any, ids: list[str], *, db_alias: str, **filters: Any) -> dict[str, Any]:
    rel = read_scope.node_relation(read_scope.DEFAULT_SCOPE, model, db_alias=db_alias)
    return {str(r.entity_id): r for r in rel.filter(entity_id__in=ids, **filters)}


def _declaration(row: ComponentDeclaration, target: str) -> m.Declaration:
    return m.Declaration(
        component_id=target,
        exposure_intent=row.exposure_intent,
        exposure_rationale=row.exposure_rationale,
        data=tuple(row.data or ()),
        mission_critical=bool(row.mission_critical),
        agency_scope=row.agency_scope,
        classified_by=row.classified_by,
        criticality_judged_by=row.criticality_judged_by,
    )


def _disposition(row: Disposition) -> m.Disposition:
    return m.Disposition(
        disposition_id=f"{row.source}:{row.disposition_key}", kind=row.kind, reason=row.reason,
        decided_by=row.decided_by, decided_on=row.decided_on, review_by=row.review_by, control_id=row.control_id,
        tested=bool(row.tested), pain_after=row.pain_after, vex_version=row.vex_version,
        vex_withdrawn=bool(row.vex_withdrawn),
    )  # fmt: skip


def _check_vectors(today: Any, *, db_alias: str) -> dict[str, CheckVector]:
    rel = read_scope.node_relation(read_scope.DEFAULT_SCOPE, CheckVector, db_alias=db_alias)
    return {
        r.check_id: r for r in rel if r.decided_by and r.decided_on and (r.review_by is None or r.review_by >= today)
    }


def reconcile_components(
    p: dict[str, Any], profile: dict[str, Any], now: datetime, *, db_alias: str
) -> tuple[dict[str, rc.ComponentState], dict[str, m.Declaration]]:
    """Every declared component's reconciliation state, and its (merged) declaration, keyed by the component's node id."""
    scope = read_scope.DEFAULT_SCOPE
    decl_rel = read_scope.node_relation(scope, ComponentDeclaration, db_alias=db_alias)
    if p.get("declaration_source"):
        decl_rel = decl_rel.filter(source=p["declaration_source"])
    decl_rows = {str(r.entity_id): r for r in decl_rel}
    by_target: dict[str, list[m.Declaration]] = defaultdict(list)
    for d, target in _pairs(DECLARES, db_alias=db_alias, from_entity_id__in=sorted(decl_rows)):
        by_target[target].append(_declaration(decl_rows[d], target))
    merged: dict[str, m.Declaration] = {}
    for t, ds in by_target.items():
        one = m.merge_declarations(ds)
        if one is not None:  # by_target lists are never empty
            merged[t] = replace(one, component_id=t)

    obs_rows = {str(r.entity_id): r for r in read_scope.node_relation(scope, Observation, db_alias=db_alias)}
    obs_target = dict(_pairs(OBSERVES, db_alias=db_alias, from_entity_id__in=sorted(obs_rows)))
    obs_source = dict(_pairs(OBSERVES_SENDER, db_alias=db_alias, from_entity_id__in=sorted(obs_rows)))
    observations = [
        rc.Observation(
            observation_id=f"{r.source}:{r.observation_key}", observer=r.observer, kind=r.kind, target=obs_target[oid],
            path_found=bool(r.path_found), observed_at=r.observed_at, source=obs_source.get(oid),
            allowlisted=r.allowlisted, evidence=f"{r.method or ''}: {r.evidence}".strip(": "),
        )
        for oid, r in obs_rows.items()
        if oid in obs_target
    ]  # fmt: skip
    flow_rows = {str(r.entity_id): r for r in read_scope.node_relation(scope, DeclaredFlow, db_alias=db_alias)}
    f_src = dict(_pairs(FLOW_SOURCE, db_alias=db_alias, from_entity_id__in=sorted(flow_rows)))
    f_dst = dict(_pairs(FLOW_TARGET, db_alias=db_alias, from_entity_id__in=sorted(flow_rows)))
    flows = [
        rc.Flow(flow_id=f"{r.source}:{r.flow_key}", source=f_src[fid], target=f_dst[fid], carries=tuple(r.carries or ()),
                metadata_reason=r.metadata_reason)
        for fid, r in flow_rows.items()
        if fid in f_src and fid in f_dst
    ]  # fmt: skip
    states = rc.reconcile(
        merged, observations, flows, now=now, freshness_hours=profile.get("observer_freshness_hours", 24)
    )
    return states, merged


def evaluate_rows(
    inputs: dict[str, Any] | None = None,
    *,
    db_alias: str = "default",
    deadlines: bool = True,
    states_sink: dict[str, rc.ComponentState] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every row, and the block every output carries. See the module docstring.

    `deadlines=False` evaluates without a FedRAMP class: IRV, LEV and PAIN do not depend on it, the clock does, so every
    row then has no due date. `states_sink`, when given, receives each component's reconciliation state."""
    p = _inputs(inputs or {}, INPUT_SCHEMA if deadlines else {**INPUT_SCHEMA, "required": []})
    now = _as_of(p.get("now"))
    profile, profile_block = load_profile(p["profile_id"], db_alias=db_alias)
    scope = read_scope.DEFAULT_SCOPE

    findings_rel = read_scope.node_relation(scope, ComplianceFinding, db_alias=db_alias).filter(status="open")
    if p.get("entity_id"):
        findings_rel = findings_rel.filter(entity_id=p["entity_id"])
    if p.get("finding_source"):
        findings_rel = findings_rel.filter(source=p["finding_source"])
    findings = {str(f.entity_id): f for f in findings_rel}
    ids = sorted(findings)

    vulns_of: dict[str, list[str]] = defaultdict(list)
    for f, v in _pairs(CONCERNS, db_alias=db_alias, from_entity_id__in=ids):
        vulns_of[f].append(v)
    vulns = _nodes(ComplianceVulnerability, sorted({v for vs in vulns_of.values() for v in vs}), db_alias=db_alias)

    carriers: dict[str, set[str]] = defaultdict(set)
    for carrier, f in _pairs(CARRIES, db_alias=db_alias, to_entity_id__in=ids):
        carriers[f].add(carrier)

    # Declarations by the node they declare, reconciled with the observations (Figure 6) before any finding is evaluated.
    states, merged_decls = reconcile_components(p, profile, now, db_alias=db_alias)
    if states_sink is not None:
        states_sink.update(states)
    declared: dict[str, list[m.Declaration]] = defaultdict(list)
    for target, decl in merged_decls.items():
        st = states[target]
        declared[target].append(
            replace(
                decl,
                undeclared_exposure=bool(st.g4),
                conflicts=tuple(st.g5),
                observer_gaps=tuple(st.g7),
                inherited_data=st.inherited_data,
            )
        )

    # Package findings with no declared carrier: the owner, container and programs reach names.
    reach: dict[str, set[str]] = defaultdict(set)
    if any(not any(c in declared for c in carriers[f]) for f in ids):
        for r in reach_rows({}, db_alias=db_alias):
            if r["finding_id"] in findings:
                reach[r["finding_id"]].update(
                    x for x in (r["owner_id"], r["container_id"], *(prog["id"] for prog in r["programs"])) if x
                )

    facts_rows = read_scope.node_relation(scope, FindingFacts, db_alias=db_alias)
    facts_of: dict[str, FindingFacts] = {}
    fact_ids = {str(r.entity_id): r for r in facts_rows}
    for fa, f in _pairs(DESCRIBES, db_alias=db_alias, to_entity_id__in=ids):
        if fa in fact_ids:
            facts_of[f] = fact_ids[fa]

    disp_rows = {str(r.entity_id): r for r in read_scope.node_relation(scope, Disposition, db_alias=db_alias)}
    disps_of: dict[str, list[m.Disposition]] = defaultdict(list)
    for d, f in _pairs(DISPOSES, db_alias=db_alias, to_entity_id__in=ids):
        if d in disp_rows:
            disps_of[f].append(_disposition(disp_rows[d]))

    check_vectors = _check_vectors(now.date(), db_alias=db_alias)
    max_overdue = acceptance_hours(db_alias=db_alias)

    def timeframe(level: str, column: str) -> int | None:
        if level == "N0" or not deadlines:
            return None
        return deadline_hours(p["fedramp_class"], level, column, db_alias=db_alias)

    rows: list[dict[str, Any]] = []
    for fid in ids:
        f = findings[fid]
        decl_list = [d for c in sorted(carriers[fid]) for d in declared.get(c, [])]
        via = "carrier"
        if not decl_list:
            decl_list = [d for n in sorted(reach[fid]) for d in declared.get(n, [])]
            via = "reach" if decl_list else "none"
        facts = facts_of.get(fid)
        vids: list[str | None] = [*vulns_of.get(fid, [])] or [None]  # a finding with no CVE is still evaluated
        for vid in vids:
            vuln = vulns.get(vid) if vid else None
            vector, vector_source = (
                (vuln.cvss_vector, "record") if vuln is not None and vuln.cvss_vector else (None, None)
            )
            cv = check_vectors.get(vuln.vuln_id) if vuln is not None else None
            if vector is None and cv is not None:
                vector, vector_source = cv.vector, f"check-vector (decided by {cv.decided_by} on {cv.decided_on})"
            finding = m.Finding(
                finding_id=fid,
                status=f.status,
                first_detected_at=f.first_detected_at,
                first_evaluated_at=facts.first_evaluated_at if facts else None,
                cvss_vector=vector,
                vector_source=vector_source,
                scanner_severity=facts.scanner_severity if facts else None,
                access=(facts.access_network, facts.access_privileges, facts.access_user_interaction)
                if facts
                else (None, None, None),
                kev=vuln.kev if vuln is not None else None,
                kev_due_date=vuln.kev_due_date if vuln is not None else None,
                exploitation_observed=bool(facts and facts.exploitation_observed),
                prediction=vuln.epss_score if vuln is not None else None,
                prediction_date=vuln.epss_date if vuln is not None else None,
                prediction_model=facts.prediction_model if facts else None,
                ssvc_exploitation=(facts.ssvc_exploitation if facts and facts.ssvc_exploitation else None)
                or (vuln.ssvc_exploitation if vuln is not None else None),
                ssvc_automatable=(facts.ssvc_automatable if facts and facts.ssvc_automatable else None)
                or (vuln.ssvc_automatable if vuln is not None else None),
                ssvc_technical_impact=(facts.ssvc_technical_impact if facts and facts.ssvc_technical_impact else None)
                or (vuln.ssvc_technical_impact if vuln is not None else None),
                fix_state=facts.fix_state if facts else None,
                deployed_version=facts.deployed_version if facts else None,
                non_machine=bool(facts and facts.non_machine),
            )
            e = m.evaluate(
                finding, decl_list, disps_of.get(fid, []), profile, now=now, timeframe_hours=timeframe,
                max_overdue_hours=max_overdue, top_level=LEVELS[-1],
            )  # fmt: skip
            row = e.as_row()
            row.update(
                finding=f.name or f.source_key,
                finding_source=f.source,
                source_key=f.source_key,
                vuln_id=vuln.vuln_id if vuln is not None else None,
                vector_source=vector_source,
                resolved_via=via,
            )
            rows.append(row)
    block = {
        "method": "vulnerability-evidence (samaydlette.com/research/vulnerability-evidence.html)",
        "profile": profile_block,
        "rules": rules_block(db_alias=db_alias),
        "fedramp_class": p.get("fedramp_class"),
        "evaluated_at": now.isoformat(),
        "not_evaluated": [
            "G6 (signing and build integrity)",
            "the build side of G7 (stale scanner databases, missing feeds)",
        ],
    }
    return rows, block


def aydlette_pain(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """One row per open finding (and vulnerability), with every decision and its basis."""
    rows, block = evaluate_rows(inputs, db_alias=db_alias)
    limit = _inputs(inputs)["max_results"]
    warnings: dict[str, Any] = {}
    if len(rows) > limit:
        warnings["rows_omitted"] = [f"{len(rows) - limit} of {len(rows)} rows were left out; max_results is {limit}"]
    return {
        "nodes": [],
        "edges": [],
        "rows": rows[:limit],
        "info": {"row_count": min(len(rows), limit), "total_rows": len(rows), **block},
        "warnings": warnings,
    }


def aydlette_summary(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """Counts by rating, column, group and state; the gates; the decision queue with its rates (REQ-QUE-1)."""
    rows, block = evaluate_rows(inputs, db_alias=db_alias)
    gates = {
        g: sorted({r["finding_id"] for r in rows if r["gates"].get(g)}) for g in ("G1", "G2", "G3", "G4", "G5", "G7")
    }
    queue = [q for r in rows for q in r["queue"]]
    kinds = Counter(q["kind"] for q in queue)
    summary = {
        "findings": len({r["finding_id"] for r in rows}),
        "rows": len(rows),
        "by_pain": dict(sorted(Counter(r["pain"] for r in rows).items())),
        "by_column": dict(Counter(r["column"] for r in rows)),
        "by_group": dict(Counter(r["group"] for r in rows)),
        "by_state": dict(Counter(r["state"] for r in rows)),
        "resolved": sum(1 for r in rows if r["resolved"]),
        "gates": {g: {"failed": bool(ids), "findings": len(ids)} for g, ids in gates.items()},
        "queue": {
            "items": len(queue),
            "by_kind": dict(kinds),
            "rate": {k: f"{n}/{len(rows)}" for k, n in kinds.items()},
        },
        "public_tier_withheld": sum(1 for r in rows if r["group"] == "open" and r["irv"] and r["lev"]),
    }
    return {"nodes": [], "edges": [], "rows": [summary], "info": block, "warnings": {}}


def aydlette_reconcile(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """One row per declared component: its declared intent, what the observers saw, the Figure 6 cell, G4, G5 and G7,
    queue items, whether it is publicly exposed (REQ-IRV-13), and the intent the observations alone suggest."""
    p = _inputs(inputs, RECONCILE_INPUT_SCHEMA)
    now = _as_of(p.get("now"))
    profile, block = load_profile(p["profile_id"], db_alias=db_alias)
    states, merged = reconcile_components(p, profile, now, db_alias=db_alias)
    from tap_grid.models import Entity

    names = {
        str(k): v for k, v in Entity.objects.using(db_alias).filter(pk__in=sorted(states)).values_list("pk", "name")
    }
    rows = []
    for cid, st in sorted(states.items(), key=lambda kv: str(names.get(kv[0], kv[0]))):
        row = dict(st.__dict__)
        row["component_name"] = names.get(cid)
        row["data"] = list(merged[cid].data)
        rows.append(row)
    summary = {
        "components": len(rows),
        "by_cell": dict(Counter(r["cell"] for r in rows)),
        "g4": sum(1 for r in rows if r["g4"]),
        "g5": sum(1 for r in rows if r["g5"]),
        "g7": sum(1 for r in rows if r["g7"]),
        "intent_vs_suggested": dict(Counter(f"{r['intent']} / {r['suggested_intent']}" for r in rows)),
    }
    limit = p["max_results"]
    return {
        "nodes": [],
        "edges": [],
        "rows": rows[:limit],
        "info": {"summary": summary, "profile": block, "evaluated_at": now.isoformat()},
        "warnings": {},
    }
